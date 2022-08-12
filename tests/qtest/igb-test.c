#include "qemu/osdep.h"
#include "libqtest-single.h"
#include "libqos/pci-pc.h"
#include "qemu/sockets.h"
#include "qemu/iov.h"
#include "qemu/module.h"
#include "qemu/bitops.h"
#include "libqos/malloc.h"

#define E1000E_RX0_MSG_ID   0
#define E1000E_TX0_MSG_ID   1
#define E1000E_TXD_LEN      16
#define E1000E_RXD_LEN      16

#define E1000_TDLEN    0x03808  /* TX Descriptor Length - RW */
#define E1000_TDT      0x03818  /* TX Descripotr Tail - RW */
#define E1000_RDLEN    0x02808  /* RX Descriptor Length - RW */
#define E1000_RDT      0x02818  /* RX Descriptor Tail - RW */

typedef struct QIGB QIGB;
typedef struct QIGB_PCI QIGB_PCI;

struct QIGB {
    uint64_t tx_ring;
    uint64_t rx_ring;
};

struct QIGB_PCI {
    QOSGraphObject obj;
    QPCIDevice pci_dev;
    QPCIBar mac_regs;
    QIGB igb;
};

static void macreg_write(QIGB *d, uint32_t reg, uint32_t val)
{
    QIGB_PCI *d_pci = container_of(d, QIGB_PCI, igb);
    qpci_io_writel(&d_pci->pci_dev, d_pci->mac_regs, reg, val);
}

static uint32_t macreg_read(QIGB *d, uint32_t reg)
{
    QIGB_PCI *d_pci = container_of(d, QIGB_PCI, igb);
    return qpci_io_readl(&d_pci->pci_dev, d_pci->mac_regs, reg);
}

static void wait_isr(QIGB *d, uint16_t msg_id)
{
    QIGB_PCI *d_pci = container_of(d, QIGB_PCI, igb);
    guint64 end_time = g_get_monotonic_time() + 5 * G_TIME_SPAN_SECOND;

    do {
        if (qpci_msix_pending(&d_pci->pci_dev, msg_id)) {
            return;
        }
        qtest_clock_step(d_pci->pci_dev.bus->qts, 10000);
    } while (g_get_monotonic_time() < end_time);

    g_error("Timeout expired");
}

static void tx_ring_push(QIGB *d, void *descr)
{
    QIGB_PCI *d_pci = container_of(d, QIGB_PCI, igb);
    uint32_t tail = macreg_read(d, E1000_TDT);
    uint32_t len = macreg_read(d, E1000_TDLEN) / E1000E_TXD_LEN;

    qtest_memwrite(d_pci->pci_dev.bus->qts, d->tx_ring + tail * E1000E_TXD_LEN,
                   descr, E1000E_TXD_LEN);
    macreg_write(d, E1000_TDT, (tail + 1) % len);

    /* Read WB data for the packet transmitted */
    qtest_memread(d_pci->pci_dev.bus->qts, d->tx_ring + tail * E1000E_TXD_LEN,
                  descr, E1000E_TXD_LEN);
}

static void rx_ring_push(QIGB *d, void *descr)
{
    QIGB_PCI *d_pci = container_of(d, QIGB_PCI, igb);
    uint32_t tail = macreg_read(d, E1000_RDT);
    uint32_t len = macreg_read(d, E1000_RDLEN) / E1000E_RXD_LEN;

    qtest_memwrite(d_pci->pci_dev.bus->qts, d->rx_ring + tail * E1000E_RXD_LEN,
                   descr, E1000E_RXD_LEN);
    macreg_write(d, E1000_RDT, (tail + 1) % len);

    /* Read WB data for the packet received */
    qtest_memread(d_pci->pci_dev.bus->qts, d->rx_ring + tail * E1000E_RXD_LEN,
                  descr, E1000E_RXD_LEN);
}

static void igb_send_verify(QIGB *d, int *test_sockets, QGuestAllocator *alloc)
{
    struct {
        uint64_t buffer_addr;
        union {
            uint32_t data;
            struct {
                uint16_t length;
                uint8_t cso;
                uint8_t cmd;
            } flags;
        } lower;
        union {
            uint32_t data;
            struct {
                uint8_t status;
                uint8_t css;
                uint16_t special;
            } fields;
        } upper;
    } descr;

    static const uint32_t dtyp_data = BIT(20);
    static const uint32_t dtyp_ext  = BIT(29);
    static const uint32_t dcmd_rs   = BIT(27);
    static const uint32_t dcmd_eop  = BIT(24);
    static const uint32_t dsta_dd   = BIT(0);
    static const int data_len = 64;
    char buffer[64];
    int ret;
    uint32_t recv_len;

    /* Prepare test data buffer */
    uint64_t data = guest_alloc(alloc, data_len);
    memwrite(data, "TEST", 5);

    /* Prepare TX descriptor */
    memset(&descr, 0, sizeof(descr));
    descr.buffer_addr = cpu_to_le64(data);
    descr.lower.data = cpu_to_le32(dcmd_rs   |
                                   dcmd_eop  |
                                   dtyp_ext  |
                                   dtyp_data |
                                   data_len);

    /* Put descriptor to the ring */
    tx_ring_push(d, &descr);

    /* Wait for TX WB interrupt */
    wait_isr(d, E1000E_TX0_MSG_ID);

    /* Check DD bit */
    g_assert_cmphex(le32_to_cpu(descr.upper.data) & dsta_dd, ==, dsta_dd);

    /* Check data sent to the backend */
    ret = recv(test_sockets[0], &recv_len, sizeof(recv_len), 0);
    g_assert_cmpint(ret, == , sizeof(recv_len));
    ret = recv(test_sockets[0], buffer, 64, 0);
    g_assert_cmpint(ret, >=, 5);
    g_assert_cmpstr(buffer, == , "TEST");

    /* Free test data buffer */
    guest_free(alloc, data);
}

static void igb_receive_verify(QIGB *d, int *test_sockets,
                               QGuestAllocator *alloc)
{
    union {
        struct {
            uint64_t buffer_addr;
            uint64_t reserved;
        } read;
        struct {
            struct {
                uint32_t mrq;
                union {
                    uint32_t rss;
                    struct {
                        uint16_t ip_id;
                        uint16_t csum;
                    } csum_ip;
                } hi_dword;
            } lower;
            struct {
                uint32_t status_error;
                uint16_t length;
                uint16_t vlan;
            } upper;
        } wb;
    } descr;

    static const uint32_t esta_dd = BIT(0);

    char test[] = "TEST";
    int len = htonl(sizeof(test));
    struct iovec iov[] = {
    {
        .iov_base = &len,
                .iov_len = sizeof(len),
    },{
        .iov_base = test,
                .iov_len = sizeof(test),
    },
};

    static const int data_len = 64;
    char buffer[64];
    int ret;

    /* Send a dummy packet to device's socket*/
    ret = iov_send(test_sockets[0], iov, 2, 0, sizeof(len) + sizeof(test));
    g_assert_cmpint(ret, == , sizeof(test) + sizeof(len));

    /* Prepare test data buffer */
    uint64_t data = guest_alloc(alloc, data_len);

    /* Prepare RX descriptor */
    memset(&descr, 0, sizeof(descr));
    descr.read.buffer_addr = cpu_to_le64(data);

    /* Put descriptor to the ring */
    rx_ring_push(d, &descr);

    /* Wait for TX WB interrupt */
    wait_isr(d, E1000E_RX0_MSG_ID);

    /* Check DD bit */
    g_assert_cmphex(le32_to_cpu(descr.wb.upper.status_error) &
                    esta_dd, ==, esta_dd);

    /* Check data sent to the backend */
    memread(data, buffer, sizeof(buffer));
    g_assert_cmpstr(buffer, == , "TEST");

    /* Free test data buffer */
    guest_free(alloc, data);
}

static void test_igb_init(void *obj, void *data, QGuestAllocator * alloc)
{
    /* init does nothing */
}

static void test_igb_tx(void *obj, void *data, QGuestAllocator * alloc)
{
    QIGB_PCI *e1000e = obj;
    QIGB *d = &e1000e->igb;
    QOSGraphObject *e_object = obj;
    QPCIDevice *dev = e_object->get_driver(e_object, "pci-device");

    /* FIXME: add spapr support */
    if (qpci_check_buggy_msi(dev)) {
        return;
    }

    igb_send_verify(d, data, alloc);
}

static void test_igb_rx(void *obj, void *data, QGuestAllocator * alloc)
{
    QIGB_PCI *e1000e = obj;
    QIGB *d = &e1000e->igb;
    QOSGraphObject *e_object = obj;
    QPCIDevice *dev = e_object->get_driver(e_object, "pci-device");

    /* FIXME: add spapr support */
    if (qpci_check_buggy_msi(dev)) {
        return;
    }

    igb_receive_verify(d, data, alloc);
}

static void test_igb_multiple_transfers(void *obj, void *data,
                                        QGuestAllocator *alloc)
{
    static const long iterations = 4 * 1024;
    long i;

    QIGB_PCI *e1000e = obj;
    QIGB *d = &e1000e->igb;
    QOSGraphObject *e_object = obj;
    QPCIDevice *dev = e_object->get_driver(e_object, "pci-device");

    /* FIXME: add spapr support */
    if (qpci_check_buggy_msi(dev)) {
        return;
    }

    for (i = 0; i < iterations; i++) {
        igb_send_verify(d, data, alloc);
        igb_receive_verify(d, data, alloc);
    }

}

static void test_igb_hotplug(void *obj, void *data, QGuestAllocator * alloc)
{
    QTestState *qts = global_qtest;  /* TODO: get rid of global_qtest here */
    QIGB_PCI *dev = obj;

    if (dev->pci_dev.bus->not_hotpluggable) {
        g_test_skip("pci bus does not support hotplug");
        return;
    }

    qtest_qmp_device_add(qts, "e1000e", "e1000e_net", "{'addr': '0x06'}");
    qpci_unplug_acpi_device_test(qts, "e1000e_net", 0x06);
}

static void data_test_clear(void *sockets)
{
    int *test_sockets = sockets;

    close(test_sockets[0]);
    qos_invalidate_command_line();
    close(test_sockets[1]);
    g_free(test_sockets);
}

static void *data_test_init(GString *cmd_line, void *arg)
{
    int *test_sockets = g_new(int, 2);
    int ret = socketpair(PF_UNIX, SOCK_STREAM, 0, test_sockets);
    g_assert_cmpint(ret, != , -1);

    g_string_append_printf(cmd_line, " -netdev socket,fd=%d,id=hs0 ",
                           test_sockets[1]);

    g_test_queue_destroy(data_test_clear, test_sockets);
    return test_sockets;
}

static void register_igb_test(void)
{
    QOSGraphTestOptions opts = {
        .before = data_test_init,
    };

    qos_add_test("init", "igb", test_igb_init, &opts);
    qos_add_test("tx", "igb", test_igb_tx, &opts);
    qos_add_test("rx", "igb", test_igb_rx, &opts);
    qos_add_test("multiple_transfers", "igb",
                 test_igb_multiple_transfers, &opts);
    qos_add_test("hotplug", "igb", test_igb_hotplug, &opts);
}

libqos_init(register_igb_test);
