/*
* Core code for QEMU e1000e emulation
*
* Software developer's manuals:
* http://www.intel.com/content/dam/doc/datasheet/82574l-gbe-controller-datasheet.pdf
*
* Copyright (c) 2015 Ravello Systems LTD (http://ravellosystems.com)
* Developed by Daynix Computing LTD (http://www.daynix.com)
*
* Authors:
* Dmitry Fleytman <dmitry@daynix.com>
* Leonid Bloch <leonid@daynix.com>
* Yan Vugenfirer <yan@daynix.com>
*
* Based on work done by:
* Nir Peleg, Tutis Systems Ltd. for Qumranet Inc.
* Copyright (c) 2008 Qumranet
* Based on work done by:
* Copyright (c) 2007 Dan Aloni
* Copyright (c) 2004 Antony T Curtis
*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public
* License as published by the Free Software Foundation; either
* version 2 of the License, or (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "net/net.h"
#include "net/tap.h"
#include "hw/net/mii.h"
#include "hw/pci/msi.h"
#include "hw/pci/msix.h"
#include "sysemu/runstate.h"

#include "net_tx_pkt.h"
#include "net_rx_pkt.h"

#include "e1000x_common.h"
#include "igb_enums.h"
#include "igb_core.h"

#include "trace.h"

#define E1000E_MAX_TX_FRAGS (64)

static uint16_t igb_receive_route(IGBCore *core, const struct eth_header *ehdr);
static void igb_update_interrupt_state(IGBCore *core);

static inline void
igb_set_interrupt_cause(IGBCore *core, uint32_t val);

static inline void
igb_raise_legacy_irq(IGBCore *core)
{
    trace_e1000e_irq_legacy_notify(true);
    e1000x_inc_reg_if_not_full(core->mac, IAC);
    pci_set_irq(core->owner, 1);
}

static inline void
igb_lower_legacy_irq(IGBCore *core)
{
    trace_e1000e_irq_legacy_notify(false);
    pci_set_irq(core->owner, 0);
}

static void igb_msix_notify(IGBCore *core, unsigned int vector)
{
    PCIDevice *dev = core->owner;
    uint16_t vfn;

	if (pcie_sriov_is_iov(core->owner)) {
		vfn = 8 - (vector + 2) / 3;
		if (vfn < pcie_sriov_vfs_count(core->owner)) {
			dev = pcie_sriov_get_vf_at_index(core->owner, vfn);
            assert(dev);
            vector = (vector + 2) % 3;
        }
    }

    msix_notify(dev, vector);
}

static inline void
igb_intrmgr_rearm_timer(IGBIntrDelayTimer *timer)
{
    int64_t delay_ns = (int64_t) timer->core->mac[timer->delay_reg] *
                                 timer->delay_resolution_ns;

    trace_e1000e_irq_rearm_timer(timer->delay_reg << 2, delay_ns);

    timer_mod(timer->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + delay_ns);

    timer->running = true;
}

static void
igb_intmgr_timer_resume(IGBIntrDelayTimer *timer)
{
    if (timer->running) {
        igb_intrmgr_rearm_timer(timer);
    }
}

static void
igb_intmgr_timer_pause(IGBIntrDelayTimer *timer)
{
    if (timer->running) {
        timer_del(timer->timer);
    }
}

static inline void
igb_intrmgr_stop_timer(IGBIntrDelayTimer *timer)
{
    if (timer->running) {
        timer_del(timer->timer);
        timer->running = false;
    }
}

static void
igb_intrmgr_on_msix_throttling_timer(void *opaque)
{
    IGBIntrDelayTimer *timer = opaque;
    int idx = timer - &timer->core->eitr[0];

    assert(msix_enabled(timer->core->owner));

    timer->running = false;

    if (!timer->core->eitr_intr_pending[idx]) {
        trace_e1000e_irq_throttling_no_pending_vec(idx);
        return;
    }

    trace_e1000e_irq_msix_notify_postponed_vec(idx);
    igb_msix_notify(timer->core, idx);
}

static void
igb_intrmgr_initialize_all_timers(IGBCore *core, bool create)
{
    int i;

    for (i = 0; i < IGB_MSIX_VEC_NUM; i++) {
        core->eitr[i].core = core;
        core->eitr[i].delay_reg = EITR0 + i;
        core->eitr[i].delay_resolution_ns = E1000_INTR_DELAY_NS_RES;
    }

    if (!create) {
        return;
    }

    for (i = 0; i < IGB_MSIX_VEC_NUM; i++) {
        core->eitr[i].timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
            igb_intrmgr_on_msix_throttling_timer, &core->eitr[i]);
    }
}

static void
igb_intrmgr_resume(IGBCore *core)
{
    int i;

    for (i = 0; i < IGB_MSIX_VEC_NUM; i++) {
        igb_intmgr_timer_resume(&core->eitr[i]);
    }
}

static void
igb_intrmgr_pause(IGBCore *core)
{
    int i;

    for (i = 0; i < IGB_MSIX_VEC_NUM; i++) {
        igb_intmgr_timer_pause(&core->eitr[i]);
    }
}

static void
igb_intrmgr_reset(IGBCore *core)
{
    int i;

    for (i = 0; i < IGB_MSIX_VEC_NUM; i++) {
        igb_intrmgr_stop_timer(&core->eitr[i]);
    }
}

static void
igb_intrmgr_pci_unint(IGBCore *core)
{
    int i;

    for (i = 0; i < IGB_MSIX_VEC_NUM; i++) {
        timer_del(core->eitr[i].timer);
        timer_free(core->eitr[i].timer);
    }
}

static void
igb_intrmgr_pci_realize(IGBCore *core)
{
    igb_intrmgr_initialize_all_timers(core, true);
}

static inline bool
igb_rx_csum_enabled(IGBCore *core)
{
    return (core->mac[RXCSUM] & E1000_RXCSUM_PCSD) ? false : true;
}

static bool igb_rx_use_legacy_descriptor(IGBCore *core)
{
    // TODO: If SRRCTL[n],DESCTYPE = 000b, the 82576 uses the legacy Rx
    // descriptor.
    return false;
}

static inline bool
igb_rss_enabled(IGBCore *core)
{
    return E1000_MRQC_ENABLED(core->mac[MRQC]) &&
           !igb_rx_csum_enabled(core) &&
           !igb_rx_use_legacy_descriptor(core);
}

typedef struct E1000E_RSSInfo_st {
    bool enabled;
    uint32_t hash;
    uint32_t queue;
    uint32_t type;
} E1000E_RSSInfo;

static uint32_t
igb_rss_get_hash_type(IGBCore *core, struct NetRxPkt *pkt)
{
    bool isip4, isip6, isudp, istcp;

    assert(igb_rss_enabled(core));

    net_rx_pkt_get_protocols(pkt, &isip4, &isip6, &isudp, &istcp);

    if (isip4) {
        bool fragment = net_rx_pkt_get_ip4_info(pkt)->fragment;

        trace_e1000e_rx_rss_ip4(fragment, istcp, core->mac[MRQC],
                                E1000_MRQC_EN_TCPIPV4(core->mac[MRQC]),
                                E1000_MRQC_EN_IPV4(core->mac[MRQC]));

        if (!fragment && istcp && E1000_MRQC_EN_TCPIPV4(core->mac[MRQC])) {
            return E1000_MRQ_RSS_TYPE_IPV4TCP;
        }

        if (E1000_MRQC_EN_IPV4(core->mac[MRQC])) {
            return E1000_MRQ_RSS_TYPE_IPV4;
        }
    } else if (isip6) {
        eth_ip6_hdr_info *ip6info = net_rx_pkt_get_ip6_info(pkt);

        bool ex_dis = core->mac[RFCTL] & E1000_RFCTL_IPV6_EX_DIS;
        bool new_ex_dis = core->mac[RFCTL] & E1000_RFCTL_NEW_IPV6_EXT_DIS;

        /*
         * Following two traces must not be combined because resulting
         * event will have 11 arguments totally and some trace backends
         * (at least "ust") have limitation of maximum 10 arguments per
         * event. Events with more arguments fail to compile for
         * backends like these.
         */
        trace_e1000e_rx_rss_ip6_rfctl(core->mac[RFCTL]);
        trace_e1000e_rx_rss_ip6(ex_dis, new_ex_dis, istcp,
                                ip6info->has_ext_hdrs,
                                ip6info->rss_ex_dst_valid,
                                ip6info->rss_ex_src_valid,
                                core->mac[MRQC],
                                E1000_MRQC_EN_TCPIPV6(core->mac[MRQC]),
                                E1000_MRQC_EN_IPV6EX(core->mac[MRQC]),
                                E1000_MRQC_EN_IPV6(core->mac[MRQC]));

        if ((!ex_dis || !ip6info->has_ext_hdrs) &&
            (!new_ex_dis || !(ip6info->rss_ex_dst_valid ||
                              ip6info->rss_ex_src_valid))) {

            if (istcp && !ip6info->fragment &&
                E1000_MRQC_EN_TCPIPV6(core->mac[MRQC])) {
                return E1000_MRQ_RSS_TYPE_IPV6TCP;
            }

            if (E1000_MRQC_EN_IPV6EX(core->mac[MRQC])) {
                return E1000_MRQ_RSS_TYPE_IPV6EX;
            }

        }

        if (E1000_MRQC_EN_IPV6(core->mac[MRQC])) {
            return E1000_MRQ_RSS_TYPE_IPV6;
        }

    }

    return E1000_MRQ_RSS_TYPE_NONE;
}

static uint32_t
igb_rss_calc_hash(IGBCore *core,
                     struct NetRxPkt *pkt,
                     E1000E_RSSInfo *info)
{
    NetRxPktRssType type;

    assert(igb_rss_enabled(core));

    switch (info->type) {
    case E1000_MRQ_RSS_TYPE_IPV4:
        type = NetPktRssIpV4;
        break;
    case E1000_MRQ_RSS_TYPE_IPV4TCP:
        type = NetPktRssIpV4Tcp;
        break;
    case E1000_MRQ_RSS_TYPE_IPV6TCP:
        type = NetPktRssIpV6TcpEx;
        break;
    case E1000_MRQ_RSS_TYPE_IPV6:
        type = NetPktRssIpV6;
        break;
    case E1000_MRQ_RSS_TYPE_IPV6EX:
        type = NetPktRssIpV6Ex;
        break;
    default:
        assert(false);
        return 0;
    }

    return net_rx_pkt_calc_rss_hash(pkt, type, (uint8_t *) &core->mac[RSSRK]);
}

static void
igb_rss_parse_packet(IGBCore *core, struct NetRxPkt *pkt, E1000E_RSSInfo *info)
{
    trace_e1000e_rx_rss_started();

    if (!igb_rss_enabled(core)) {
        info->enabled = false;
        info->hash = 0;
        info->queue = 0;
        info->type = 0;
        trace_e1000e_rx_rss_disabled();
        return;
    }

    info->enabled = true;

    info->type = igb_rss_get_hash_type(core, pkt);

    trace_e1000e_rx_rss_type(info->type);

    if (info->type == E1000_MRQ_RSS_TYPE_NONE) {
        info->hash = 0;
        info->queue = 0;
        return;
    }

    info->hash = igb_rss_calc_hash(core, pkt, info);
    info->queue = E1000_RSS_QUEUE(&core->mac[RETA], info->hash);
}

static void
igb_setup_tx_offloads(IGBCore *core, struct IGBTx *tx)
{
    if (tx->tse) {
        net_tx_pkt_build_vheader(tx->tx_pkt, true, true, tx->mss);
        net_tx_pkt_update_ip_checksums(tx->tx_pkt);
        e1000x_inc_reg_if_not_full(core->mac, TSCTC);
        return;
    }

    if (tx->txsm) {
        net_tx_pkt_build_vheader(tx->tx_pkt, false, true, 0);
    }

    if (tx->ixsm) {
        net_tx_pkt_update_ip_hdr_checksum(tx->tx_pkt);
    }
}

/* TX Packets Switching (7.10.3.6) */
static bool igb_tx_pkt_switch(IGBCore *core, struct IGBTx *tx,
    NetClientState *nc)
{
    struct eth_header *ehdr;
    bool ret, send_both;

	/* TX switching is only used to serve VM to VM traffic. */
	if (!pcie_sriov_is_iov(core->owner)) {
        goto send_out;
    }

    /* TX switching requires DTXSWC.Loopback_en bit enabled. */
    if (!(core->mac[DTXSWC] & BIT(31))) {
        goto send_out;
    }

    if (net_tx_pkt_get_packet_type(tx->tx_pkt) == ETH_PKT_UCAST) {
        ehdr = net_tx_pkt_get_eth_hdr(tx->tx_pkt);
        if (igb_receive_route(core, ehdr)) {
            send_both = false;
            goto send_back;
        }
        /* Unicast packet which doesn't target a VF is send to lan. */
        goto send_out;
    } else {
        send_both = true;
    }

send_back:
    ret = net_tx_pkt_send_loopback(tx->tx_pkt, nc);
    if (!send_both) {
        return ret;
    }

send_out:
    return net_tx_pkt_send(tx->tx_pkt, nc);
}

static bool igb_tx_pkt_send(IGBCore *core, struct IGBTx *tx,
    int queue_index)
{
    int target_queue = MIN(core->max_queue_num, queue_index);
    NetClientState *queue = qemu_get_subqueue(core->owner_nic, target_queue);

    igb_setup_tx_offloads(core, tx);

    net_tx_pkt_dump(tx->tx_pkt);

    if ((core->phy[MII_BMCR] & MII_BMCR_LOOPBACK) ||
        ((core->mac[RCTL] & E1000_RCTL_LBM_MAC) == E1000_RCTL_LBM_MAC)) {
        return net_tx_pkt_send_loopback(tx->tx_pkt, queue);
    } else {
        return igb_tx_pkt_switch(core, tx, queue);
    }
}

static void
igb_on_tx_done_update_stats(IGBCore *core, struct NetTxPkt *tx_pkt)
{
    static const int PTCregs[6] = { PTC64, PTC127, PTC255, PTC511,
                                    PTC1023, PTC1522 };

    size_t tot_len = net_tx_pkt_get_total_len(tx_pkt);

    e1000x_increase_size_stats(core->mac, PTCregs, tot_len);
    e1000x_inc_reg_if_not_full(core->mac, TPT);
    e1000x_grow_8reg_if_not_full(core->mac, TOTL, tot_len);

    switch (net_tx_pkt_get_packet_type(tx_pkt)) {
    case ETH_PKT_BCAST:
        e1000x_inc_reg_if_not_full(core->mac, BPTC);
        break;
    case ETH_PKT_MCAST:
        e1000x_inc_reg_if_not_full(core->mac, MPTC);
        break;
    case ETH_PKT_UCAST:
        break;
    default:
        g_assert_not_reached();
    }

    core->mac[GPTC] = core->mac[TPT];
    core->mac[GOTCL] = core->mac[TOTL];
    core->mac[GOTCH] = core->mac[TOTH];
}

static void igb_process_tx_desc(IGBCore *core, struct IGBTx *tx,
    union e1000_adv_tx_desc *tx_desc, int queue_index)
{
    struct e1000_adv_tx_context_desc *tx_ctx_desc;
    uint32_t cmd_type_len;
    uint32_t olinfo_status;
    uint64_t buffer_addr;
    uint16_t length;

    cmd_type_len = le32_to_cpu(tx_desc->read.cmd_type_len);

    if (cmd_type_len & E1000_ADVTXD_DCMD_DEXT) {
        if ((cmd_type_len & E1000_ADVTXD_DTYP_DATA) ==
            E1000_ADVTXD_DTYP_DATA) {
            /* Advanced Transmit Data Descriptor */
            if (tx->first) {
                olinfo_status = le32_to_cpu(tx_desc->read.olinfo_status);

                tx->tse = !!(cmd_type_len & E1000_ADVTXD_DCMD_TSE);
                tx->ixsm = !!(olinfo_status & E1000_ADVTXD_POTS_IXSM);
                tx->txsm = !!(olinfo_status & E1000_ADVTXD_POTS_TXSM);

                tx->first = false;
            }
        } else if ((cmd_type_len & E1000_ADVTXD_DTYP_CTXT) ==
                   E1000_ADVTXD_DTYP_CTXT) {
            /* Advanced Transmit Context Descriptor */
            tx_ctx_desc = (struct e1000_adv_tx_context_desc *)tx_desc;
            tx->vlan = le32_to_cpu(tx_ctx_desc->vlan_macip_lens) >> 16;
            tx->mss = le32_to_cpu(tx_ctx_desc->mss_l4len_idx) >> 16;
            return;
        } else {
            /* Unknown Descriptor Type */
            return;
        }
    } else {
        /* Legacy Descriptor */

        // TODO: Implement a support for legacy descriptors (7.2.2.1).
    }

    buffer_addr = le64_to_cpu(tx_desc->read.buffer_addr);
    length = cmd_type_len & 0xFFFF;

    if (!tx->skip_cp) {
        if (!net_tx_pkt_add_raw_fragment(tx->tx_pkt, buffer_addr, length)) {
            tx->skip_cp = true;
        }
    }

    if (cmd_type_len & E1000_TXD_CMD_EOP) {
        if (!tx->skip_cp && net_tx_pkt_parse(tx->tx_pkt)) {
            if (cmd_type_len & E1000_TXD_CMD_VLE) {
                net_tx_pkt_setup_vlan_header_ex(tx->tx_pkt, tx->vlan,
                    core->vet);
            }
            if (igb_tx_pkt_send(core, tx, queue_index)) {
                igb_on_tx_done_update_stats(core, tx->tx_pkt);
            }
        }

        tx->first = true;
        tx->skip_cp = false;
        net_tx_pkt_reset(tx->tx_pkt);
    }
}

static uint32_t igb_tx_wb_eic(IGBCore *core, int queue_idx)
{
    uint32_t n, ent = 0;

    if (!msix_enabled(core->owner)) {
        return BIT(queue_idx);
    }

    n = igb_ivar_entry_tx(queue_idx);
    ent = (core->mac[IVAR0 + n / 4] >> (8 * (n % 4))) & 0xff;

    return (ent & E1000_IVAR_VALID) ? BIT(ent & 0x1f) : 0;
}

static uint32_t igb_rx_wb_eic(IGBCore *core, int queue_idx,
                              bool min_threshold_hit)
{
    uint32_t n, ent = 0;

    if (!msix_enabled(core->owner)) {
        return BIT(queue_idx);
    }

    n = igb_ivar_entry_rx(queue_idx);
    ent = (core->mac[IVAR0 + n / 4] >> (8 * (n % 4))) & 0xff;

    return (ent & E1000_IVAR_VALID) ? BIT(ent & 0x1f) : 0;
}

static uint32_t igb_txdesc_writeback(IGBCore *core, dma_addr_t base,
    union e1000_adv_tx_desc *tx_desc, int queue_idx)
{
    uint32_t cmd_type_len;
    uint32_t status;

    cmd_type_len = le32_to_cpu(tx_desc->read.cmd_type_len);
    if (!(cmd_type_len & E1000_TXD_CMD_RS)) {
        return 0;
    }

    status = le32_to_cpu(tx_desc->wb.status) | E1000_TXD_STAT_DD;
    tx_desc->wb.status = cpu_to_le32(status);

    pci_dma_write(core->owner, base + offsetof(union e1000_adv_tx_desc, wb),
        &tx_desc->wb, sizeof(tx_desc->wb));

    return igb_tx_wb_eic(core, queue_idx);
}

typedef struct E1000E_RingInfo_st {
    int dbah;
    int dbal;
    int dlen;
    int dh;
    int dt;
    int idx;
} E1000E_RingInfo;

static inline bool
igb_ring_empty(IGBCore *core, const E1000E_RingInfo *r)
{
    return core->mac[r->dh] == core->mac[r->dt] ||
                core->mac[r->dt] >= core->mac[r->dlen] / E1000_RING_DESC_LEN;
}

static inline uint64_t
igb_ring_base(IGBCore *core, const E1000E_RingInfo *r)
{
    uint64_t bah = core->mac[r->dbah];
    uint64_t bal = core->mac[r->dbal];

    return (bah << 32) + bal;
}

static inline uint64_t
igb_ring_head_descr(IGBCore *core, const E1000E_RingInfo *r)
{
    return igb_ring_base(core, r) + E1000_RING_DESC_LEN * core->mac[r->dh];
}

static inline void
igb_ring_advance(IGBCore *core, const E1000E_RingInfo *r, uint32_t count)
{
    core->mac[r->dh] += count;

    if (core->mac[r->dh] * E1000_RING_DESC_LEN >= core->mac[r->dlen]) {
        core->mac[r->dh] = 0;
    }
}

static inline uint32_t
igb_ring_free_descr_num(IGBCore *core, const E1000E_RingInfo *r)
{
    trace_e1000e_ring_free_space(r->idx, core->mac[r->dlen],
                                 core->mac[r->dh],  core->mac[r->dt]);

    if (core->mac[r->dh] <= core->mac[r->dt]) {
        return core->mac[r->dt] - core->mac[r->dh];
    }

    if (core->mac[r->dh] > core->mac[r->dt]) {
        return core->mac[r->dlen] / E1000_RING_DESC_LEN +
               core->mac[r->dt] - core->mac[r->dh];
    }

    g_assert_not_reached();
    return 0;
}

static inline bool
igb_ring_enabled(IGBCore *core, const E1000E_RingInfo *r)
{
    return core->mac[r->dlen] > 0;
}

static inline uint32_t
igb_ring_len(IGBCore *core, const E1000E_RingInfo *r)
{
    return core->mac[r->dlen];
}

typedef struct IGBTxRing {
    const E1000E_RingInfo *i;
    struct IGBTx *tx;
} IGBTxRing;

static inline int
igb_mq_queue_idx(int base_reg_idx, int reg_idx)
{
    return (reg_idx - base_reg_idx) / 16;
}

static inline void igb_tx_ring_init(IGBCore *core, IGBTxRing *txr, int idx)
{
    static const E1000E_RingInfo i[IGB_NUM_QUEUES] = {
        { TDBAH0, TDBAL0, TDLEN0, TDH0, TDT0, 0 },
        { TDBAH1, TDBAL1, TDLEN1, TDH1, TDT1, 1 },
        { TDBAH2, TDBAL2, TDLEN2, TDH2, TDT2, 2 },
        { TDBAH3, TDBAL3, TDLEN3, TDH3, TDT3, 3 },
        { TDBAH4, TDBAL4, TDLEN4, TDH4, TDT4, 4 },
        { TDBAH5, TDBAL5, TDLEN5, TDH5, TDT5, 5 },
        { TDBAH6, TDBAL6, TDLEN6, TDH6, TDT6, 6 },
        { TDBAH7, TDBAL7, TDLEN7, TDH7, TDT7, 7 },
        { TDBAH8, TDBAL8, TDLEN8, TDH8, TDT8, 8 },
        { TDBAH9, TDBAL9, TDLEN9, TDH9, TDT9, 9 },
        { TDBAH10, TDBAL10, TDLEN10, TDH10, TDT10, 10 },
        { TDBAH11, TDBAL11, TDLEN11, TDH11, TDT11, 11 },
        { TDBAH12, TDBAL12, TDLEN12, TDH12, TDT12, 12 },
        { TDBAH13, TDBAL13, TDLEN13, TDH13, TDT13, 13 },
        { TDBAH14, TDBAL14, TDLEN14, TDH14, TDT14, 14 },
        { TDBAH15, TDBAL15, TDLEN15, TDH15, TDT15, 15 }
    };

    assert(idx < ARRAY_SIZE(i));

    txr->i = &i[idx];
    txr->tx = &core->tx[idx];
}

typedef struct E1000E_RxRing_st {
    const E1000E_RingInfo *i;
} E1000E_RxRing;

static inline void igb_rx_ring_init(IGBCore *core, E1000E_RxRing *rxr,
                                    int idx)
{
    static const E1000E_RingInfo i[IGB_NUM_QUEUES] = {
        { RDBAH0, RDBAL0, RDLEN0, RDH0, RDT0, 0 },
        { RDBAH1, RDBAL1, RDLEN1, RDH1, RDT1, 1 },
        { RDBAH2, RDBAL2, RDLEN2, RDH2, RDT2, 2 },
        { RDBAH3, RDBAL3, RDLEN3, RDH3, RDT3, 3 },
        { RDBAH4, RDBAL4, RDLEN4, RDH4, RDT4, 4 },
        { RDBAH5, RDBAL5, RDLEN5, RDH5, RDT5, 5 },
        { RDBAH6, RDBAL6, RDLEN6, RDH6, RDT6, 6 },
        { RDBAH7, RDBAL7, RDLEN7, RDH7, RDT7, 7 },
        { RDBAH8, RDBAL8, RDLEN8, RDH8, RDT8, 8 },
        { RDBAH9, RDBAL9, RDLEN9, RDH9, RDT9, 9 },
        { RDBAH10, RDBAL10, RDLEN10, RDH10, RDT10, 10 },
        { RDBAH11, RDBAL11, RDLEN11, RDH11, RDT11, 11 },
        { RDBAH12, RDBAL12, RDLEN12, RDH12, RDT12, 12 },
        { RDBAH13, RDBAL13, RDLEN13, RDH13, RDT13, 13 },
        { RDBAH14, RDBAL14, RDLEN14, RDH14, RDT14, 14 },
        { RDBAH15, RDBAL15, RDLEN15, RDH15, RDT15, 15 }
    };

    assert(idx < ARRAY_SIZE(i));

    rxr->i = &i[idx];
}

static void igb_start_xmit(IGBCore *core, const IGBTxRing *txr)
{
    dma_addr_t base;
    union e1000_adv_tx_desc desc;
    const E1000E_RingInfo *txi = txr->i;
    uint32_t eic = 0;

    // TODO: check if the queue itself is enabled too.
    if (!(core->mac[TCTL] & E1000_TCTL_EN)) {
        trace_e1000e_tx_disabled();
        return;
    }

    while (!igb_ring_empty(core, txi)) {
        base = igb_ring_head_descr(core, txi);

        pci_dma_read(core->owner, base, &desc, sizeof(desc));

        trace_e1000e_tx_descr((void *)(intptr_t)desc.read.buffer_addr,
                              desc.read.cmd_type_len, desc.wb.status);

        igb_process_tx_desc(core, txr->tx, &desc, txi->idx);
        eic |= igb_txdesc_writeback(core, base, &desc, txi->idx);

        igb_ring_advance(core, txi, 1);
    }

    if (eic) {
        core->mac[EICR] |= eic;
        igb_set_interrupt_cause(core, E1000_ICR_TXDW);
    }
}

static bool
igb_has_rxbufs(IGBCore *core, const E1000E_RingInfo *r, size_t total_size)
{
    uint32_t bufs = igb_ring_free_descr_num(core, r);

    trace_e1000e_rx_has_buffers(r->idx, bufs, total_size,
                                core->rx_desc_buf_size);

    return total_size <= bufs / (core->rx_desc_len / E1000_MIN_RX_DESC_LEN) *
                         core->rx_desc_buf_size;
}

void igb_start_recv(IGBCore *core)
{
    int i;

    trace_e1000e_rx_start_recv();

    for (i = 0; i <= core->max_queue_num; i++) {
        qemu_flush_queued_packets(qemu_get_subqueue(core->owner_nic, i));
    }
}

bool igb_can_receive(IGBCore *core)
{
    int i;

    if (!e1000x_rx_ready(core->owner, core->mac)) {
        return false;
    }

    for (i = 0; i < IGB_NUM_QUEUES; i++) {
        E1000E_RxRing rxr;

        igb_rx_ring_init(core, &rxr, i);
        if (igb_ring_enabled(core, rxr.i) && igb_has_rxbufs(core, rxr.i, 1)) {
            trace_e1000e_rx_can_recv();
            return true;
        }
    }

    trace_e1000e_rx_can_recv_rings_full();
    return false;
}

static inline bool
igb_rx_l3_cso_enabled(IGBCore *core)
{
    return !!(core->mac[RXCSUM] & E1000_RXCSUM_IPOFLD);
}

static inline bool
igb_rx_l4_cso_enabled(IGBCore *core)
{
    return !!(core->mac[RXCSUM] & E1000_RXCSUM_TUOFLD);
}

static uint16_t igb_receive_route(IGBCore *core, const struct eth_header *ehdr)
{
    static const int ta_shift[] = { 4, 3, 2, 0 };
    uint32_t f, ra[2], *macp, rctl = core->mac[RCTL];
    uint16_t queues = 0;
    int i;

    if (e1000x_is_vlan_packet(ehdr->h_dest, core->vet) &&
        e1000x_vlan_rx_filter_enabled(core->mac)) {
        uint16_t vid = lduw_be_p(ehdr->h_dest + 14);
        uint32_t vfta = ldl_le_p((uint32_t *)(core->mac + VFTA) +
                                 ((vid >> 5) & 0x7f));
        if ((vfta & (1 << (vid & 0x1f))) == 0) {
            trace_e1000e_rx_flt_vlan_mismatch(vid);
            return queues;
        } else {
            trace_e1000e_rx_flt_vlan_match(vid);
        }
    }

    if (is_broadcast_ether_addr(ehdr->h_dest)) {
        for (i = 0; i < IGB_MAX_VF_FUNCTIONS; i++) {
            if (core->mac[VMOLR0 + i] & E1000_VMOLR_BAM) {
                queues |= BIT(i);
            }
        }

        return queues;
    }

    for (macp = core->mac + RA; macp < core->mac + RA + 32; macp += 2) {
        if (!(macp[1] & E1000_RAH_AV)) {
            continue;
        }
        ra[0] = cpu_to_le32(macp[0]);
        ra[1] = cpu_to_le32(macp[1]);
        if (!memcmp(ehdr->h_dest, (uint8_t *)ra, 6)) {
            trace_e1000x_rx_flt_ucast_match((int)(macp - core->mac - RA) / 2,
                                            MAC_ARG(ehdr->h_dest));

            queues |= (macp[1] & E1000_RAH_POOL_MASK) / E1000_RAH_POOL_1;
        }
    }

    for (macp = core->mac + RA2; macp < core->mac + RA2 + 16; macp += 2) {
        if (!(macp[1] & E1000_RAH_AV)) {
            continue;
        }
        ra[0] = cpu_to_le32(macp[0]);
        ra[1] = cpu_to_le32(macp[1]);
        if (!memcmp(ehdr->h_dest, (uint8_t *)ra, 6)) {
            trace_e1000x_rx_flt_ucast_match((int)(macp - core->mac - RA2) / 2,
                                            MAC_ARG(ehdr->h_dest));

            queues |= (macp[1] & E1000_RAH_POOL_MASK) / E1000_RAH_POOL_1;
        }
    }

    if (queues) {
        return queues;
    }

    macp = core->mac + (is_multicast_ether_addr(ehdr->h_dest) ? MTA : UTA);

    f = ta_shift[(rctl >> E1000_RCTL_MO_SHIFT) & 3];
    f = (((ehdr->h_dest[5] << 8) | ehdr->h_dest[4]) >> f) & 0xfff;
    if (macp[f >> 5] & (1 << (f & 0x1f))) {
        for (i = 0; i < IGB_MAX_VF_FUNCTIONS; i++) {
            if (core->mac[VMOLR0 + i] & E1000_VMOLR_ROMPE) {
                queues |= BIT(i);
            }
        }
    }

    if (queues) {
        e1000x_inc_reg_if_not_full(core->mac, MPRC);
        return queues;
    }

    trace_e1000x_rx_flt_inexact_mismatch(MAC_ARG(ehdr->h_dest),
                                         (rctl >> E1000_RCTL_MO_SHIFT) & 3,
                                         f >> 5,
                                         macp[f >> 5]);

    return queues;
}

static inline void
igb_read_lgcy_rx_descr(IGBCore *core, uint8_t *desc, hwaddr *buff_addr)
{
    struct e1000_rx_desc *d = (struct e1000_rx_desc *) desc;
    *buff_addr = le64_to_cpu(d->buffer_addr);
}

static inline void
igb_read_ext_rx_descr(IGBCore *core, uint8_t *desc, hwaddr *buff_addr)
{
    union e1000_adv_rx_desc *d = (union e1000_adv_rx_desc *) desc;
    *buff_addr = le64_to_cpu(d->read.pkt_addr);
}

static inline void
igb_read_rx_descr(IGBCore *core, uint8_t *desc, hwaddr *buff_addr)
{
    if (igb_rx_use_legacy_descriptor(core)) {
        igb_read_lgcy_rx_descr(core, desc, buff_addr);
    } else {
        igb_read_ext_rx_descr(core, desc, buff_addr);
    }
}

static void
igb_verify_csum_in_sw(IGBCore *core, struct NetRxPkt *pkt,
                      uint32_t *status_flags, bool istcp, bool isudp)
{
    bool csum_valid;
    uint32_t csum_error;

    if (igb_rx_l3_cso_enabled(core)) {
        if (!net_rx_pkt_validate_l3_csum(pkt, &csum_valid)) {
            trace_e1000e_rx_metadata_l3_csum_validation_failed();
        } else {
            csum_error = csum_valid ? 0 : E1000_RXDEXT_STATERR_IPE;
            *status_flags |= E1000_RXD_STAT_IPCS | csum_error;
        }
    } else {
        trace_e1000e_rx_metadata_l3_cso_disabled();
    }

    if (!igb_rx_l4_cso_enabled(core)) {
        trace_e1000e_rx_metadata_l4_cso_disabled();
        return;
    }

    if (!net_rx_pkt_validate_l4_csum(pkt, &csum_valid)) {
        trace_e1000e_rx_metadata_l4_csum_validation_failed();
        return;
    }

    csum_error = csum_valid ? 0 : E1000_RXDEXT_STATERR_TCPE;

    if (istcp) {
        *status_flags |= E1000_RXD_STAT_TCPCS |
                         csum_error;
    } else if (isudp) {
        *status_flags |= E1000_RXD_STAT_TCPCS |
                         E1000_RXD_STAT_UDPCS |
                         csum_error;
    }
}

static void igb_build_rx_metadata(IGBCore *core, struct NetRxPkt *pkt,
    bool is_eop, const E1000E_RSSInfo *rss_info,
    uint16_t *pkt_info, uint16_t *hdr_info,
    uint32_t *rss, uint16_t *ip_id, uint16_t *csum,
    uint32_t *status, uint16_t *vlan)
{
    bool isip4, isip6, istcp, isudp;
    uint32_t pkt_type;

    *status = E1000_RXD_STAT_DD;

    /* No additional metadata needed for non-EOP descriptors */
    // TODO: EOP apply only to status so don't skip whole function.
    if (!is_eop) {
        goto func_exit;
    }

    *status |= E1000_RXD_STAT_EOP;

    net_rx_pkt_get_protocols(pkt, &isip4, &isip6, &isudp, &istcp);
    trace_e1000e_rx_metadata_protocols(isip4, isip6, isudp, istcp);

    if (rss_info->enabled) {
        *pkt_info = rss_info->type;
    }

    if (isip6 && (core->mac[RFCTL] & E1000_RFCTL_IPV6_DIS)) {
        trace_e1000e_rx_metadata_ipv6_filtering_disabled();
        pkt_type = E1000_RXD_PKT_MAC;
    } else if (istcp || isudp) {
        pkt_type = isip4 ? E1000_RXD_PKT_IP4_XDP : E1000_RXD_PKT_IP6_XDP;
    } else if (isip4 || isip6) {
        pkt_type = isip4 ? E1000_RXD_PKT_IP4 : E1000_RXD_PKT_IP6;
    } else {
        pkt_type = E1000_RXD_PKT_MAC;
    }

    trace_e1000e_rx_metadata_pkt_type(pkt_type);
    *pkt_info |= (pkt_type << 4);

    *hdr_info = 0;

    /* VLAN state */
    if (net_rx_pkt_is_vlan_stripped(pkt)) {
        *status |= E1000_RXD_STAT_VP;
        *vlan = cpu_to_le16(net_rx_pkt_get_vlan_tag(pkt));
        trace_e1000e_rx_metadata_vlan(*vlan);
    }

    /* Packet parsing results */
    if ((core->mac[RXCSUM] & E1000_RXCSUM_PCSD) != 0) {
        if (rss_info->enabled) {
            *rss = cpu_to_le32(rss_info->hash);
            trace_igb_rx_metadata_rss(*rss);
        }
    } else if (isip4) {
        *status |= E1000_RXD_STAT_IPIDV;
        *ip_id = cpu_to_le16(net_rx_pkt_get_ip_id(pkt));
        trace_e1000e_rx_metadata_ip_id(*ip_id);
    }

    if (istcp && net_rx_pkt_is_tcp_ack(pkt)) {
        *status |= E1000_RXD_STAT_ACK;
        trace_e1000e_rx_metadata_ack();
    }

    /* RX CSO information */
    if (isip6 && (core->mac[RFCTL] & E1000_RFCTL_IPV6_XSUM_DIS)) {
        trace_e1000e_rx_metadata_ipv6_sum_disabled();
        goto func_exit;
    }

    if (!net_rx_pkt_has_virt_hdr(pkt)) {
        trace_e1000e_rx_metadata_no_virthdr();
        igb_verify_csum_in_sw(core, pkt, status, istcp, isudp);
        goto func_exit;
    }

    if (igb_rx_l3_cso_enabled(core)) {
        *status |= isip4 ? E1000_RXD_STAT_IPCS : 0;
    } else {
        trace_e1000e_rx_metadata_l3_cso_disabled();
    }

    if (igb_rx_l4_cso_enabled(core)) {
        if (istcp) {
            *status |= E1000_RXD_STAT_TCPCS;
        } else if (isudp) {
            *status |= E1000_RXD_STAT_TCPCS | E1000_RXD_STAT_UDPCS;
        }
    } else {
        trace_e1000e_rx_metadata_l4_cso_disabled();
    }

    trace_e1000e_rx_metadata_status_flags(*status);

func_exit:
    *status = cpu_to_le32(*status);
}

static void
igb_build_lgcy_rx_metadata(IGBCore *core,
                           struct NetRxPkt *pkt,
                           bool is_eop,
                           const E1000E_RSSInfo *rss_info,
                           uint32_t *rss, uint32_t *mrq,
                           uint32_t *status_flags,
                           uint16_t *ip_id,
                           uint16_t *vlan_tag)
{
    struct virtio_net_hdr *vhdr;
    bool isip4, isip6, istcp, isudp;
    uint32_t pkt_type;

    *status_flags = E1000_RXD_STAT_DD;

    /* No additional metadata needed for non-EOP descriptors */
    if (!is_eop) {
        goto func_exit;
    }

    *status_flags |= E1000_RXD_STAT_EOP;

    net_rx_pkt_get_protocols(pkt, &isip4, &isip6, &isudp, &istcp);
    trace_e1000e_rx_metadata_protocols(isip4, isip6, isudp, istcp);

    /* VLAN state */
    if (net_rx_pkt_is_vlan_stripped(pkt)) {
        *status_flags |= E1000_RXD_STAT_VP;
        *vlan_tag = cpu_to_le16(net_rx_pkt_get_vlan_tag(pkt));
        trace_e1000e_rx_metadata_vlan(*vlan_tag);
    }

    /* Packet parsing results */
    if ((core->mac[RXCSUM] & E1000_RXCSUM_PCSD) != 0) {
        if (rss_info->enabled) {
            *rss = cpu_to_le32(rss_info->hash);
            *mrq = cpu_to_le32(rss_info->type | (rss_info->queue << 8));
            trace_e1000e_rx_metadata_rss(*rss, *mrq);
        }
    } else if (isip4) {
            *status_flags |= E1000_RXD_STAT_IPIDV;
            *ip_id = cpu_to_le16(net_rx_pkt_get_ip_id(pkt));
            trace_e1000e_rx_metadata_ip_id(*ip_id);
    }

    if (istcp && net_rx_pkt_is_tcp_ack(pkt)) {
        *status_flags |= E1000_RXD_STAT_ACK;
        trace_e1000e_rx_metadata_ack();
    }

    if (isip6 && (core->mac[RFCTL] & E1000_RFCTL_IPV6_DIS)) {
        trace_e1000e_rx_metadata_ipv6_filtering_disabled();
        pkt_type = E1000_RXD_PKT_MAC;
    } else if (istcp || isudp) {
        pkt_type = isip4 ? E1000_RXD_PKT_IP4_XDP : E1000_RXD_PKT_IP6_XDP;
    } else if (isip4 || isip6) {
        pkt_type = isip4 ? E1000_RXD_PKT_IP4 : E1000_RXD_PKT_IP6;
    } else {
        pkt_type = E1000_RXD_PKT_MAC;
    }

    *status_flags |= E1000_RXD_PKT_TYPE(pkt_type);
    trace_e1000e_rx_metadata_pkt_type(pkt_type);

    /* RX CSO information */
    if (isip6 && (core->mac[RFCTL] & E1000_RFCTL_IPV6_XSUM_DIS)) {
        trace_e1000e_rx_metadata_ipv6_sum_disabled();
        goto func_exit;
    }

    if (!net_rx_pkt_has_virt_hdr(pkt)) {
        trace_e1000e_rx_metadata_no_virthdr();
        igb_verify_csum_in_sw(core, pkt, status_flags, istcp, isudp);
        goto func_exit;
    }

    vhdr = net_rx_pkt_get_vhdr(pkt);

    if (!(vhdr->flags & VIRTIO_NET_HDR_F_DATA_VALID) &&
        !(vhdr->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM)) {
        trace_e1000e_rx_metadata_virthdr_no_csum_info();
        igb_verify_csum_in_sw(core, pkt, status_flags, istcp, isudp);
        goto func_exit;
    }

    if (igb_rx_l3_cso_enabled(core)) {
        *status_flags |= isip4 ? E1000_RXD_STAT_IPCS : 0;
    } else {
        trace_e1000e_rx_metadata_l3_cso_disabled();
    }

    if (igb_rx_l4_cso_enabled(core)) {
        if (istcp) {
            *status_flags |= E1000_RXD_STAT_TCPCS;
        } else if (isudp) {
            *status_flags |= E1000_RXD_STAT_TCPCS | E1000_RXD_STAT_UDPCS;
        }
    } else {
        trace_e1000e_rx_metadata_l4_cso_disabled();
    }

    trace_e1000e_rx_metadata_status_flags(*status_flags);

func_exit:
    *status_flags = cpu_to_le32(*status_flags);
}

static inline void
igb_write_lgcy_rx_descr(IGBCore *core, uint8_t *desc,
                        struct NetRxPkt *pkt,
                        const E1000E_RSSInfo *rss_info,
                        uint16_t length)
{
    uint32_t status_flags, rss, mrq;
    uint16_t ip_id;

    struct e1000_rx_desc *d = (struct e1000_rx_desc *) desc;

    assert(!rss_info->enabled);
    d->length = cpu_to_le16(length);
    d->csum = 0;

    igb_build_lgcy_rx_metadata(core, pkt, pkt != NULL,
                               rss_info,
                               &rss, &mrq,
                               &status_flags, &ip_id,
                               &d->special);
    d->errors = (uint8_t) (le32_to_cpu(status_flags) >> 24);
    d->status = (uint8_t) le32_to_cpu(status_flags);
    d->special = 0;
}

static inline void
igb_write_ext_rx_descr(IGBCore *core, uint8_t *desc,
                       struct NetRxPkt *pkt,
                       const E1000E_RSSInfo *rss_info,
                       uint16_t length)
{
    union e1000_adv_rx_desc *d = (union e1000_adv_rx_desc *) desc;

    memset(&d->wb, 0, sizeof(d->wb));
    d->wb.upper.length = cpu_to_le16(length);

    igb_build_rx_metadata(core, pkt, pkt != NULL, rss_info,
        &d->wb.lower.lo_dword.pkt_info,
        &d->wb.lower.lo_dword.hdr_info,
        &d->wb.lower.hi_dword.rss,
        &d->wb.lower.hi_dword.csum_ip.ip_id,
        &d->wb.lower.hi_dword.csum_ip.csum,
        &d->wb.upper.status_error,
        &d->wb.upper.vlan);
}

static inline void
igb_write_rx_descr(IGBCore *core, uint8_t *desc, struct NetRxPkt *pkt,
                   const E1000E_RSSInfo *rss_info, uint16_t length)
{
    if (igb_rx_use_legacy_descriptor(core)) {
        igb_write_lgcy_rx_descr(core, desc, pkt, rss_info, length);
    } else {
        igb_write_ext_rx_descr(core, desc, pkt, rss_info, length);
    }
}

static inline void
igb_write_hdr_to_rx_buffers(IGBCore *core, hwaddr ba, uint16_t *written,
                            const char *data, dma_addr_t data_len)
{
    assert(data_len <= core->rx_desc_buf_size - *written);

    pci_dma_write(core->owner, ba + *written, data, data_len);
    *written += data_len;
}

static void
igb_write_to_rx_buffers(IGBCore *core, hwaddr ba, uint16_t *written,
                        const char *data, dma_addr_t data_len)
{
    assert(data_len <= core->rx_desc_buf_size - *written);
    trace_igb_rx_desc_buff_write(ba, *written, data, data_len);
    pci_dma_write(core->owner, ba + *written, data, data_len);
    *written += data_len;
}

static void
igb_update_rx_stats(IGBCore *core, size_t data_size, size_t data_fcs_size)
{
    e1000x_update_rx_total_stats(core->mac, data_size, data_fcs_size);

    switch (net_rx_pkt_get_packet_type(core->rx_pkt)) {
    case ETH_PKT_BCAST:
        e1000x_inc_reg_if_not_full(core->mac, BPRC);
        break;

    case ETH_PKT_MCAST:
        e1000x_inc_reg_if_not_full(core->mac, MPRC);
        break;

    default:
        break;
    }
}

static inline bool
igb_rx_descr_threshold_hit(IGBCore *core, const E1000E_RingInfo *rxi)
{
    return igb_ring_free_descr_num(core, rxi) ==
           igb_ring_len(core, rxi) >> core->rxbuf_min_shift;
}

static void
igb_write_packet_to_guest(IGBCore *core, struct NetRxPkt *pkt,
                          const E1000E_RxRing *rxr,
                          const E1000E_RSSInfo *rss_info)
{
    PCIDevice *d = core->owner;
    dma_addr_t base;
    uint8_t desc[E1000_MAX_RX_DESC_LEN];
    size_t desc_size;
    size_t desc_offset = 0;
    size_t iov_ofs = 0;

    struct iovec *iov = net_rx_pkt_get_iovec(pkt);
    size_t size = net_rx_pkt_get_total_len(pkt);
    size_t total_size = size + e1000x_fcs_len(core->mac);
    const E1000E_RingInfo *rxi;

    rxi = rxr->i;

    do {
        hwaddr ba;
        uint16_t written = 0;
        bool is_last = false;

        desc_size = total_size - desc_offset;

        if (desc_size > core->rx_desc_buf_size) {
            desc_size = core->rx_desc_buf_size;
        }

        if (igb_ring_empty(core, rxi)) {
            return;
        }

        base = igb_ring_head_descr(core, rxi);

        pci_dma_read(d, base, &desc, core->rx_desc_len);

        trace_e1000e_rx_descr(rxi->idx, base, core->rx_desc_len);

        igb_read_rx_descr(core, desc, &ba);

        if (ba) {
            if (desc_offset < size) {
                static const uint32_t fcs_pad;
                size_t iov_copy;
                size_t copy_size = size - desc_offset;
                if (copy_size > core->rx_desc_buf_size) {
                    copy_size = core->rx_desc_buf_size;
                }

                /* Copy packet payload */
                while (copy_size) {
                    iov_copy = MIN(copy_size, iov->iov_len - iov_ofs);

                    igb_write_to_rx_buffers(core, ba, &written,
                                            iov->iov_base + iov_ofs, iov_copy);

                    copy_size -= iov_copy;
                    iov_ofs += iov_copy;
                    if (iov_ofs == iov->iov_len) {
                        iov++;
                        iov_ofs = 0;
                    }
                }

                if (desc_offset + desc_size >= total_size) {
                    /* Simulate FCS checksum presence in the last descriptor */
                    igb_write_to_rx_buffers(core, ba, &written,
                          (const char *) &fcs_pad, e1000x_fcs_len(core->mac));
                }
            }
        } else { /* as per intel docs; skip descriptors with null buf addr */
            trace_e1000e_rx_null_descriptor();
        }
        desc_offset += desc_size;
        if (desc_offset >= total_size) {
            is_last = true;
        }

        igb_write_rx_descr(core, desc, is_last ? core->rx_pkt : NULL,
                           rss_info, written);

        pci_dma_write(d, base, &desc, core->rx_desc_len);

        igb_ring_advance(core, rxi, core->rx_desc_len / E1000_MIN_RX_DESC_LEN);

    } while (desc_offset < total_size);

    igb_update_rx_stats(core, size, total_size);
}

ssize_t igb_receive_iov(IGBCore *core, const struct iovec *iov, int iovcnt)
{
    static const int maximum_ethernet_hdr_len = (14 + 4);
    /* Min. octets in an ethernet frame sans FCS */
    static const int min_buf_size = 60;

    uint16_t queues = 0;
    uint32_t n;
    uint8_t min_buf[min_buf_size];
    struct iovec min_iov;
    struct eth_header *ehdr;
    uint8_t *filter_buf;
    size_t size, orig_size;
    size_t iov_ofs = 0;
    E1000E_RxRing rxr;
    E1000E_RSSInfo rss_info;
    size_t total_size;
    ssize_t retval;
    bool rdmts_hit;
    int i;

    trace_e1000e_rx_receive_iov(iovcnt);

    if (!e1000x_hw_rx_enabled(core->mac)) {
        return -1;
    }

    filter_buf = iov->iov_base + iov_ofs;
    orig_size = iov_size(iov, iovcnt);
    size = orig_size - iov_ofs;

    /* Pad to minimum Ethernet frame length */
    if (size < sizeof(min_buf)) {
        iov_to_buf(iov, iovcnt, iov_ofs, min_buf, size);
        memset(&min_buf[size], 0, sizeof(min_buf) - size);
        e1000x_inc_reg_if_not_full(core->mac, RUC);
        min_iov.iov_base = filter_buf = min_buf;
        min_iov.iov_len = size = sizeof(min_buf);
        iovcnt = 1;
        iov = &min_iov;
        iov_ofs = 0;
    } else if (iov->iov_len < maximum_ethernet_hdr_len) {
        /* This is very unlikely, but may happen. */
        iov_to_buf(iov, iovcnt, iov_ofs, min_buf, maximum_ethernet_hdr_len);
        filter_buf = min_buf;
    }

    /* Discard oversized packets if !LPE and !SBP. */
    if (e1000x_is_oversized(core->mac, size)) {
        return orig_size;
    }

    ehdr = PKT_GET_ETH_HDR(filter_buf);
    net_rx_pkt_set_packet_type(core->rx_pkt, get_eth_packet_type(ehdr));

    queues = igb_receive_route(core, ehdr);
    if (!queues) {
        trace_e1000e_rx_flt_dropped();
        return orig_size;
    }

    net_rx_pkt_attach_iovec_ex(core->rx_pkt, iov, iovcnt, iov_ofs,
                               e1000x_vlan_enabled(core->mac), core->vet);

    // TODO: Fix RETA for virtualized environment
    if (!pcie_sriov_is_iov(core->owner)) {
        igb_rss_parse_packet(core, core->rx_pkt, &rss_info);
        queues = BIT(rss_info.queue);
    }

    total_size = net_rx_pkt_get_total_len(core->rx_pkt) +
        e1000x_fcs_len(core->mac);

    retval = orig_size;

    for (i = 0; i < IGB_NUM_QUEUES; i++) {
        if (!(queues & BIT(i))) {
            continue;
        }

        igb_rx_ring_init(core, &rxr, i);

        trace_e1000e_rx_rss_dispatched_to_queue(rxr.i->idx);

        if (!igb_has_rxbufs(core, rxr.i, total_size)) {
            retval = 0;
        }
    }

    if (retval) {
        for (i = 0; i < IGB_NUM_QUEUES; i++) {
            if (!(queues & BIT(i))) {
                continue;
            }

            rss_info.enabled = false;
            rss_info.hash = 0;
            rss_info.queue = i;
            rss_info.type = 0;

            igb_rx_ring_init(core, &rxr, i);

            igb_write_packet_to_guest(core, core->rx_pkt, &rxr, &rss_info);

            /* Check if receive descriptor minimum threshold hit */
            rdmts_hit = igb_rx_descr_threshold_hit(core, rxr.i);
            core->mac[EICR] |= igb_rx_wb_eic(core, rxr.i->idx, rdmts_hit);
        }

        n = E1000_ICR_RXT0;
        trace_e1000e_rx_written_to_guest(n);
    } else {
        n = E1000_ICS_RXO;
        trace_e1000e_rx_not_written_to_guest(n);
    }

    trace_e1000e_rx_interrupt_set(n);
    igb_set_interrupt_cause(core, n);

    return retval;
}

static inline bool
igb_have_autoneg(IGBCore *core)
{
    return core->phy[MII_BMCR] & MII_BMCR_AUTOEN;
}

static void igb_update_flowctl_status(IGBCore *core)
{
    if (igb_have_autoneg(core) && core->phy[MII_BMSR] & MII_BMSR_AN_COMP) {
        trace_e1000e_link_autoneg_flowctl(true);
        core->mac[CTRL] |= E1000_CTRL_TFCE | E1000_CTRL_RFCE;
    } else {
        trace_e1000e_link_autoneg_flowctl(false);
    }
}

static inline void
igb_link_down(IGBCore *core)
{
    e1000x_update_regs_on_link_down(core->mac, core->phy);
    igb_update_flowctl_status(core);
}

static inline void
igb_set_phy_ctrl(IGBCore *core, int index, uint16_t val)
{
    /* bits 0-5 reserved; MII_BMCR_[ANRESTART,RESET] are self clearing */
    core->phy[MII_BMCR] = val & ~(0x3f | MII_BMCR_RESET | MII_BMCR_ANRESTART);

    if ((val & MII_BMCR_ANRESTART) && igb_have_autoneg(core)) {
        e1000x_restart_autoneg(core->mac, core->phy, core->autoneg_timer);
    }
}

void igb_core_set_link_status(IGBCore *core)
{
    NetClientState *nc = qemu_get_queue(core->owner_nic);
    uint32_t old_status = core->mac[STATUS];

    trace_e1000e_link_status_changed(nc->link_down ? false : true);

    if (nc->link_down) {
        e1000x_update_regs_on_link_down(core->mac, core->phy);
    } else {
        if (igb_have_autoneg(core) &&
            !(core->phy[MII_BMSR] & MII_BMSR_AN_COMP)) {
            e1000x_restart_autoneg(core->mac, core->phy,
                                   core->autoneg_timer);
        } else {
            e1000x_update_regs_on_link_up(core->mac, core->phy);
            igb_start_recv(core);
        }
    }

    if (core->mac[STATUS] != old_status) {
        igb_set_interrupt_cause(core, E1000_ICR_LSC);
    }
}

static void igb_set_ctrl(IGBCore *core, int index, uint32_t val)
{
    trace_e1000e_core_ctrl_write(index, val);

    /* RST is self clearing */
    core->mac[CTRL] = val & ~E1000_CTRL_RST;
    core->mac[CTRL_DUP] = core->mac[CTRL];

    trace_e1000e_link_set_params(
        !!(val & E1000_CTRL_ASDE),
        (val & E1000_CTRL_SPD_SEL) >> E1000_CTRL_SPD_SHIFT,
        !!(val & E1000_CTRL_FRCSPD),
        !!(val & E1000_CTRL_FRCDPX),
        !!(val & E1000_CTRL_RFCE),
        !!(val & E1000_CTRL_TFCE));

    if (val & E1000_CTRL_RST) {
        trace_e1000e_core_ctrl_sw_reset();
        igb_core_reset(core);
    }

    if (val & E1000_CTRL_PHY_RST) {
        trace_e1000e_core_ctrl_phy_reset();
        core->mac[STATUS] |= E1000_STATUS_PHYRA;
    }
}

static void
igb_set_rfctl(IGBCore *core, int index, uint32_t val)
{
    trace_e1000e_rx_set_rfctl(val);

    if (!(val & E1000_RFCTL_ISCSI_DIS)) {
        trace_e1000e_wrn_iscsi_filtering_not_supported();
    }

    if (!(val & E1000_RFCTL_NFSW_DIS)) {
        trace_e1000e_wrn_nfsw_filtering_not_supported();
    }

    if (!(val & E1000_RFCTL_NFSR_DIS)) {
        trace_e1000e_wrn_nfsr_filtering_not_supported();
    }

    core->mac[RFCTL] = val;
}

static void
igb_parse_rxbufsize(IGBCore *core)
{
    uint32_t rctl = core->mac[RCTL];

    if (rctl & E1000_RCTL_FLXBUF_MASK) {
        int flxbuf = rctl & E1000_RCTL_FLXBUF_MASK;
        core->rx_desc_buf_size = (flxbuf >> E1000_RCTL_FLXBUF_SHIFT) * 1024;
    } else {
        core->rx_desc_buf_size = e1000x_rxbufsize(rctl);
    }

    trace_igb_rx_desc_buff_size(core->rx_desc_buf_size);
}

static void
igb_calc_rxdesclen(IGBCore *core)
{
    core->rx_desc_len = sizeof(union e1000_adv_rx_desc);
    return;

    if (igb_rx_use_legacy_descriptor(core)) {
        core->rx_desc_len = sizeof(struct e1000_rx_desc);
    } else {
        core->rx_desc_len = sizeof(union e1000_rx_desc_extended);
    }
    trace_e1000e_rx_desc_len(core->rx_desc_len);
}

static void
igb_set_rx_control(IGBCore *core, int index, uint32_t val)
{
    core->mac[RCTL] = val;
    trace_e1000e_rx_set_rctl(core->mac[RCTL]);

    if (val & E1000_RCTL_DTYP_MASK) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "igb: RCTL.DTYP must be zero for compatibility");
    }

    if (val & E1000_RCTL_EN) {
        igb_parse_rxbufsize(core);
        igb_calc_rxdesclen(core);
        core->rxbuf_min_shift = ((val / E1000_RCTL_RDMTS_QUAT) & 3) + 1 +
                                E1000_RING_DESC_LEN_SHIFT;

        igb_start_recv(core);
    }
}

static inline void
igb_clear_ims_bits(IGBCore *core, uint32_t bits)
{
    trace_e1000e_irq_clear_ims(bits, core->mac[IMS], core->mac[IMS] & ~bits);
    core->mac[IMS] &= ~bits;
}

static inline bool
igb_postpone_interrupt(bool *interrupt_pending, IGBIntrDelayTimer *timer)
{
    if (timer->running) {
        trace_e1000e_irq_postponed_by_xitr(timer->delay_reg << 2);

        *interrupt_pending = true;
        return true;
    }

    if (timer->core->mac[timer->delay_reg] != 0) {
        igb_intrmgr_rearm_timer(timer);
    }

    return false;
}

static inline bool
igb_eitr_should_postpone(IGBCore *core, int idx)
{
    return igb_postpone_interrupt(&core->eitr_intr_pending[idx],
                                  &core->eitr[idx]);
}

static inline void
igb_fix_icr_asserted(IGBCore *core)
{
    core->mac[ICR] &= ~E1000_ICR_ASSERTED;
    if (core->mac[ICR]) {
        core->mac[ICR] |= E1000_ICR_ASSERTED;
    }

    trace_e1000e_irq_fix_icr_asserted(core->mac[ICR]);
}

static void igb_send_msi(IGBCore *core, bool msix)
{
    uint32_t causes = core->mac[EICR] & core->mac[EIMS];
    uint32_t effective_eiac;
    int vector;

    for (vector = 0; vector < IGB_MSIX_VEC_NUM; ++vector) {
        if ((causes & BIT(vector)) && !igb_eitr_should_postpone(core, vector)) {

            trace_e1000e_irq_msix_notify_vec(vector);
            igb_msix_notify(core, vector);

            trace_e1000e_irq_icr_clear_eiac(core->mac[EICR], core->mac[EIAC]);
            effective_eiac = core->mac[EIAC] & BIT(vector);
            core->mac[EICR] &= ~effective_eiac;
        }
    }
}

static void igb_update_interrupt_state(IGBCore *core)
{
    uint32_t icr;
    uint32_t causes;
    uint32_t int_alloc;
    bool interrupts_pending;
    bool is_msix = msix_enabled(core->owner);

    icr = core->mac[ICR] & core->mac[IMS];
    if (icr) {
        if (is_msix) {
            causes = 0;
            if (icr & E1000_ICR_DRSTA) {
                int_alloc = core->mac[IVAR_MISC] & 0xff;
                if (int_alloc & E1000_IVAR_VALID) {
                    causes |= BIT(int_alloc & 0x1f);
                }
            }
            /* Check if other bits (excluding the TCP Timer) are enabled. */
            if (icr & ~E1000_ICR_DRSTA) {
                int_alloc = (core->mac[IVAR_MISC] >> 8) & 0xff;
                if (int_alloc & E1000_IVAR_VALID) {
                    causes |= BIT(int_alloc & 0x1f);
                }
            }
            core->mac[EICR] |= causes;
        } else {
            core->mac[EICR] |= E1000_EICR_OTHER;
            trace_e1000e_irq_add_msi_other(core->mac[EICR]);
        }
    } else {
        if (!is_msix) {
            core->mac[EICR] &= ~E1000_EICR_OTHER;
            igb_fix_icr_asserted(core);
        }
    }

    interrupts_pending = !!(core->mac[EIMS] & core->mac[EICR]);

    trace_e1000e_irq_pending_interrupts(core->mac[EIMS] & core->mac[EICR],
                                        core->mac[EICR], core->mac[EIMS]);

    if (is_msix || msi_enabled(core->owner)) {
        if (interrupts_pending) {
            igb_send_msi(core, is_msix);
        }
    } else {
        if (interrupts_pending) {
            if (!igb_eitr_should_postpone(core, 0)) {
                igb_raise_legacy_irq(core);
            }
        } else {
            igb_lower_legacy_irq(core);
        }
    }
}

static void
igb_set_interrupt_cause(IGBCore *core, uint32_t val)
{
    trace_e1000e_irq_set_cause_entry(val, core->mac[ICR]);

    core->mac[ICR] |= val;

    trace_e1000e_irq_set_cause_exit(val, core->mac[ICR]);

    igb_update_interrupt_state(core);
}

static void igb_set_eics(IGBCore *core, int index, uint32_t val)
{
    bool msix = !!(core->mac[GPIE] & E1000_GPIE_MSIX_MODE);

    trace_igb_irq_write_eics(val, msix);

    core->mac[EICS] |=
        msix ? (val & E1000_EICR_MSIX_MASK) : (val & E1000_EICR_LEGACY_MASK);

    // TODO: Move to igb_update_interrupt_state if EICS is modified in other
    // places.
    core->mac[EICR] = core->mac[EICS];

    igb_update_interrupt_state(core);
}

static void igb_set_eims(IGBCore *core, int index, uint32_t val)
{
    bool msix = !!(core->mac[GPIE] & E1000_GPIE_MSIX_MODE);

    trace_igb_irq_write_eims(val, msix);

    core->mac[EIMS] |=
        msix ? (val & E1000_EICR_MSIX_MASK) : (val & E1000_EICR_LEGACY_MASK);

    igb_update_interrupt_state(core);
}

static void igb_vf_reset(IGBCore *core, uint16_t vfn)
{
    // TODO: Reset of the queue enable and the interrupt registers of the VF.

    core->mac[V2PMAILBOX0 + vfn] &= ~E1000_V2PMAILBOX_RSTI;
    core->mac[V2PMAILBOX0 + vfn] = E1000_V2PMAILBOX_RSTD;
}

static void mailbox_interrupt_to_vf(IGBCore *core, uint16_t vfn)
{
    uint32_t ent = core->mac[VTIVAR_MISC + vfn] & 0xFF;

    if ((ent & E1000_IVAR_VALID)) {
        core->mac[EICR] |= (ent & 0x3) << (22 - vfn*3);
        igb_update_interrupt_state(core);
    }
}

static void mailbox_interrupt_to_pf(IGBCore *core)
{
    igb_set_interrupt_cause(core, E1000_ICR_VMMB);
}

static void igb_set_pfmailbox(IGBCore *core, int index, uint32_t val)
{
    uint16_t vfn = index - P2VMAILBOX0;

    trace_igb_set_pfmailbox(vfn, val);

    if (val & E1000_P2VMAILBOX_STS) {
        core->mac[V2PMAILBOX0 + vfn] |= E1000_V2PMAILBOX_PFSTS;
        mailbox_interrupt_to_vf(core, vfn);
    }

    if (val & E1000_P2VMAILBOX_ACK) {
        core->mac[V2PMAILBOX0 + vfn] |= E1000_V2PMAILBOX_PFACK;
        mailbox_interrupt_to_vf(core, vfn);
    }

    /* Buffer Taken by PF (can be set only if the VFU is cleared). */
    if (val & E1000_P2VMAILBOX_PFU) {
        if (!(core->mac[index] & E1000_P2VMAILBOX_VFU)) {
            core->mac[index] |= E1000_P2VMAILBOX_PFU;
            core->mac[V2PMAILBOX0 + vfn] |= E1000_V2PMAILBOX_PFU;
        }
    } else {
        core->mac[index] &= ~E1000_P2VMAILBOX_PFU;
        core->mac[V2PMAILBOX0 + vfn] &= ~E1000_V2PMAILBOX_PFU;
    }

    if (val & E1000_P2VMAILBOX_RVFU) {
        core->mac[V2PMAILBOX0 + vfn] &= ~E1000_V2PMAILBOX_VFU;
        core->mac[MBVFICR] &= ~((BIT(vfn) << 16) | BIT(vfn));
    }
}

static void igb_set_vfmailbox(IGBCore *core, int index, uint32_t val)
{
    uint16_t vfn = index - V2PMAILBOX0;

    trace_igb_set_vfmailbox(vfn, val);

    if (val & E1000_V2PMAILBOX_REQ) {
        core->mac[MBVFICR] |= BIT(vfn);
        mailbox_interrupt_to_pf(core);
    }

    if (val & E1000_V2PMAILBOX_ACK) {
        core->mac[MBVFICR] |= (BIT(vfn) << 16);
        mailbox_interrupt_to_pf(core);
    }

    /* Buffer Taken by VF (can be set only if the PFU is cleared). */
    if (val & E1000_V2PMAILBOX_VFU) {
        if (!(core->mac[index] & E1000_V2PMAILBOX_PFU)) {
            core->mac[index] |= E1000_V2PMAILBOX_VFU;
            core->mac[P2VMAILBOX0 + vfn] |= E1000_P2VMAILBOX_VFU;
        }
    } else {
        core->mac[index] &= ~E1000_V2PMAILBOX_VFU;
        core->mac[P2VMAILBOX0 + vfn] &= ~E1000_P2VMAILBOX_VFU;
    }
}

static void igb_set_mbvficr(IGBCore *core, int index, uint32_t val)
{
    core->mac[MBVFICR] &= ~(val & 0xFF00FF);
}

static void igb_set_vflre(IGBCore *core, int index, uint32_t val)
{
    core->mac[VFLRE] &= ~(val & 0xFF);
}

static void igb_set_eimc(IGBCore *core, int index, uint32_t val)
{
    bool msix = !!(core->mac[GPIE] & E1000_GPIE_MSIX_MODE);

    /* Interrupts are disabled via a write to EIMC and reflected in EIMS. */
    core->mac[EIMS] &=
        msix ? ~(val & E1000_EICR_MSIX_MASK) : ~(val & E1000_EICR_LEGACY_MASK);

    trace_igb_irq_write_eimc(val, core->mac[EIMS], msix);
    igb_update_interrupt_state(core);
}

static void igb_set_eiac(IGBCore *core, int index, uint32_t val)
{
    bool msix = !!(core->mac[GPIE] & E1000_GPIE_MSIX_MODE);

    if (msix)
    {
        trace_igb_irq_write_eiac(val);

        /* TODO: When using IOV, the bits that correspond to MSI-X vectors
           that are assigned to a VF are read-only. */
        core->mac[EIAC] |= (val & E1000_EICR_MSIX_MASK);
    }
}

static void igb_set_eiam(IGBCore *core, int index, uint32_t val)
{
    bool msix = !!(core->mac[GPIE] & E1000_GPIE_MSIX_MODE);

    /* TODO: When using IOV, the bits that correspond to MSI-X vectors that
       are assigned to a VF are read-only. */
    core->mac[EIAM] |=
        msix ? ~(val & E1000_EICR_MSIX_MASK) : ~(val & E1000_EICR_LEGACY_MASK);

    trace_igb_irq_write_eiam(val, msix);
}

static void igb_set_eicr(IGBCore *core, int index, uint32_t val)
{
    bool msix = !!(core->mac[GPIE] & E1000_GPIE_MSIX_MODE);

    /* TODO: In IOV mode, only bit zero of this vector is available for the PF
       function. */
    core->mac[EICR] &=
        msix ? ~(val & E1000_EICR_MSIX_MASK) : ~(val & E1000_EICR_LEGACY_MASK);

    trace_igb_irq_write_eicr(val, msix);
    igb_update_interrupt_state(core);
}

static void igb_set_vtctrl(IGBCore *core, int index, uint32_t val)
{
    uint16_t vfn;

    if (val & E1000_CTRL_RST) {
        vfn = (index - PVTCTRL0) / 0x40;
        igb_vf_reset(core, vfn);
    }
}

static void igb_set_vteics(IGBCore *core, int index, uint32_t val)
{
    uint16_t vfn = (index - PVTEICS0) / 0x40;

    core->mac[index] = val;
    igb_set_eics(core, EICS, (val & 0x7) << (22 - vfn*3));
}

static void igb_set_vteims(IGBCore *core, int index, uint32_t val)
{
    uint16_t vfn = (index - PVTEIMS0) / 0x40;

    core->mac[index] = val;
    igb_set_eims(core, EIMS, (val & 0x7) << (22 - vfn*3));
}

static void igb_set_vteimc(IGBCore *core, int index, uint32_t val)
{
    uint16_t vfn = (index - PVTEIMC0) / 0x40;

    core->mac[index] = val;
    igb_set_eimc(core, EIMC, (val & 0x7) << (22 - vfn*3));
}

static void igb_set_vteiac(IGBCore *core, int index, uint32_t val)
{
    uint16_t vfn = (index - PVTEIAC0) / 0x40;

    core->mac[index] = val;
    igb_set_eiac(core, EIAC, (val & 0x7) << (22 - vfn*3));
}

static void igb_set_vteiam(IGBCore *core, int index, uint32_t val)
{
    uint16_t vfn = (index - PVTEIAM0) / 0x40;

    core->mac[index] = val;
    igb_set_eiam(core, EIAM, (val & 0x7) << (22 - vfn*3));
}

static void igb_set_vteicr(IGBCore *core, int index, uint32_t val)
{
    uint16_t vfn = (index - PVTEICR0) / 0x40;

    core->mac[index] = val;
    igb_set_eicr(core, EICR, (val & 0x7) << (22 - vfn*3));
}

static void igb_set_vtivar(IGBCore *core, int index, uint32_t val)
{
    uint16_t vfn = (index - VTIVAR);
    uint16_t qn = vfn;
    uint8_t ent;
    int n;

    core->mac[index] = val;

    /* Get assigned vector associated with queue Rx#0. */
    ent = val & 0xFF;
    if ((ent & E1000_IVAR_VALID)) {
        n = igb_ivar_entry_rx(qn);
        ent = 0x80 | (24 - vfn*3 - (2-(ent & 0x7)));
        core->mac[IVAR0 + n/4] |= ent << 8*(n%4);
    }

    /* Get assigned vector associated with queue Tx#0 */
    ent = (val >> 8) & 0xFF;
    if ((ent & E1000_IVAR_VALID)) {
        n = igb_ivar_entry_tx(qn);
        ent = 0x80 | (24 - vfn*3 - (2-(ent & 0x7)));
        core->mac[IVAR0 + n/4] |= ent << 8*(n%4);
    }

    /* Ignoring assigned vectors associated with queues Rx#1 and Tx#1 for
     * now. */
}

static inline void
igb_autoneg_timer(void *opaque)
{
    IGBCore *core = opaque;
    if (!qemu_get_queue(core->owner_nic)->link_down) {
        e1000x_update_regs_on_autoneg_done(core->mac, core->phy);
        igb_start_recv(core);

        igb_update_flowctl_status(core);
        /* signal link status change to the guest */
        igb_set_interrupt_cause(core, E1000_ICR_LSC);
    }
}

static inline uint16_t
igb_get_reg_index_with_offset(const uint16_t *mac_reg_access, hwaddr addr)
{
    uint16_t index = (addr & 0x1ffff) >> 2;
    return index + (mac_reg_access[index] & 0xfffe);
}

static const char igb_phy_regcap[0x20] = {
    [MII_BMCR]                   = PHY_RW,
    [MII_BMSR]                   = PHY_R,
    [MII_PHYID1]                 = PHY_R,
    [MII_PHYID2]                 = PHY_R,
    [MII_ANAR]                   = PHY_RW,
    [MII_ANLPAR]                 = PHY_R,
    [MII_ANER]                   = PHY_R,
    [MII_ANNP]                   = PHY_RW,
    [MII_ANLPRNP]                = PHY_R,
    [MII_CTRL1000]               = PHY_RW,
    [MII_STAT1000]               = PHY_R,
    [MII_EXTSTAT]                = PHY_R,

    [IGP01E1000_PHY_PAGE_SELECT] = PHY_RW,
};

static void
igb_phy_reg_write(IGBCore *core, uint32_t addr, uint16_t data)
{
    assert(addr < E1000E_PHY_PAGE_SIZE);

    if (addr == MII_BMCR) {
        igb_set_phy_ctrl(core, addr, data);
    } else {
        core->phy[addr] = data;
    }
}

static void
igb_set_mdic(IGBCore *core, int index, uint32_t val)
{
    uint32_t data = val & E1000_MDIC_DATA_MASK;
    uint32_t addr = ((val & E1000_MDIC_REG_MASK) >> E1000_MDIC_REG_SHIFT);

    if ((val & E1000_MDIC_PHY_MASK) >> E1000_MDIC_PHY_SHIFT != 1) { /* phy # */
        val = core->mac[MDIC] | E1000_MDIC_ERROR;
    } else if (val & E1000_MDIC_OP_READ) {
        if (!(igb_phy_regcap[addr] & PHY_R)) {
            trace_igb_core_mdic_read_unhandled(addr);
            val |= E1000_MDIC_ERROR;
        } else {
            val = (val ^ data) | core->phy[addr];
            trace_igb_core_mdic_read(addr, val);
        }
    } else if (val & E1000_MDIC_OP_WRITE) {
        if (!(igb_phy_regcap[addr] & PHY_W)) {
            trace_igb_core_mdic_write_unhandled(addr);
            val |= E1000_MDIC_ERROR;
        } else {
            trace_igb_core_mdic_write(addr, data);
            igb_phy_reg_write(core, addr, data);
        }
    }
    core->mac[MDIC] = val | E1000_MDIC_READY;

    if (val & E1000_MDIC_INT_EN) {
        igb_set_interrupt_cause(core, E1000_ICR_MDAC);
    }
}

static void
igb_set_rdt(IGBCore *core, int index, uint32_t val)
{
    core->mac[index] = val & 0xffff;
    trace_e1000e_rx_set_rdt(igb_mq_queue_idx(RDT0, index), val);
    igb_start_recv(core);
}

static void igb_set_status(IGBCore *core, int index, uint32_t val)
{
    if ((val & E1000_STATUS_PHYRA) == 0) {
        core->mac[index] &= ~E1000_STATUS_PHYRA;
    }
}

static void
igb_set_ctrlext(IGBCore *core, int index, uint32_t val)
{
    trace_e1000e_link_set_ext_params(!!(val & E1000_CTRL_EXT_ASDCHK),
                                     !!(val & E1000_CTRL_EXT_SPD_BYPS));

    // TODO: PFRSTD

    /* Zero self-clearing bits */
    val &= ~(E1000_CTRL_EXT_ASDCHK | E1000_CTRL_EXT_EE_RST);
    core->mac[CTRL_EXT] = val;
}

static void
igb_set_pbaclr(IGBCore *core, int index, uint32_t val)
{
    int i;

    core->mac[PBACLR] = val & E1000_PBACLR_VALID_MASK;

    if (!msix_enabled(core->owner)) {
        return;
    }

    for (i = 0; i < IGB_MSIX_VEC_NUM; i++) {
        if (core->mac[PBACLR] & BIT(i)) {
            msix_clr_pending(core->owner, i);
        }
    }
}

static void
igb_set_fcrth(IGBCore *core, int index, uint32_t val)
{
    core->mac[FCRTH] = val & 0xFFF8;
}

static void
igb_set_fcrtl(IGBCore *core, int index, uint32_t val)
{
    core->mac[FCRTL] = val & 0x8000FFF8;
}

static inline void
igb_set_16bit(IGBCore *core, int index, uint32_t val)
{
    core->mac[index] = val & 0xffff;
}

static void
igb_set_dlen(IGBCore *core, int index, uint32_t val)
{
    core->mac[index] = val & E1000_XDLEN_MASK;
}

static void igb_set_dbal(IGBCore *core, int index, uint32_t val)
{
    core->mac[index] = val & E1000_XDBAL_MASK;
}

static void igb_set_tdt(IGBCore *core, int index, uint32_t val)
{
    IGBTxRing txr;
    int qn = igb_mq_queue_idx(TDT0, index);

    core->mac[index] = val & 0xffff;
    igb_tx_ring_init(core, &txr, qn);
    igb_start_xmit(core, &txr);
}

static void
igb_set_ics(IGBCore *core, int index, uint32_t val)
{
    trace_e1000e_irq_write_ics(val);
    igb_set_interrupt_cause(core, val);
}

static void write_iam_content_to_ims(IGBCore *core)
{
    // TODO: Read and understand 8.8.11 and NSICR in 8.8.15 before removing
    // this return!
    return;

    /* If GPIE.NSICR = 0, then the copy of IAM to IMS will occur only if at
       least one bit is set in the IMS and there is a true interrupt as
       reflected in ICR.INTA. */
    if ((core->mac[GPIE] & E1000_GPIE_NSICR) ||
        (core->mac[IMS] && (core->mac[ICR] & E1000_ICR_INT_ASSERTED)))
    {
        core->mac[IMS] = core->mac[IAM];
    }
}

static void igb_set_icr(IGBCore *core, int index, uint32_t val)
{
    uint32_t icr = core->mac[ICR] & ~val;

    trace_igb_irq_icr_write(val, core->mac[ICR], icr);
    core->mac[ICR] = icr;
    write_iam_content_to_ims(core);
    igb_update_interrupt_state(core);
}

static void
igb_set_imc(IGBCore *core, int index, uint32_t val)
{
    trace_e1000e_irq_ims_clear_set_imc(val);
    igb_clear_ims_bits(core, val);
    igb_update_interrupt_state(core);
}

static void igb_set_ims(IGBCore *core, int index, uint32_t val)
{
    static const uint32_t ims_valid_mask =
        E1000_ICR_TXDW     | E1000_ICR_LSC      | E1000_ICR_RXDMT0   |
        E1000_ICR_MACSEC   | E1000_ICR_RX0      | E1000_ICR_RXT0     |
        E1000_ICR_VMMB     | E1000_ICR_GPI_SDP0 | E1000_ICR_GPI_SDP1 |
        E1000_ICR_GPI_SDP2 | E1000_ICR_GPI_SDP3 | E1000_ICR_PTRAP    |
        E1000_ICR_MNG      | E1000_ICR_OMED     | E1000_ICR_FER      |
        E1000_ICR_NFER     | E1000_ICR_CSRTO    | E1000_ICR_SCE      |
        E1000_ICR_SW_WD    | E1000_ICR_DOUTSYNC | E1000_ICR_DRSTA;

    uint32_t valid_val = val & ims_valid_mask;

    trace_e1000e_irq_set_ims(val, core->mac[IMS], core->mac[IMS] | valid_val);
    core->mac[IMS] |= valid_val;
    igb_update_interrupt_state(core);
}

static uint32_t
igb_mac_readreg(IGBCore *core, int index)
{
    return core->mac[index];
}

static uint32_t
igb_mac_ics_read(IGBCore *core, int index)
{
    trace_e1000e_irq_read_ics(core->mac[ICS]);
    return core->mac[ICS];
}

static uint32_t
igb_mac_ims_read(IGBCore *core, int index)
{
    trace_e1000e_irq_read_ims(core->mac[IMS]);
    return core->mac[IMS];
}

#define IGB_LOW_BITS_READ_FUNC(num)                   \
    static uint32_t                                   \
    igb_mac_low##num##_read(IGBCore *core, int index) \
    {                                                 \
        return core->mac[index] & (BIT(num) - 1);     \
    }                                                 \

#define IGB_LOW_BITS_READ(num)                        \
    igb_mac_low##num##_read

IGB_LOW_BITS_READ_FUNC(4);
IGB_LOW_BITS_READ_FUNC(6);
IGB_LOW_BITS_READ_FUNC(11);
IGB_LOW_BITS_READ_FUNC(13);
IGB_LOW_BITS_READ_FUNC(16);

static uint32_t
igb_mac_swsm_read(IGBCore *core, int index)
{
    uint32_t val = core->mac[SWSM];
    core->mac[SWSM] = val | 1;
    return val;
}

static uint32_t igb_mac_eitr_read(IGBCore *core, int index)
{
    uint32_t val = core->eitr_guest_value[index - EITR0];

    /* CNT_INGR (bit 31) is always read as zero. */
    val &= (BIT(31) - 1);

    return val;
}

static uint32_t igb_mac_pfmailbox_read(IGBCore *core, int index)
{
    uint32_t val = core->mac[index];

    /* STS and ACK (bit 0 and 1) are always read as zero. */
    val &= 0xFC;

    return val;
}

static uint32_t igb_mac_vfmailbox_read(IGBCore *core, int index)
{
    uint32_t val = core->mac[index];

    /* REQ and ACK (bit 0 and 1) are always read as zero. */
    val &= 0xFC;

    /* PFSTS, PFACK and RSTD (bits 4, 5 and 7) are clear after read bits. */
    core->mac[index] &= 0x4F;

    return val;
}

static uint32_t igb_mac_icr_read(IGBCore *core, int index)
{
    uint32_t ret = core->mac[ICR];

    trace_igb_irq_icr_read(ret);

    if (core->mac[GPIE] & E1000_GPIE_NSICR) {
        trace_igb_irq_icr_clear_gpie_nsicr();
        core->mac[ICR] = 0;
    } else {
        if (core->mac[IMS] == 0) {
            trace_igb_irq_icr_clear_zero_ims();
            core->mac[ICR] = 0;
        }
    }

    write_iam_content_to_ims(core);
    igb_update_interrupt_state(core);
    return ret;
}

static uint32_t
igb_mac_read_clr4(IGBCore *core, int index)
{
    uint32_t ret = core->mac[index];

    core->mac[index] = 0;
    return ret;
}

static uint32_t
igb_mac_read_clr8(IGBCore *core, int index)
{
    uint32_t ret = core->mac[index];

    core->mac[index] = 0;
    core->mac[index - 1] = 0;
    return ret;
}

static uint32_t
igb_get_ctrl(IGBCore *core, int index)
{
    uint32_t val = core->mac[CTRL];

    trace_e1000e_link_read_params(
        !!(val & E1000_CTRL_ASDE),
        (val & E1000_CTRL_SPD_SEL) >> E1000_CTRL_SPD_SHIFT,
        !!(val & E1000_CTRL_FRCSPD),
        !!(val & E1000_CTRL_FRCDPX),
        !!(val & E1000_CTRL_RFCE),
        !!(val & E1000_CTRL_TFCE));

    return val;
}

static uint32_t igb_get_status(IGBCore *core, int index)
{
    uint32_t status = core->mac[STATUS];

    if (core->mac[CTRL] & E1000_CTRL_FRCDPX) {
        status |= (core->mac[CTRL] & E1000_CTRL_FD) ? E1000_STATUS_FD : 0;
    } else {
        status |= E1000_STATUS_FD;
    }

    if ((core->mac[CTRL] & E1000_CTRL_FRCSPD) ||
        (core->mac[CTRL_EXT] & E1000_CTRL_EXT_SPD_BYPS)) {
        switch (core->mac[CTRL] & E1000_CTRL_SPD_SEL) {
        case E1000_CTRL_SPD_10:
            status |= E1000_STATUS_SPEED_10;
            break;
        case E1000_CTRL_SPD_100:
            status |= E1000_STATUS_SPEED_100;
            break;
        case E1000_CTRL_SPD_1000:
        default:
            status |= E1000_STATUS_SPEED_1000;
            break;
        }
    } else {
        status |= E1000_STATUS_SPEED_1000;
    }

    if (pcie_sriov_is_iov(core->owner)) {
        status |=
            (pcie_sriov_vfs_count(core->owner) << E1000_STATUS_NUM_VFS_SHIFT);
        status |= E1000_STATUS_IOV_MODE;
    }

    if (!(core->mac[CTRL] & E1000_CTRL_GIO_MASTER_DISABLE)) {
        status |= E1000_STATUS_GIO_MASTER_ENABLE;
    }

    return status;
}

static uint32_t
igb_get_tarc(IGBCore *core, int index)
{
    return core->mac[index] & ((BIT(11) - 1) |
                                BIT(27)      |
                                BIT(28)      |
                                BIT(29)      |
                                BIT(30));
}

static void
igb_mac_writereg(IGBCore *core, int index, uint32_t val)
{
    core->mac[index] = val;
}

static void igb_mac_set_macaddr(IGBCore *core, int index, uint32_t val)
{
    uint32_t macaddr[2];

    core->mac[index] = val;

    macaddr[0] = cpu_to_le32(core->mac[RA]);
    macaddr[1] = cpu_to_le32(core->mac[RA + 1]);

    qemu_format_nic_info_str(qemu_get_queue(core->owner_nic),
        (uint8_t *) macaddr);

    trace_e1000e_mac_set_sw(MAC_ARG(macaddr));
}

static void
igb_set_eecd(IGBCore *core, int index, uint32_t val)
{
    static const uint32_t ro_bits = E1000_EECD_PRES          |
                                    E1000_EECD_AUTO_RD       |
                                    E1000_EECD_SIZE_EX_MASK;

    core->mac[EECD] = (core->mac[EECD] & ro_bits) | (val & ~ro_bits);
}

static void
igb_set_eerd(IGBCore *core, int index, uint32_t val)
{
    uint32_t addr = (val >> E1000_EERW_ADDR_SHIFT) & E1000_EERW_ADDR_MASK;
    uint32_t flags = 0;
    uint32_t data = 0;

    if ((addr < IGB_EEPROM_SIZE) && (val & E1000_EERW_START)) {
        data = core->eeprom[addr];
        flags = E1000_EERW_DONE;
    }

    core->mac[EERD] = flags                           |
                      (addr << E1000_EERW_ADDR_SHIFT) |
                      (data << E1000_EERW_DATA_SHIFT);
}

static void
igb_set_eewr(IGBCore *core, int index, uint32_t val)
{
    uint32_t addr = (val >> E1000_EERW_ADDR_SHIFT) & E1000_EERW_ADDR_MASK;
    uint32_t data = (val >> E1000_EERW_DATA_SHIFT) & E1000_EERW_DATA_MASK;
    uint32_t flags = 0;

    if ((addr < IGB_EEPROM_SIZE) && (val & E1000_EERW_START)) {
        core->eeprom[addr] = data;
        flags = E1000_EERW_DONE;
    }

    core->mac[EERD] = flags                           |
                      (addr << E1000_EERW_ADDR_SHIFT) |
                      (data << E1000_EERW_DATA_SHIFT);
}

static void igb_set_eitr(IGBCore *core, int index, uint32_t val)
{
    uint32_t interval = val & 0x7FFE;
    uint32_t eitr_num = index - EITR0;

    trace_igb_irq_eitr_set(eitr_num, val);

    core->eitr_guest_value[eitr_num] = val;
    core->mac[index] = interval;
}

static void
igb_update_rx_offloads(IGBCore *core)
{
    int cso_state = igb_rx_l4_cso_enabled(core);

    trace_e1000e_rx_set_cso(cso_state);
}

static void
igb_set_rxcsum(IGBCore *core, int index, uint32_t val)
{
    core->mac[RXCSUM] = val;
    igb_update_rx_offloads(core);
}

static void
igb_set_gcr(IGBCore *core, int index, uint32_t val)
{
    uint32_t ro_bits = core->mac[GCR] & E1000_GCR_RO_BITS;
    core->mac[GCR] = (val & ~E1000_GCR_RO_BITS) | ro_bits;
}

#define igb_getreg(x)    [x] = igb_mac_readreg
typedef uint32_t (*readops)(IGBCore *, int);
static const readops igb_macreg_readops[] = {
    igb_getreg(PBA),
    igb_getreg(WUFC),
    igb_getreg(MANC),
    igb_getreg(TOTL),
    igb_getreg(RDT0),
    igb_getreg(RDT1),
    igb_getreg(RDT2),
    igb_getreg(RDT3),
    igb_getreg(RDT4),
    igb_getreg(RDT5),
    igb_getreg(RDT6),
    igb_getreg(RDT7),
    igb_getreg(RDT8),
    igb_getreg(RDT9),
    igb_getreg(RDT10),
    igb_getreg(RDT11),
    igb_getreg(RDT12),
    igb_getreg(RDT13),
    igb_getreg(RDT14),
    igb_getreg(RDT15),
    igb_getreg(RDBAH0),
    igb_getreg(RDBAH1),
    igb_getreg(RDBAH2),
    igb_getreg(RDBAH3),
    igb_getreg(RDBAH4),
    igb_getreg(RDBAH5),
    igb_getreg(RDBAH6),
    igb_getreg(RDBAH7),
    igb_getreg(RDBAH8),
    igb_getreg(RDBAH9),
    igb_getreg(RDBAH10),
    igb_getreg(RDBAH11),
    igb_getreg(RDBAH12),
    igb_getreg(RDBAH13),
    igb_getreg(RDBAH14),
    igb_getreg(RDBAH15),
    igb_getreg(TDBAL0),
    igb_getreg(TDBAL1),
    igb_getreg(TDBAL2),
    igb_getreg(TDBAL3),
    igb_getreg(TDBAL4),
    igb_getreg(TDBAL5),
    igb_getreg(TDBAL6),
    igb_getreg(TDBAL7),
    igb_getreg(TDBAL8),
    igb_getreg(TDBAL9),
    igb_getreg(TDBAL10),
    igb_getreg(TDBAL11),
    igb_getreg(TDBAL12),
    igb_getreg(TDBAL13),
    igb_getreg(TDBAL14),
    igb_getreg(TDBAL15),
    igb_getreg(RDLEN0),
    igb_getreg(RDLEN1),
    igb_getreg(RDLEN2),
    igb_getreg(RDLEN3),
    igb_getreg(RDLEN4),
    igb_getreg(RDLEN5),
    igb_getreg(RDLEN6),
    igb_getreg(RDLEN7),
    igb_getreg(RDLEN8),
    igb_getreg(RDLEN9),
    igb_getreg(RDLEN10),
    igb_getreg(RDLEN11),
    igb_getreg(RDLEN12),
    igb_getreg(RDLEN13),
    igb_getreg(RDLEN14),
    igb_getreg(RDLEN15),
    igb_getreg(SRRCTL0),
    igb_getreg(SRRCTL1),
    igb_getreg(SRRCTL2),
    igb_getreg(SRRCTL3),
    igb_getreg(SRRCTL4),
    igb_getreg(SRRCTL5),
    igb_getreg(SRRCTL6),
    igb_getreg(SRRCTL7),
    igb_getreg(SRRCTL8),
    igb_getreg(SRRCTL9),
    igb_getreg(SRRCTL10),
    igb_getreg(SRRCTL11),
    igb_getreg(SRRCTL12),
    igb_getreg(SRRCTL13),
    igb_getreg(SRRCTL14),
    igb_getreg(SRRCTL15),
    igb_getreg(LATECOL),
    igb_getreg(SEQEC),
    igb_getreg(XONTXC),
    igb_getreg(WUS),
    igb_getreg(GORCL),
    igb_getreg(MGTPRC),
    igb_getreg(EERD),
    igb_getreg(EIAC),
    igb_getreg(MANC2H),
    igb_getreg(RXCSUM),
    igb_getreg(GSCL_3),
    igb_getreg(GSCN_2),
    igb_getreg(FCAH),
    igb_getreg(FCRTH),
    igb_getreg(FLOP),
    igb_getreg(FLASHT),
    igb_getreg(RXSTMPH),
    igb_getreg(TXSTMPL),
    igb_getreg(TIMADJL),
    igb_getreg(RDH0),
    igb_getreg(RDH1),
    igb_getreg(RDH2),
    igb_getreg(RDH3),
    igb_getreg(RDH4),
    igb_getreg(RDH5),
    igb_getreg(RDH6),
    igb_getreg(RDH7),
    igb_getreg(RDH8),
    igb_getreg(RDH9),
    igb_getreg(RDH10),
    igb_getreg(RDH11),
    igb_getreg(RDH12),
    igb_getreg(RDH13),
    igb_getreg(RDH14),
    igb_getreg(RDH15),
    igb_getreg(TDT0),
    igb_getreg(TDT1),
    igb_getreg(TDT2),
    igb_getreg(TDT3),
    igb_getreg(TDT4),
    igb_getreg(TDT5),
    igb_getreg(TDT6),
    igb_getreg(TDT7),
    igb_getreg(TDT8),
    igb_getreg(TDT9),
    igb_getreg(TDT10),
    igb_getreg(TDT11),
    igb_getreg(TDT12),
    igb_getreg(TDT13),
    igb_getreg(TDT14),
    igb_getreg(TDT15),
    igb_getreg(TNCRS),
    igb_getreg(RJC),
    igb_getreg(IAM),
    igb_getreg(GSCL_2),
    igb_getreg(FLSWDATA),
    igb_getreg(RXSATRH),
    igb_getreg(TIPG),
    igb_getreg(FLMNGCTL),
    igb_getreg(FLMNGCNT),
    igb_getreg(TSYNCTXCTL),
    igb_getreg(EXTCNF_SIZE),
    igb_getreg(EXTCNF_CTRL),
    igb_getreg(EEMNGDATA),
    igb_getreg(CTRL_EXT),
    igb_getreg(SYSTIMH),
    igb_getreg(EEMNGCTL),
    igb_getreg(FLMNGDATA),
    igb_getreg(TSYNCRXCTL),
    igb_getreg(LEDCTL),
    igb_getreg(TCTL),
    igb_getreg(TCTL_EXT),
    igb_getreg(DTXCTL),
    igb_getreg(RXPBS),
    igb_getreg(TDH0),
    igb_getreg(TDH1),
    igb_getreg(TDH2),
    igb_getreg(TDH3),
    igb_getreg(TDH4),
    igb_getreg(TDH5),
    igb_getreg(TDH6),
    igb_getreg(TDH7),
    igb_getreg(TDH8),
    igb_getreg(TDH9),
    igb_getreg(TDH10),
    igb_getreg(TDH11),
    igb_getreg(TDH12),
    igb_getreg(TDH13),
    igb_getreg(TDH14),
    igb_getreg(TDH15),
    igb_getreg(ECOL),
    igb_getreg(DC),
    igb_getreg(RLEC),
    igb_getreg(XOFFTXC),
    igb_getreg(RFC),
    igb_getreg(RNBC),
    igb_getreg(MGTPTC),
    igb_getreg(TIMINCA),
    igb_getreg(RXCFGL),
    igb_getreg(MFUTP01),
    igb_getreg(FACTPS),
    igb_getreg(GSCL_1),
    igb_getreg(GSCN_0),
    igb_getreg(GCR2),
    igb_getreg(PBACLR),
    igb_getreg(FCTTV),
    igb_getreg(EEWR),
    igb_getreg(FLSWCTL),
    igb_getreg(RXSATRL),
    igb_getreg(SYSTIML),
    igb_getreg(RXUDP),
    igb_getreg(TORL),
    igb_getreg(TDLEN0),
    igb_getreg(TDLEN1),
    igb_getreg(TDLEN2),
    igb_getreg(TDLEN3),
    igb_getreg(TDLEN4),
    igb_getreg(TDLEN5),
    igb_getreg(TDLEN6),
    igb_getreg(TDLEN7),
    igb_getreg(TDLEN8),
    igb_getreg(TDLEN9),
    igb_getreg(TDLEN10),
    igb_getreg(TDLEN11),
    igb_getreg(TDLEN12),
    igb_getreg(TDLEN13),
    igb_getreg(TDLEN14),
    igb_getreg(TDLEN15),
    igb_getreg(MCC),
    igb_getreg(WUC),
    igb_getreg(EECD),
    igb_getreg(MFUTP23),
    igb_getreg(FCRTV),
    igb_getreg(TXDCTL0),
    igb_getreg(TXDCTL1),
    igb_getreg(TXDCTL2),
    igb_getreg(TXDCTL3),
    igb_getreg(TXDCTL4),
    igb_getreg(TXDCTL5),
    igb_getreg(TXDCTL6),
    igb_getreg(TXDCTL7),
    igb_getreg(TXDCTL8),
    igb_getreg(TXDCTL9),
    igb_getreg(TXDCTL10),
    igb_getreg(TXDCTL11),
    igb_getreg(TXDCTL12),
    igb_getreg(TXDCTL13),
    igb_getreg(TXDCTL14),
    igb_getreg(TXDCTL15),
    igb_getreg(TXCTL0),
    igb_getreg(TXCTL1),
    igb_getreg(TXCTL2),
    igb_getreg(TXCTL3),
    igb_getreg(TXCTL4),
    igb_getreg(TXCTL5),
    igb_getreg(TXCTL6),
    igb_getreg(TXCTL7),
    igb_getreg(TXCTL8),
    igb_getreg(TXCTL9),
    igb_getreg(TXCTL10),
    igb_getreg(TXCTL11),
    igb_getreg(TXCTL12),
    igb_getreg(TXCTL13),
    igb_getreg(TXCTL14),
    igb_getreg(TXCTL15),
    igb_getreg(PVTCTRL0),
    igb_getreg(PVTCTRL1),
    igb_getreg(PVTCTRL2),
    igb_getreg(PVTCTRL3),
    igb_getreg(PVTCTRL4),
    igb_getreg(PVTCTRL5),
    igb_getreg(PVTCTRL6),
    igb_getreg(PVTCTRL7),
    igb_getreg(PVTEIMS0),
    igb_getreg(PVTEIMS1),
    igb_getreg(PVTEIMS2),
    igb_getreg(PVTEIMS3),
    igb_getreg(PVTEIMS4),
    igb_getreg(PVTEIMS5),
    igb_getreg(PVTEIMS6),
    igb_getreg(PVTEIMS7),
    igb_getreg(PVTEIAC0),
    igb_getreg(PVTEIAC1),
    igb_getreg(PVTEIAC2),
    igb_getreg(PVTEIAC3),
    igb_getreg(PVTEIAC4),
    igb_getreg(PVTEIAC5),
    igb_getreg(PVTEIAC6),
    igb_getreg(PVTEIAC7),
    igb_getreg(PVTEIAM0),
    igb_getreg(PVTEIAM1),
    igb_getreg(PVTEIAM2),
    igb_getreg(PVTEIAM3),
    igb_getreg(PVTEIAM4),
    igb_getreg(PVTEIAM5),
    igb_getreg(PVTEIAM6),
    igb_getreg(PVTEIAM7),
    igb_getreg(PVFGPRC0),
    igb_getreg(PVFGPRC1),
    igb_getreg(PVFGPRC2),
    igb_getreg(PVFGPRC3),
    igb_getreg(PVFGPRC4),
    igb_getreg(PVFGPRC5),
    igb_getreg(PVFGPRC6),
    igb_getreg(PVFGPRC7),
    igb_getreg(PVFGPTC0),
    igb_getreg(PVFGPTC1),
    igb_getreg(PVFGPTC2),
    igb_getreg(PVFGPTC3),
    igb_getreg(PVFGPTC4),
    igb_getreg(PVFGPTC5),
    igb_getreg(PVFGPTC6),
    igb_getreg(PVFGPTC7),
    igb_getreg(PVFGORC0),
    igb_getreg(PVFGORC1),
    igb_getreg(PVFGORC2),
    igb_getreg(PVFGORC3),
    igb_getreg(PVFGORC4),
    igb_getreg(PVFGORC5),
    igb_getreg(PVFGORC6),
    igb_getreg(PVFGORC7),
    igb_getreg(PVFGOTC0),
    igb_getreg(PVFGOTC1),
    igb_getreg(PVFGOTC2),
    igb_getreg(PVFGOTC3),
    igb_getreg(PVFGOTC4),
    igb_getreg(PVFGOTC5),
    igb_getreg(PVFGOTC6),
    igb_getreg(PVFGOTC7),
    igb_getreg(PVFMPRC0),
    igb_getreg(PVFMPRC1),
    igb_getreg(PVFMPRC2),
    igb_getreg(PVFMPRC3),
    igb_getreg(PVFMPRC4),
    igb_getreg(PVFMPRC5),
    igb_getreg(PVFMPRC6),
    igb_getreg(PVFMPRC7),
    igb_getreg(PVFGPRLBC0),
    igb_getreg(PVFGPRLBC1),
    igb_getreg(PVFGPRLBC2),
    igb_getreg(PVFGPRLBC3),
    igb_getreg(PVFGPRLBC4),
    igb_getreg(PVFGPRLBC5),
    igb_getreg(PVFGPRLBC6),
    igb_getreg(PVFGPRLBC7),
    igb_getreg(PVFGPTLBC0),
    igb_getreg(PVFGPTLBC1),
    igb_getreg(PVFGPTLBC2),
    igb_getreg(PVFGPTLBC3),
    igb_getreg(PVFGPTLBC4),
    igb_getreg(PVFGPTLBC5),
    igb_getreg(PVFGPTLBC6),
    igb_getreg(PVFGPTLBC7),
    igb_getreg(PVFGORLBC0),
    igb_getreg(PVFGORLBC1),
    igb_getreg(PVFGORLBC2),
    igb_getreg(PVFGORLBC3),
    igb_getreg(PVFGORLBC4),
    igb_getreg(PVFGORLBC5),
    igb_getreg(PVFGORLBC6),
    igb_getreg(PVFGORLBC7),
    igb_getreg(PVFGOTLBC0),
    igb_getreg(PVFGOTLBC1),
    igb_getreg(PVFGOTLBC2),
    igb_getreg(PVFGOTLBC3),
    igb_getreg(PVFGOTLBC4),
    igb_getreg(PVFGOTLBC5),
    igb_getreg(PVFGOTLBC6),
    igb_getreg(PVFGOTLBC7),
    igb_getreg(RCTL),
    igb_getreg(MDIC),
    igb_getreg(FCRUC),
    igb_getreg(VET),
    igb_getreg(RDBAL0),
    igb_getreg(RDBAL1),
    igb_getreg(RDBAL2),
    igb_getreg(RDBAL3),
    igb_getreg(RDBAL4),
    igb_getreg(RDBAL5),
    igb_getreg(RDBAL6),
    igb_getreg(RDBAL7),
    igb_getreg(RDBAL8),
    igb_getreg(RDBAL9),
    igb_getreg(RDBAL10),
    igb_getreg(RDBAL11),
    igb_getreg(RDBAL12),
    igb_getreg(RDBAL13),
    igb_getreg(RDBAL14),
    igb_getreg(RDBAL15),
    igb_getreg(TDBAH0),
    igb_getreg(TDBAH1),
    igb_getreg(TDBAH2),
    igb_getreg(TDBAH3),
    igb_getreg(TDBAH4),
    igb_getreg(TDBAH5),
    igb_getreg(TDBAH6),
    igb_getreg(TDBAH7),
    igb_getreg(TDBAH8),
    igb_getreg(TDBAH9),
    igb_getreg(TDBAH10),
    igb_getreg(TDBAH11),
    igb_getreg(TDBAH12),
    igb_getreg(TDBAH13),
    igb_getreg(TDBAH14),
    igb_getreg(TDBAH15),
    igb_getreg(SCC),
    igb_getreg(COLC),
    igb_getreg(CEXTERR),
    igb_getreg(XOFFRXC),
    igb_getreg(IPAV),
    igb_getreg(GOTCL),
    igb_getreg(MGTPDC),
    igb_getreg(GCR),
    igb_getreg(POEMB),
    igb_getreg(MFVAL),
    igb_getreg(FUNCTAG),
    igb_getreg(GSCL_4),
    igb_getreg(GSCN_3),
    igb_getreg(MRQC),
    igb_getreg(FCT),
    igb_getreg(FLA),
    igb_getreg(FLOL),
    igb_getreg(RXDCTL0),
    igb_getreg(RXDCTL1),
    igb_getreg(RXDCTL2),
    igb_getreg(RXDCTL3),
    igb_getreg(RXDCTL4),
    igb_getreg(RXDCTL5),
    igb_getreg(RXDCTL6),
    igb_getreg(RXDCTL7),
    igb_getreg(RXDCTL8),
    igb_getreg(RXDCTL9),
    igb_getreg(RXDCTL10),
    igb_getreg(RXDCTL11),
    igb_getreg(RXDCTL12),
    igb_getreg(RXDCTL13),
    igb_getreg(RXDCTL14),
    igb_getreg(RXDCTL15),
    igb_getreg(RXSTMPL),
    igb_getreg(TXSTMPH),
    igb_getreg(TIMADJH),
    igb_getreg(FCRTL),
    igb_getreg(XONRXC),
    igb_getreg(TSCTFC),
    igb_getreg(RFCTL),
    igb_getreg(GSCN_1),
    igb_getreg(FCAL),
    igb_getreg(FLSWCNT),
    igb_getreg(GPIE),
    igb_getreg(TXPBS),
    igb_getreg(RLPML),

    [TOTH]    = igb_mac_read_clr8,
    [GOTCH]   = igb_mac_read_clr8,
    [PRC64]   = igb_mac_read_clr4,
    [PRC255]  = igb_mac_read_clr4,
    [PRC1023] = igb_mac_read_clr4,
    [PTC64]   = igb_mac_read_clr4,
    [PTC255]  = igb_mac_read_clr4,
    [PTC1023] = igb_mac_read_clr4,
    [GPRC]    = igb_mac_read_clr4,
    [TPT]     = igb_mac_read_clr4,
    [RUC]     = igb_mac_read_clr4,
    [BPRC]    = igb_mac_read_clr4,
    [MPTC]    = igb_mac_read_clr4,
    [IAC]     = igb_mac_read_clr4,
    [ICR]     = igb_mac_icr_read,
    [RDFH]    = IGB_LOW_BITS_READ(13),
    [RDFHS]   = IGB_LOW_BITS_READ(13),
    [RDFPC]   = IGB_LOW_BITS_READ(13),
    [TDFH]    = IGB_LOW_BITS_READ(13),
    [TDFHS]   = IGB_LOW_BITS_READ(13),
    [STATUS]  = igb_get_status,
    [TARC0]   = igb_get_tarc,
    [PBS]     = IGB_LOW_BITS_READ(6),
    [ICS]     = igb_mac_ics_read,
    /* 8.8.10: Reading the IMC register returns the value of the IMS register.
    */
    [IMC]     = igb_mac_ims_read,
    [AIT]     = IGB_LOW_BITS_READ(16),
    [TORH]    = igb_mac_read_clr8,
    [GORCH]   = igb_mac_read_clr8,
    [PRC127]  = igb_mac_read_clr4,
    [PRC511]  = igb_mac_read_clr4,
    [PRC1522] = igb_mac_read_clr4,
    [PTC127]  = igb_mac_read_clr4,
    [PTC511]  = igb_mac_read_clr4,
    [PTC1522] = igb_mac_read_clr4,
    [GPTC]    = igb_mac_read_clr4,
    [TPR]     = igb_mac_read_clr4,
    [ROC]     = igb_mac_read_clr4,
    [MPRC]    = igb_mac_read_clr4,
    [BPTC]    = igb_mac_read_clr4,
    [TSCTC]   = igb_mac_read_clr4,
    [RDFT]    = IGB_LOW_BITS_READ(13),
    [RDFTS]   = IGB_LOW_BITS_READ(13),
    [TDFPC]   = IGB_LOW_BITS_READ(13),
    [TDFT]    = IGB_LOW_BITS_READ(13),
    [TDFTS]   = IGB_LOW_BITS_READ(13),
    [CTRL]    = igb_get_ctrl,
    [TARC1]   = igb_get_tarc,
    [SWSM]    = igb_mac_swsm_read,
    [IMS]     = igb_mac_ims_read,

    /* E1000E specific: */
    [CRCERRS ... MPC]      = igb_mac_readreg,
    [IP6AT ... IP6AT + 3]  = igb_mac_readreg,
    [IP4AT ... IP4AT + 6]  = igb_mac_readreg,
    [RA ... RA + 31]       = igb_mac_readreg,
    [RA2 ... RA2 + 31]     = igb_mac_readreg,
    [WUPM ... WUPM + 31]   = igb_mac_readreg,
    [MTA ... MTA + 127]    = igb_mac_readreg,
    [VFTA ... VFTA + 127]  = igb_mac_readreg,
    [FFMT ... FFMT + 254]  = IGB_LOW_BITS_READ(4),
    [FFVT ... FFVT + 254]  = igb_mac_readreg,
    [MDEF ... MDEF + 7]    = igb_mac_readreg,
    [FFLT ... FFLT + 10]   = IGB_LOW_BITS_READ(11),
    [FTFT ... FTFT + 254]  = igb_mac_readreg,
    [PBM ... PBM + 10239]  = igb_mac_readreg,
    [RETA ... RETA + 31]   = igb_mac_readreg,
    [RSSRK ... RSSRK + 9]  = igb_mac_readreg,
    [MAVTV0 ... MAVTV3]    = igb_mac_readreg,
    [EITR0 ... EITR0 + IGB_MSIX_VEC_NUM - 1] = igb_mac_eitr_read,
    [PVTEICR0] = igb_mac_read_clr4,
    [PVTEICR1] = igb_mac_read_clr4,
    [PVTEICR2] = igb_mac_read_clr4,
    [PVTEICR3] = igb_mac_read_clr4,
    [PVTEICR4] = igb_mac_read_clr4,
    [PVTEICR5] = igb_mac_read_clr4,
    [PVTEICR6] = igb_mac_read_clr4,
    [PVTEICR7] = igb_mac_read_clr4,

    /* IGB specific: */
    [FWSM]       = igb_mac_readreg,
    [SW_FW_SYNC] = igb_mac_readreg,
    [HTCBDPC]    = igb_mac_read_clr4,
    [EICR]       = igb_mac_read_clr4,
    [EIMS]       = igb_mac_readreg,
    [EIAM]       = igb_mac_readreg,
    [IVAR0 ... IVAR0 + 7] = igb_mac_readreg,
    igb_getreg(IVAR_MISC),
    [P2VMAILBOX0 ... P2VMAILBOX0 + 7] = igb_mac_pfmailbox_read,
    [V2PMAILBOX0 ... V2PMAILBOX0 + 7] = igb_mac_vfmailbox_read,
    igb_getreg(MBVFICR),
    [VMBMEM0 ... VMBMEM0 + 127] = igb_mac_readreg,
    igb_getreg(MBVFIMR),
    igb_getreg(VFLRE),
    igb_getreg(VFRE),
    igb_getreg(VFTE),
    igb_getreg(QDE),
    igb_getreg(DTXSWC),
    igb_getreg(RPLOLR),
    [VLVF0 ... VLVF0 + 31] = igb_mac_readreg,
    [VMVIR0 ... VMVIR0 + 7] = igb_mac_readreg,
    [VMOLR0 ... VMOLR0 + 7] = igb_mac_readreg,
    [WVBR] = igb_mac_read_clr4,
    [RQDPC0 ... RQDPC0 + IGB_NUM_QUEUES - 1] = igb_mac_read_clr4,
    [VTIVAR ... VTIVAR + 7] = igb_mac_readreg,
    [VTIVAR_MISC ... VTIVAR_MISC + 7] = igb_mac_readreg,
};
enum { IGB_NREADOPS = ARRAY_SIZE(igb_macreg_readops) };

#define igb_putreg(x)    [x] = igb_mac_writereg
typedef void (*writeops)(IGBCore *, int, uint32_t);
static const writeops igb_macreg_writeops[] = {
    igb_putreg(PBA),
    igb_putreg(SWSM),
    igb_putreg(WUFC),
    igb_putreg(RDBAH0),
    igb_putreg(RDBAH1),
    igb_putreg(RDBAH2),
    igb_putreg(RDBAH3),
    igb_putreg(RDBAH4),
    igb_putreg(RDBAH5),
    igb_putreg(RDBAH6),
    igb_putreg(RDBAH7),
    igb_putreg(RDBAH8),
    igb_putreg(RDBAH9),
    igb_putreg(RDBAH10),
    igb_putreg(RDBAH11),
    igb_putreg(RDBAH12),
    igb_putreg(RDBAH13),
    igb_putreg(RDBAH14),
    igb_putreg(RDBAH15),
    igb_putreg(SRRCTL0),
    igb_putreg(SRRCTL1),
    igb_putreg(SRRCTL2),
    igb_putreg(SRRCTL3),
    igb_putreg(SRRCTL4),
    igb_putreg(SRRCTL5),
    igb_putreg(SRRCTL6),
    igb_putreg(SRRCTL7),
    igb_putreg(SRRCTL8),
    igb_putreg(SRRCTL9),
    igb_putreg(SRRCTL10),
    igb_putreg(SRRCTL11),
    igb_putreg(SRRCTL12),
    igb_putreg(SRRCTL13),
    igb_putreg(SRRCTL14),
    igb_putreg(SRRCTL15),
    igb_putreg(RXDCTL0),
    igb_putreg(RXDCTL1),
    igb_putreg(RXDCTL2),
    igb_putreg(RXDCTL3),
    igb_putreg(RXDCTL4),
    igb_putreg(RXDCTL5),
    igb_putreg(RXDCTL6),
    igb_putreg(RXDCTL7),
    igb_putreg(RXDCTL8),
    igb_putreg(RXDCTL9),
    igb_putreg(RXDCTL10),
    igb_putreg(RXDCTL11),
    igb_putreg(RXDCTL12),
    igb_putreg(RXDCTL13),
    igb_putreg(RXDCTL14),
    igb_putreg(RXDCTL15),
    igb_putreg(LEDCTL),
    igb_putreg(TCTL),
    igb_putreg(TCTL_EXT),
    igb_putreg(DTXCTL),
    igb_putreg(RXPBS),
    igb_putreg(RQDPC0),
    igb_putreg(FCAL),
    igb_putreg(FCRUC),
    igb_putreg(AIT),
    igb_putreg(TDFH),
    igb_putreg(TDFT),
    igb_putreg(TDFHS),
    igb_putreg(TDFTS),
    igb_putreg(TDFPC),
    igb_putreg(WUC),
    igb_putreg(WUS),
    igb_putreg(RDFH),
    igb_putreg(RDFT),
    igb_putreg(RDFHS),
    igb_putreg(RDFTS),
    igb_putreg(RDFPC),
    igb_putreg(IPAV),
    igb_putreg(TDBAH0),
    igb_putreg(TDBAH1),
    igb_putreg(TDBAH2),
    igb_putreg(TDBAH3),
    igb_putreg(TDBAH4),
    igb_putreg(TDBAH5),
    igb_putreg(TDBAH6),
    igb_putreg(TDBAH7),
    igb_putreg(TDBAH8),
    igb_putreg(TDBAH9),
    igb_putreg(TDBAH10),
    igb_putreg(TDBAH11),
    igb_putreg(TDBAH12),
    igb_putreg(TDBAH13),
    igb_putreg(TDBAH14),
    igb_putreg(TDBAH15),
    igb_putreg(TIMINCA),
    igb_putreg(IAM),
    igb_putreg(TARC0),
    igb_putreg(TARC1),
    igb_putreg(FLSWDATA),
    igb_putreg(POEMB),
    igb_putreg(PBS),
    igb_putreg(MFUTP01),
    igb_putreg(MFUTP23),
    igb_putreg(MANC),
    igb_putreg(MANC2H),
    igb_putreg(MFVAL),
    igb_putreg(EXTCNF_CTRL),
    igb_putreg(FACTPS),
    igb_putreg(FUNCTAG),
    igb_putreg(GSCL_1),
    igb_putreg(GSCL_2),
    igb_putreg(GSCL_3),
    igb_putreg(GSCL_4),
    igb_putreg(GSCN_0),
    igb_putreg(GSCN_1),
    igb_putreg(GSCN_2),
    igb_putreg(GSCN_3),
    igb_putreg(GCR2),
    igb_putreg(MRQC),
    igb_putreg(FLOP),
    igb_putreg(FLOL),
    igb_putreg(FLSWCTL),
    igb_putreg(FLSWCNT),
    igb_putreg(FLA),
    igb_putreg(TXDCTL0),
    igb_putreg(TXDCTL1),
    igb_putreg(TXDCTL2),
    igb_putreg(TXDCTL3),
    igb_putreg(TXDCTL4),
    igb_putreg(TXDCTL5),
    igb_putreg(TXDCTL6),
    igb_putreg(TXDCTL7),
    igb_putreg(TXDCTL8),
    igb_putreg(TXDCTL9),
    igb_putreg(TXDCTL10),
    igb_putreg(TXDCTL11),
    igb_putreg(TXDCTL12),
    igb_putreg(TXDCTL13),
    igb_putreg(TXDCTL14),
    igb_putreg(TXDCTL15),
    igb_putreg(TXCTL0),
    igb_putreg(TXCTL1),
    igb_putreg(TXCTL2),
    igb_putreg(TXCTL3),
    igb_putreg(TXCTL4),
    igb_putreg(TXCTL5),
    igb_putreg(TXCTL6),
    igb_putreg(TXCTL7),
    igb_putreg(TXCTL8),
    igb_putreg(TXCTL9),
    igb_putreg(TXCTL10),
    igb_putreg(TXCTL11),
    igb_putreg(TXCTL12),
    igb_putreg(TXCTL13),
    igb_putreg(TXCTL14),
    igb_putreg(TXCTL15),
    igb_putreg(TIPG),
    igb_putreg(RXSTMPH),
    igb_putreg(RXSTMPL),
    igb_putreg(RXSATRL),
    igb_putreg(RXSATRH),
    igb_putreg(TXSTMPL),
    igb_putreg(TXSTMPH),
    igb_putreg(SYSTIML),
    igb_putreg(SYSTIMH),
    igb_putreg(TIMADJL),
    igb_putreg(TIMADJH),
    igb_putreg(RXUDP),
    igb_putreg(RXCFGL),
    igb_putreg(TSYNCRXCTL),
    igb_putreg(TSYNCTXCTL),
    igb_putreg(EXTCNF_SIZE),
    igb_putreg(EEMNGCTL),
    igb_putreg(GPIE),
    igb_putreg(TXPBS),
    igb_putreg(RLPML),
    igb_putreg(VET),

    [TDH0]     = igb_set_16bit,
    [TDH1]     = igb_set_16bit,
    [TDH2]     = igb_set_16bit,
    [TDH3]     = igb_set_16bit,
    [TDH4]     = igb_set_16bit,
    [TDH5]     = igb_set_16bit,
    [TDH6]     = igb_set_16bit,
    [TDH7]     = igb_set_16bit,
    [TDH8]     = igb_set_16bit,
    [TDH9]     = igb_set_16bit,
    [TDH10]    = igb_set_16bit,
    [TDH11]    = igb_set_16bit,
    [TDH12]    = igb_set_16bit,
    [TDH13]    = igb_set_16bit,
    [TDH14]    = igb_set_16bit,
    [TDH15]    = igb_set_16bit,
    [TDT0]     = igb_set_tdt,
    [TDT1]     = igb_set_tdt,
    [TDT2]     = igb_set_tdt,
    [TDT3]     = igb_set_tdt,
    [TDT4]     = igb_set_tdt,
    [TDT5]     = igb_set_tdt,
    [TDT6]     = igb_set_tdt,
    [TDT7]     = igb_set_tdt,
    [TDT8]     = igb_set_tdt,
    [TDT9]     = igb_set_tdt,
    [TDT10]    = igb_set_tdt,
    [TDT11]    = igb_set_tdt,
    [TDT12]    = igb_set_tdt,
    [TDT13]    = igb_set_tdt,
    [TDT14]    = igb_set_tdt,
    [TDT15]    = igb_set_tdt,
    [MDIC]     = igb_set_mdic,
    [ICS]      = igb_set_ics,
    [RDH0]     = igb_set_16bit,
    [RDH1]     = igb_set_16bit,
    [RDH2]     = igb_set_16bit,
    [RDH3]     = igb_set_16bit,
    [RDH4]     = igb_set_16bit,
    [RDH5]     = igb_set_16bit,
    [RDH6]     = igb_set_16bit,
    [RDH7]     = igb_set_16bit,
    [RDH8]     = igb_set_16bit,
    [RDH9]     = igb_set_16bit,
    [RDH10]    = igb_set_16bit,
    [RDH11]    = igb_set_16bit,
    [RDH12]    = igb_set_16bit,
    [RDH13]    = igb_set_16bit,
    [RDH14]    = igb_set_16bit,
    [RDH15]    = igb_set_16bit,
    [RDT0]     = igb_set_rdt,
    [RDT1]     = igb_set_rdt,
    [RDT2]     = igb_set_rdt,
    [RDT3]     = igb_set_rdt,
    [RDT4]     = igb_set_rdt,
    [RDT5]     = igb_set_rdt,
    [RDT6]     = igb_set_rdt,
    [RDT7]     = igb_set_rdt,
    [RDT8]     = igb_set_rdt,
    [RDT9]     = igb_set_rdt,
    [RDT10]    = igb_set_rdt,
    [RDT11]    = igb_set_rdt,
    [RDT12]    = igb_set_rdt,
    [RDT13]    = igb_set_rdt,
    [RDT14]    = igb_set_rdt,
    [RDT15]    = igb_set_rdt,
    [IMC]      = igb_set_imc,
    [IMS]      = igb_set_ims,
    [ICR]      = igb_set_icr,
    [EECD]     = igb_set_eecd,
    [RCTL]     = igb_set_rx_control,
    [CTRL]     = igb_set_ctrl,
    [EERD]     = igb_set_eerd,
    [GCR]      = igb_set_gcr,
    [RXCSUM]   = igb_set_rxcsum,
    [TDLEN0]   = igb_set_dlen,
    [TDLEN1]   = igb_set_dlen,
    [TDLEN2]   = igb_set_dlen,
    [TDLEN3]   = igb_set_dlen,
    [TDLEN4]   = igb_set_dlen,
    [TDLEN5]   = igb_set_dlen,
    [TDLEN6]   = igb_set_dlen,
    [TDLEN7]   = igb_set_dlen,
    [TDLEN8]   = igb_set_dlen,
    [TDLEN9]   = igb_set_dlen,
    [TDLEN10]  = igb_set_dlen,
    [TDLEN11]  = igb_set_dlen,
    [TDLEN12]  = igb_set_dlen,
    [TDLEN13]  = igb_set_dlen,
    [TDLEN14]  = igb_set_dlen,
    [TDLEN15]  = igb_set_dlen,
    [RDLEN0]   = igb_set_dlen,
    [RDLEN1]   = igb_set_dlen,
    [RDLEN2]   = igb_set_dlen,
    [RDLEN3]   = igb_set_dlen,
    [RDLEN4]   = igb_set_dlen,
    [RDLEN5]   = igb_set_dlen,
    [RDLEN6]   = igb_set_dlen,
    [RDLEN7]   = igb_set_dlen,
    [RDLEN8]   = igb_set_dlen,
    [RDLEN9]   = igb_set_dlen,
    [RDLEN10]  = igb_set_dlen,
    [RDLEN11]  = igb_set_dlen,
    [RDLEN12]  = igb_set_dlen,
    [RDLEN13]  = igb_set_dlen,
    [RDLEN14]  = igb_set_dlen,
    [RDLEN15]  = igb_set_dlen,
    [TDBAL0]   = igb_set_dbal,
    [TDBAL1]   = igb_set_dbal,
    [TDBAL2]   = igb_set_dbal,
    [TDBAL3]   = igb_set_dbal,
    [TDBAL4]   = igb_set_dbal,
    [TDBAL5]   = igb_set_dbal,
    [TDBAL6]   = igb_set_dbal,
    [TDBAL7]   = igb_set_dbal,
    [TDBAL8]   = igb_set_dbal,
    [TDBAL9]   = igb_set_dbal,
    [TDBAL10]  = igb_set_dbal,
    [TDBAL11]  = igb_set_dbal,
    [TDBAL12]  = igb_set_dbal,
    [TDBAL13]  = igb_set_dbal,
    [TDBAL14]  = igb_set_dbal,
    [TDBAL15]  = igb_set_dbal,
    [RDBAL0]   = igb_set_dbal,
    [RDBAL1]   = igb_set_dbal,
    [RDBAL2]   = igb_set_dbal,
    [RDBAL3]   = igb_set_dbal,
    [RDBAL4]   = igb_set_dbal,
    [RDBAL5]   = igb_set_dbal,
    [RDBAL6]   = igb_set_dbal,
    [RDBAL7]   = igb_set_dbal,
    [RDBAL8]   = igb_set_dbal,
    [RDBAL9]   = igb_set_dbal,
    [RDBAL10]  = igb_set_dbal,
    [RDBAL11]  = igb_set_dbal,
    [RDBAL12]  = igb_set_dbal,
    [RDBAL13]  = igb_set_dbal,
    [RDBAL14]  = igb_set_dbal,
    [RDBAL15]  = igb_set_dbal,
    [STATUS]   = igb_set_status,
    [PBACLR]   = igb_set_pbaclr,
    [CTRL_EXT] = igb_set_ctrlext,
    [FCAH]     = igb_set_16bit,
    [FCT]      = igb_set_16bit,
    [FCTTV]    = igb_set_16bit,
    [FCRTV]    = igb_set_16bit,
    [FCRTH]    = igb_set_fcrth,
    [FCRTL]    = igb_set_fcrtl,
    [FLASHT]   = igb_set_16bit,
    [EEWR]     = igb_set_eewr,
    [CTRL_DUP] = igb_set_ctrl,
    [RFCTL]    = igb_set_rfctl,

    [IP6AT ... IP6AT + 3]    = igb_mac_writereg,
    [IP4AT ... IP4AT + 6]    = igb_mac_writereg,
    [RA]                     = igb_mac_writereg,
    [RA + 1]                 = igb_mac_set_macaddr,
    [RA + 2 ... RA + 31]     = igb_mac_writereg,
    [RA2 ... RA2 + 31]       = igb_mac_writereg,
    [WUPM ... WUPM + 31]     = igb_mac_writereg,
    [MTA ... MTA + 127]      = igb_mac_writereg,
    [VFTA ... VFTA + 127]    = igb_mac_writereg,
    [FFMT ... FFMT + 254]    = igb_mac_writereg,
    [FFVT ... FFVT + 254]    = igb_mac_writereg,
    [PBM ... PBM + 10239]    = igb_mac_writereg,
    [MDEF ... MDEF + 7]      = igb_mac_writereg,
    [FFLT ... FFLT + 10]     = igb_mac_writereg,
    [FTFT ... FTFT + 254]    = igb_mac_writereg,
    [RETA ... RETA + 31]     = igb_mac_writereg,
    [RSSRK ... RSSRK + 9]    = igb_mac_writereg,
    [MAVTV0 ... MAVTV3]      = igb_mac_writereg,
    [EITR0 ... EITR0 + IGB_MSIX_VEC_NUM - 1] = igb_set_eitr,

    /* IGB specific: */
    [FWSM]     = igb_mac_writereg,
    [SW_FW_SYNC] = igb_mac_writereg,
    [EICR] = igb_set_eicr,
    [EICS] = igb_set_eics,
    [EIAC] = igb_set_eiac,
    [EIAM] = igb_set_eiam,
    [EIMC] = igb_set_eimc,
    [EIMS] = igb_set_eims,
    [IVAR0 ... IVAR0 + 7] = igb_mac_writereg,
    igb_putreg(IVAR_MISC),
    [P2VMAILBOX0 ... P2VMAILBOX0 + 7] = igb_set_pfmailbox,
    [V2PMAILBOX0 ... V2PMAILBOX0 + 7] = igb_set_vfmailbox,
    [MBVFICR] = igb_set_mbvficr,
    [VMBMEM0 ... VMBMEM0 + 127] = igb_mac_writereg,
    igb_putreg(MBVFIMR),
    [VFLRE] = igb_set_vflre,
    igb_putreg(VFRE),
    igb_putreg(VFTE),
    igb_putreg(QDE),
    igb_putreg(DTXSWC),
    igb_putreg(RPLOLR),
    [VLVF0 ... VLVF0 + 31] = igb_mac_writereg,
    [VMVIR0 ... VMVIR0 + 7] = igb_mac_writereg,
    [VMOLR0 ... VMOLR0 + 7] = igb_mac_writereg,
    [UTA ... UTA + 127] = igb_mac_writereg,
    [PVTCTRL0] = igb_set_vtctrl,
    [PVTCTRL1] = igb_set_vtctrl,
    [PVTCTRL2] = igb_set_vtctrl,
    [PVTCTRL3] = igb_set_vtctrl,
    [PVTCTRL4] = igb_set_vtctrl,
    [PVTCTRL5] = igb_set_vtctrl,
    [PVTCTRL6] = igb_set_vtctrl,
    [PVTCTRL7] = igb_set_vtctrl,
    [PVTEICS0] = igb_set_vteics,
    [PVTEICS1] = igb_set_vteics,
    [PVTEICS2] = igb_set_vteics,
    [PVTEICS3] = igb_set_vteics,
    [PVTEICS4] = igb_set_vteics,
    [PVTEICS5] = igb_set_vteics,
    [PVTEICS6] = igb_set_vteics,
    [PVTEICS7] = igb_set_vteics,
    [PVTEIMS0] = igb_set_vteims,
    [PVTEIMS1] = igb_set_vteims,
    [PVTEIMS2] = igb_set_vteims,
    [PVTEIMS3] = igb_set_vteims,
    [PVTEIMS4] = igb_set_vteims,
    [PVTEIMS5] = igb_set_vteims,
    [PVTEIMS6] = igb_set_vteims,
    [PVTEIMS7] = igb_set_vteims,
    [PVTEIMC0] = igb_set_vteimc,
    [PVTEIMC1] = igb_set_vteimc,
    [PVTEIMC2] = igb_set_vteimc,
    [PVTEIMC3] = igb_set_vteimc,
    [PVTEIMC4] = igb_set_vteimc,
    [PVTEIMC5] = igb_set_vteimc,
    [PVTEIMC6] = igb_set_vteimc,
    [PVTEIMC7] = igb_set_vteimc,
    [PVTEIAC0] = igb_set_vteiac,
    [PVTEIAC1] = igb_set_vteiac,
    [PVTEIAC2] = igb_set_vteiac,
    [PVTEIAC3] = igb_set_vteiac,
    [PVTEIAC4] = igb_set_vteiac,
    [PVTEIAC5] = igb_set_vteiac,
    [PVTEIAC6] = igb_set_vteiac,
    [PVTEIAC7] = igb_set_vteiac,
    [PVTEIAM0] = igb_set_vteiam,
    [PVTEIAM1] = igb_set_vteiam,
    [PVTEIAM2] = igb_set_vteiam,
    [PVTEIAM3] = igb_set_vteiam,
    [PVTEIAM4] = igb_set_vteiam,
    [PVTEIAM5] = igb_set_vteiam,
    [PVTEIAM6] = igb_set_vteiam,
    [PVTEIAM7] = igb_set_vteiam,
    [PVTEICR0] = igb_set_vteicr,
    [PVTEICR1] = igb_set_vteicr,
    [PVTEICR2] = igb_set_vteicr,
    [PVTEICR3] = igb_set_vteicr,
    [PVTEICR4] = igb_set_vteicr,
    [PVTEICR5] = igb_set_vteicr,
    [PVTEICR6] = igb_set_vteicr,
    [PVTEICR7] = igb_set_vteicr,
    [VTIVAR ... VTIVAR + 7] = igb_set_vtivar,
    [VTIVAR_MISC ... VTIVAR_MISC + 7] = igb_mac_writereg
};
enum { IGB_NWRITEOPS = ARRAY_SIZE(igb_macreg_writeops) };

enum { MAC_ACCESS_PARTIAL = 1 };

/* The array below combines alias offsets of the index values for the
 * MAC registers that have aliases, with the indication of not fully
 * implemented registers (lowest bit). This combination is possible
 * because all of the offsets are even. */
static const uint16_t mac_reg_access[E1000E_MAC_SIZE] = {
    /* Alias index offsets */
    [FCRTL_A] = 0x07fe, [FCRTH_A] = 0x0802,
    [RDFH_A]  = 0xe904, [RDFT_A]  = 0xe904,
    [TDFH_A]  = 0xed00, [TDFT_A]  = 0xed00,
    [RA_A ... RA_A + 31]      = 0x14f0,
    [VFTA_A ... VFTA_A + 127] = 0x1400,

    [RDBAL0_A] = 0x2600,
    [RDBAH0_A] = 0x2600,
    [RDLEN0_A] = 0x2600,
    [SRRCTL0_A] = 0x2600,
    [RDH0_A] = 0x2600,
    [RDT0_A] = 0x2600,
    [RXDCTL0_A] = 0x2600,
    [RXCTL0_A] = 0x2600,
    [RQDPC0_A] = 0x2600,
    [RDBAL1_A] = 0x25D0,
    [RDBAL2_A] = 0x25A0,
    [RDBAL3_A] = 0x2570,
    [RDBAH1_A] = 0x25D0,
    [RDBAH2_A] = 0x25A0,
    [RDBAH3_A] = 0x2570,
    [RDLEN1_A] = 0x25D0,
    [RDLEN2_A] = 0x25A0,
    [RDLEN3_A] = 0x2570,
    [SRRCTL1_A] = 0x25D0,
    [SRRCTL2_A] = 0x25A0,
    [SRRCTL3_A] = 0x2570,
    [RDH1_A] = 0x25D0,
    [RDH2_A] = 0x25A0,
    [RDH3_A] = 0x2570,
    [RDT1_A] = 0x25D0,
    [RDT2_A] = 0x25A0,
    [RDT3_A] = 0x2570,
    [RXDCTL1_A] = 0x25D0,
    [RXDCTL2_A] = 0x25A0,
    [RXDCTL3_A] = 0x2570,
    [RXCTL1_A] = 0x25D0,
    [RXCTL2_A] = 0x25A0,
    [RXCTL3_A] = 0x2570,
    [RQDPC1_A] = 0x25D0,
    [RQDPC2_A] = 0x25A0,
    [RQDPC3_A] = 0x2570,
    [TDBAL0_A] = 0x2A00,
    [TDBAH0_A] = 0x2A00,
    [TDLEN0_A] = 0x2A00,
    [TDH0_A] = 0x2A00,
    [TDT0_A] = 0x2A00,
    [TXCTL0_A] = 0x2A00,
    [TDWBAL0_A] = 0x2A00,
    [TDWBAH0_A] = 0x2A00,
    [TDBAL1_A] = 0x29D0,
    [TDBAL2_A] = 0x29A0,
    [TDBAL3_A] = 0x2970,
    [TDBAH1_A] = 0x29D0,
    [TDBAH2_A] = 0x29A0,
    [TDBAH3_A] = 0x2970,
    [TDLEN1_A] = 0x29D0,
    [TDLEN2_A] = 0x29A0,
    [TDLEN3_A] = 0x2970,
    [TDH1_A] = 0x29D0,
    [TDH2_A] = 0x29A0,
    [TDH3_A] = 0x2970,
    [TDT1_A] = 0x29D0,
    [TDT2_A] = 0x29A0,
    [TDT3_A] = 0x2970,
    [TXDCTL0_A] = 0x2A00,
    [TXDCTL1_A] = 0x29D0,
    [TXDCTL2_A] = 0x29A0,
    [TXDCTL3_A] = 0x2970,
    [TXCTL1_A] = 0x29D0,
    [TXCTL2_A] = 0x29A0,
    [TXCTL3_A] = 0x29D0,
    [TDWBAL1_A] = 0x29D0,
    [TDWBAL2_A] = 0x29A0,
    [TDWBAL3_A] = 0x2970,
    [TDWBAH1_A] = 0x29D0,
    [TDWBAH2_A] = 0x29A0,
    [TDWBAH3_A] = 0x2970,

    /* Access options */
    [RDFH]  = MAC_ACCESS_PARTIAL,    [RDFT]  = MAC_ACCESS_PARTIAL,
    [RDFHS] = MAC_ACCESS_PARTIAL,    [RDFTS] = MAC_ACCESS_PARTIAL,
    [RDFPC] = MAC_ACCESS_PARTIAL,
    [TDFH]  = MAC_ACCESS_PARTIAL,    [TDFT]  = MAC_ACCESS_PARTIAL,
    [TDFHS] = MAC_ACCESS_PARTIAL,    [TDFTS] = MAC_ACCESS_PARTIAL,
    [TDFPC] = MAC_ACCESS_PARTIAL,    [EECD]  = MAC_ACCESS_PARTIAL,
    [PBM]   = MAC_ACCESS_PARTIAL,    [FLA]   = MAC_ACCESS_PARTIAL,
    [FCAL]  = MAC_ACCESS_PARTIAL,    [FCAH]  = MAC_ACCESS_PARTIAL,
    [FCT]   = MAC_ACCESS_PARTIAL,    [FCTTV] = MAC_ACCESS_PARTIAL,
    [FCRTV] = MAC_ACCESS_PARTIAL,    [FCRTL] = MAC_ACCESS_PARTIAL,
    [FCRTH] = MAC_ACCESS_PARTIAL,
    [MAVTV0 ... MAVTV3] = MAC_ACCESS_PARTIAL
};

void igb_core_write(IGBCore *core, hwaddr addr, uint64_t val, unsigned size)
{
    uint16_t index = igb_get_reg_index_with_offset(mac_reg_access, addr);

    if (index < IGB_NWRITEOPS && igb_macreg_writeops[index]) {
        if (mac_reg_access[index] & MAC_ACCESS_PARTIAL) {
            trace_e1000e_wrn_regs_write_trivial(index << 2);
        }
        trace_e1000e_core_write(index << 2, size, val);
        igb_macreg_writeops[index](core, index, val);
    } else if (index < IGB_NREADOPS && igb_macreg_readops[index]) {
        trace_e1000e_wrn_regs_write_ro(index << 2, size, val);
    } else {
        trace_e1000e_wrn_regs_write_unknown(index << 2, size, val);
    }
}

uint64_t igb_core_read(IGBCore *core, hwaddr addr, unsigned size)
{
    uint64_t val;
    uint16_t index = igb_get_reg_index_with_offset(mac_reg_access, addr);

    if (index < IGB_NREADOPS && igb_macreg_readops[index]) {
        if (mac_reg_access[index] & MAC_ACCESS_PARTIAL) {
            trace_e1000e_wrn_regs_read_trivial(index << 2);
        }
        val = igb_macreg_readops[index](core, index);
        trace_e1000e_core_read(index << 2, size, val);
        return val;
    } else {
        trace_e1000e_wrn_regs_read_unknown(index << 2, size);
    }
    return 0;
}

static inline void
igb_autoneg_pause(IGBCore *core)
{
    timer_del(core->autoneg_timer);
}

static void
igb_autoneg_resume(IGBCore *core)
{
    if (igb_have_autoneg(core) &&
        !(core->phy[MII_BMSR] & MII_BMSR_AN_COMP)) {
        qemu_get_queue(core->owner_nic)->link_down = false;
        timer_mod(core->autoneg_timer,
                  qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 500);
    }
}

static void
igb_vm_state_change(void *opaque, bool running, RunState state)
{
    IGBCore *core = opaque;

    if (running) {
        trace_e1000e_vm_state_running();
        igb_intrmgr_resume(core);
        igb_autoneg_resume(core);
    } else {
        trace_e1000e_vm_state_stopped();
        igb_autoneg_pause(core);
        igb_intrmgr_pause(core);
    }
}

void igb_core_pci_realize(IGBCore     *core,
                          const uint16_t *eeprom_templ,
                          uint32_t        eeprom_size,
                          const uint8_t  *macaddr)
{
    int i;

    core->autoneg_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                       igb_autoneg_timer, core);

    igb_intrmgr_pci_realize(core);

    core->vmstate = qemu_add_vm_change_state_handler(igb_vm_state_change, core);

    for (i = 0; i < IGB_NUM_QUEUES; i++) {
        net_tx_pkt_init(&core->tx[i].tx_pkt, core->owner,
                        E1000E_MAX_TX_FRAGS, false);
    }

    net_rx_pkt_init(&core->rx_pkt, false);

    e1000x_core_prepare_eeprom(core->eeprom,
                               eeprom_templ,
                               eeprom_size,
                               PCI_DEVICE_GET_CLASS(core->owner)->device_id,
                               macaddr);
    igb_update_rx_offloads(core);
}

void igb_core_pci_uninit(IGBCore *core)
{
    int i;

    timer_del(core->autoneg_timer);
    timer_free(core->autoneg_timer);

    igb_intrmgr_pci_unint(core);

    qemu_del_vm_change_state_handler(core->vmstate);

    for (i = 0; i < IGB_NUM_QUEUES; i++) {
        net_tx_pkt_reset(core->tx[i].tx_pkt);
        net_tx_pkt_uninit(core->tx[i].tx_pkt);
    }

    net_rx_pkt_uninit(core->rx_pkt);
}

static const uint16_t
igb_phy_reg_init[E1000E_PHY_PAGE_SIZE] = {
    [MII_BMCR] = MII_BMCR_SPEED1000 |
                 MII_BMCR_FD        |
                 MII_BMCR_AUTOEN,

    [MII_BMSR] = MII_BMSR_EXTCAP    |
                 MII_BMSR_LINK_ST   |
                 MII_BMSR_AUTONEG   |
                 MII_BMSR_MFPS      |
                 MII_BMSR_EXTSTAT   |
                 MII_BMSR_10T_HD    |
                 MII_BMSR_10T_FD    |
                 MII_BMSR_100TX_HD  |
                 MII_BMSR_100TX_FD,

    [MII_PHYID1]            = IGP03E1000_E_PHY_ID >> 16,
    [MII_PHYID2]            = (IGP03E1000_E_PHY_ID & 0xffff) | 1,
    [MII_ANAR]              = MII_ANAR_CSMACD | MII_ANAR_10 |
                              MII_ANAR_10FD | MII_ANAR_TX |
                              MII_ANAR_TXFD | MII_ANAR_PAUSE |
                              MII_ANAR_PAUSE_ASYM,
    [MII_ANLPAR]            = MII_ANLPAR_10 | MII_ANLPAR_10FD |
                              MII_ANLPAR_TX | MII_ANLPAR_TXFD |
                              MII_ANLPAR_T4 | MII_ANLPAR_PAUSE,
    [MII_ANER]              = MII_ANER_NP,
    [MII_ANNP]              = 0x1 | MII_ANNP_MP,
    [MII_CTRL1000]          = MII_CTRL1000_HALF | MII_CTRL1000_FULL |
                              MII_CTRL1000_PORT | MII_CTRL1000_MASTER,
    [MII_STAT1000]          = MII_STAT1000_HALF | MII_STAT1000_FULL |
                              MII_STAT1000_ROK | MII_STAT1000_LOK,
    [MII_EXTSTAT]           = MII_EXTSTAT_1000T_HD | MII_EXTSTAT_1000T_FD,
};

static const uint32_t igb_mac_reg_init[] = {
    [PBA]           = 0x00140014,
    [LEDCTL]        = BIT(1) | BIT(8) | BIT(9) | BIT(15) | BIT(17) | BIT(18),
    [EXTCNF_CTRL]   = BIT(3),
    [EEMNGCTL]      = E1000_EEPROM_CFG_DONE | E1000_EEPROM_CFG_DONE_PORT_1 |
                      BIT(31),
    [FLASHT]        = 0x2,
    [FLSWCTL]       = BIT(30) | BIT(31),
    [FLOL]          = BIT(0),
    [RXDCTL0]       = BIT(25) | BIT(16),
    [RXDCTL1]       = BIT(25) | BIT(16),
    [RXDCTL2]       = BIT(25) | BIT(16),
    [RXDCTL3]       = BIT(25) | BIT(16),
    [RXDCTL4]       = BIT(25) | BIT(16),
    [RXDCTL5]       = BIT(25) | BIT(16),
    [RXDCTL6]       = BIT(25) | BIT(16),
    [RXDCTL7]       = BIT(25) | BIT(16),
    [RXDCTL8]       = BIT(25) | BIT(16),
    [RXDCTL9]       = BIT(25) | BIT(16),
    [RXDCTL10]      = BIT(25) | BIT(16),
    [RXDCTL11]      = BIT(25) | BIT(16),
    [RXDCTL12]      = BIT(25) | BIT(16),
    [RXDCTL13]      = BIT(25) | BIT(16),
    [RXDCTL14]      = BIT(25) | BIT(16),
    [RXDCTL15]      = BIT(25) | BIT(16),
    [TIPG]          = 0x8 | (0x4 << 10) | (0x6 << 20),
    [RXCFGL]        = 0x88F7,
    [RXUDP]         = 0x319,
    [CTRL]          = E1000_CTRL_FD | E1000_CTRL_LRST | E1000_CTRL_SPD_1000 |
                      E1000_CTRL_ADVD3WUC,
    [STATUS]        = E1000_STATUS_PHYRA | E1000_STATUS_GIO_MASTER_ENABLE,
    [TARC0]         = 0x3 | E1000_TARC_ENABLE,
    [TARC1]         = 0x3 | E1000_TARC_ENABLE,
    [EECD]          = E1000_EECD_AUTO_RD | E1000_EECD_PRES,
    [EERD]          = E1000_EERW_DONE,
    [EEWR]          = E1000_EERW_DONE,
    [GCR]           = E1000_L0S_ADJUST |
                      E1000_L1_ENTRY_LATENCY_MSB |
                      E1000_L1_ENTRY_LATENCY_LSB,
    [TDFH]          = 0x600,
    [TDFT]          = 0x600,
    [TDFHS]         = 0x600,
    [TDFTS]         = 0x600,
    [POEMB]         = 0x30D,
    [PBS]           = 0x028,
    [MANC]          = E1000_MANC_DIS_IP_CHK_ARP,
    [FACTPS]        = E1000_FACTPS_LAN0_ON | 0x20000000,
    [SWSM]          = 0,
    [RXCSUM]        = E1000_RXCSUM_IPOFLD | E1000_RXCSUM_TUOFLD,
    [TXPBS]         = 0x28,
    [RXPBS]         = 0x40,
    [TCTL]          = (0x1 << 3) | (0xF << 4) | (0x40 << 12) | (0x1 << 26) | (0xA << 28),
    [TCTL_EXT]      = 0x40 | (0x42 << 10),
    [DTXCTL]        = (0x1 << 2) | (0x1 << 6),
    [VET]           = 0x81008100,

    [V2PMAILBOX0 ... V2PMAILBOX0 + 7] = BIT(6),
    [MBVFIMR]       = 0xFF,
    [VFRE]          = 0xFF,
    [VFTE]          = 0xFF,
    [VMOLR0 ... VMOLR0 + 7] = 0x80002600,
    [RPLOLR]        = 0x80000000,
    [RLPML]         = 0x2600,
    [TXCTL0]       = BIT(13) | BIT(9),
    [TXCTL1]       = BIT(13) | BIT(9),
    [TXCTL2]       = BIT(13) | BIT(9),
    [TXCTL3]       = BIT(13) | BIT(9),
    [TXCTL4]       = BIT(13) | BIT(9),
    [TXCTL5]       = BIT(13) | BIT(9),
    [TXCTL6]       = BIT(13) | BIT(9),
    [TXCTL7]       = BIT(13) | BIT(9),
    [TXCTL8]       = BIT(13) | BIT(9),
    [TXCTL9]       = BIT(13) | BIT(9),
    [TXCTL10]      = BIT(13) | BIT(9),
    [TXCTL11]      = BIT(13) | BIT(9),
    [TXCTL12]      = BIT(13) | BIT(9),
    [TXCTL13]      = BIT(13) | BIT(9),
    [TXCTL14]      = BIT(13) | BIT(9),
    [TXCTL15]      = BIT(13) | BIT(9),
};

void igb_core_reset(IGBCore *core)
{
    struct IGBTx *tx;
    int i;

    timer_del(core->autoneg_timer);

    igb_intrmgr_reset(core);

    memset(core->phy, 0, sizeof core->phy);
    memmove(core->phy, igb_phy_reg_init, sizeof igb_phy_reg_init);
    memset(core->mac, 0, sizeof core->mac);
    memmove(core->mac, igb_mac_reg_init, sizeof igb_mac_reg_init);

    core->rxbuf_min_shift = 1 + E1000_RING_DESC_LEN_SHIFT;

    if (qemu_get_queue(core->owner_nic)->link_down) {
        igb_link_down(core);
    }

    e1000x_reset_mac_addr(core->owner_nic, core->mac, core->permanent_mac);

    for (i = 0; i < ARRAY_SIZE(core->tx); i++) {
        tx = &core->tx[i];
        net_tx_pkt_reset(tx->tx_pkt);
        tx->vlan = 0;
        tx->mss = 0;
        tx->tse = false;
        tx->ixsm = false;
        tx->txsm = false;
        tx->first = true;
        tx->skip_cp = false;
    }
}

void igb_core_pre_save(IGBCore *core)
{
    int i;
    NetClientState *nc = qemu_get_queue(core->owner_nic);

    /*
    * If link is down and auto-negotiation is supported and ongoing,
    * complete auto-negotiation immediately. This allows us to look
    * at MII_BMSR_AN_COMP to infer link status on load.
    */
    if (nc->link_down && igb_have_autoneg(core)) {
        core->phy[MII_BMSR] |= MII_BMSR_AN_COMP;
        igb_update_flowctl_status(core);
    }

    for (i = 0; i < ARRAY_SIZE(core->tx); i++) {
        if (net_tx_pkt_has_fragments(core->tx[i].tx_pkt)) {
            core->tx[i].skip_cp = true;
        }
    }
}

int igb_core_post_load(IGBCore *core)
{
    NetClientState *nc = qemu_get_queue(core->owner_nic);

    /* nc.link_down can't be migrated, so infer link_down according
     * to link status bit in core.mac[STATUS].
     */
    nc->link_down = (core->mac[STATUS] & E1000_STATUS_LU) == 0;

    return 0;
}
