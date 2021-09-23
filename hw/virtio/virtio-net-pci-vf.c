#include "qemu/osdep.h"

#include "hw/qdev-properties.h"
#include "hw/virtio/virtio-net.h"
#include "virtio-pci.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "qom/object.h"

typedef struct VirtIONetPCIVF VirtIONetPCIVF;

/*
 * virtio-net-pci: This extends VirtioPCIProxy.
 */
#define TYPE_VIRTIO_NET_PCI_VF "virtio-net-pci-vf-base"
DECLARE_INSTANCE_CHECKER(VirtIONetPCIVF, VIRTIO_NET_PCI_VF,
                         TYPE_VIRTIO_NET_PCI_VF)

struct VirtIONetPCIVF {
    VirtIOPCIProxy parent_obj;
    VirtIONet vdev;
};

static Property virtio_net_properties[] = {
    DEFINE_PROP_BIT("ioeventfd", VirtIOPCIProxy, flags,
                    VIRTIO_PCI_FLAG_USE_IOEVENTFD_BIT, true),
    DEFINE_PROP_UINT32("vectors", VirtIOPCIProxy, nvectors,
                       DEV_NVECTORS_UNSPECIFIED),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_net_pci_vf_realize(VirtIOPCIProxy *vpci_dev, Error **errp)
{
   DeviceState *qdev = DEVICE(vpci_dev);
   VirtIONetPCIVF *dev = VIRTIO_NET_PCI_VF(vpci_dev);
   DeviceState *vdev = DEVICE(&dev->vdev);
   VirtIONet *net = VIRTIO_NET(vdev);

   if (vpci_dev->nvectors == DEV_NVECTORS_UNSPECIFIED) {
       vpci_dev->nvectors = 2 * MAX(net->nic_conf.peers.queues, 1)
           + 1 /* Config interrupt */
           + 1 /* Control vq */;
   }

   virtio_net_set_netclient_name(&dev->vdev, qdev->id,
                                 object_get_typename(OBJECT(qdev)));
   qdev_realize(vdev, BUS(&vpci_dev->bus), errp);
}

static void virtio_net_pci_vf_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);
    VirtioPCIClass *vpciklass = VIRTIO_PCI_CLASS(klass);

    k->vendor_id = PCI_VENDOR_ID_REDHAT_QUMRANET;
    k->device_id = PCI_DEVICE_ID_VIRTIO_NET;
    k->revision = VIRTIO_PCI_ABI_VERSION;
    k->class_id = PCI_CLASS_OTHERS;
    k->class_id = PCI_CLASS_NETWORK_ETHERNET;
    set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);
    device_class_set_props(dc, virtio_net_properties);
    vpciklass->realize = virtio_net_pci_vf_realize;
}

static void virtio_net_pci_vf_assign_netdev(Object *obj)
{
    char nd_name[] = "ndvfX";
    static int nd_num = 0;

    sprintf(nd_name, "ndvf%1d", nd_num++);
    object_property_parse(obj, "netdev", nd_name, NULL);
}

static void virtio_net_pci_vf_instance_init(Object *obj)
{
    VirtIONetPCIVF *dev = VIRTIO_NET_PCI_VF(obj);

    virtio_instance_init_common(obj, &dev->vdev, sizeof(dev->vdev),
                                TYPE_VIRTIO_NET);

    virtio_net_pci_vf_assign_netdev(obj);
}

static const VirtioPCIDeviceTypeInfo virtio_net_pci_vf_info = {
    .base_name             = TYPE_VIRTIO_NET_PCI_VF,
    .generic_name          = "virtio-net-pci-vf",
    .instance_size = sizeof(VirtIONetPCIVF),
    .instance_init = virtio_net_pci_vf_instance_init,
    .class_init    = virtio_net_pci_vf_class_init,
};

static void virtio_net_pci_vf_register(void)
{
    virtio_pci_types_register(&virtio_net_pci_vf_info);
}

type_init(virtio_net_pci_vf_register)
