===========================
eBPF RSS virtio-net support
===========================

RSS(Receive Side Scaling) used to distribute network packets to guest queues by calculating packet hash.
Usually, every queue is processed by a specific guest CPU core.

For now, there are 2 RSS implementations in qemu:

- 'software' RSS
- eBPF RSS

TAP + virtio-net queues usually linked in order. So packet from TAP queue 1 would be sent to virtio tx queue 1 etc.
'software' RSS 're-steers' packets in qemu after reading it from the TAP device. eBPF RSS steers them by eBPF program in TAP device. The eBPF program sets by TAP's TUNSETSTEERINGEBPF ioctl.

Simplified decision formula:

.. code:: C

    queue_index = indirection_table[hash(<packet data>)%<indirection_table size>]


Not for all packets, the hash can/should be calculated.

Note: currently, eBPF RSS does not support hash reporting.

eBPF RSS turned on by different combinations of vhost-net, vitrio-net and tap configurations:

- eBPF is used:

        tap,vhost=off & virtio-net-pci,rss=on,hash=off

- eBPF is used:

        tap,vhost=on & virtio-net-pci,rss=on,hash=off

- 'software' RSS is used:

        tap,vhost=off & virtio-net-pci,rss=on,hash=on

- eBPF is used, hash population would be not reported as virtio-net feature to guest:

        tap,vhost=on & virtio-net-pci,rss=on,hash=on

If CONFIG_EBPF doesn't set, then 'software' RSS is used in all cases.
Also 'software' RSS, as a fallback, is used if the eBPF program failed to load or set to TAP.

RSS eBPF program
----------------

RSS program located in ebpf/tun_rss_steering.h as an array of 'struct bpf_insn'.
So the program is part of the qemu binary.
Initially, the eBPF program was compiled by clang and source code located at ebpf/rss.bpf.c.

To compile ebpf/rss.bpf.c:

        $ clang -O2 -g -fno-stack-protector -S -emit-llvm -c rss.bpf.c -o - | llc -march=bpf -filetype=obj -o rss.bpf.o

Also, there is a python script for convertation from eBPF ELF object to '.h' file - Ebpf_to_C.py:

        $ python EbpfElf_to_C.py rss.bpf.o tun_rss_steering

The first argument of the script is ELF object, second - section name where the eBPF program located.
The script would generate <section name>.h file with eBPF instructions and 'relocate array'.
'relocate array' is an array of 'struct fixup_mapfd_t' with the name of the eBPF map and instruction offset where the file descriptor of the map should be placed.

Current eBPF RSS implementation uses 'bounded loops' with 'backward jump instructions' which present in the last kernels(version 5.3).

eBPF RSS implementation
-----------------------

eBPF RSS loading functionality located in ebpf/ebpf_rss.c and ebpf/ebpf_rss.h.

The `struct EBPFRSSContext` structure that holds 4 file descriptors:

- program_fd - file descriptor of the eBPF RSS program.
- map_configuration - file descriptor of the 'configuration' map. This map contains one element of 'struct EBPFRSSConfig'. This configuration determines eBPF program behavior.
- map_toeplitz_key - file descriptor of the 'Toeplitz key' map. One element of the 40byte key prepared for the hashing algorithm.
- map_indirections_table - 128 elements of queue indexes.

`struct EBPFRSSConfig` fields:

- redirect - "boolean" value, should the hash be calculated, on false  - `default_queue` would be used as the final decision.
- populate_hash - for now, not used. eBPF RSS doesn't support hash reporting.
- hash_types - binary mask of different hash types. See `VIRTIO_NET_RSS_HASH_TYPE_*` defines. If for packet hash should not be calculated - `default_queue` would be used.
- indirections_len - length of the indirections table, maximum 128.
- default_queue - the queue index that used for packet that shouldn't be hashed. For some packets, the hash can't be calculated(g.e ARP).

Functions:

- `ebpf_rss_init()` - sets program_fd to -1, which indicates that EBPFRSSContext is not loaded.
- `ebpf_rss_load()` - creates 3 maps and loads eBPF program from tun_rss_steering.h. Returns 'true' on success. After that, program_fd can be used to set steering for TAP.
- `ebpf_rss_set_all()` - sets values for eBPF maps. `indirections_table` length is in EBPFRSSConfig. `toeplitz_key` is VIRTIO_NET_RSS_MAX_KEY_SIZE aka 40 bytes array.
- `ebpf_rss_unload()` - close all file descriptors and set program_fd to -1.

Simplified eBPF RSS workflow:

.. code:: C

    struct EBPFRSSConfig config;
    config.redirect = 1;
    config.hash_types = VIRTIO_NET_RSS_HASH_TYPE_UDPv4 | VIRTIO_NET_RSS_HASH_TYPE_TCPv4;
    config.indirections_len = VIRTIO_NET_RSS_MAX_TABLE_LEN;
    config.default_queue = 0;

    uint16_t table[VIRTIO_NET_RSS_MAX_TABLE_LEN] = {...};
    uint8_t key[VIRTIO_NET_RSS_MAX_KEY_SIZE] = {...};

    struct EBPFRSSContext ctx;
    ebpf_rss_init(&ctx);
    ebpf_rss_load(&ctx);
    ebpf_rss_set_all(&ctx, &config, table, key);
    if (net_client->info->set_steering_ebpf != NULL) {
        net_client->info->set_steering_ebpf(net_client, ctx->program_fd);
    }
    ...
    ebpf_unload(&ctx);


NetClientState SetSteeringEBPF()
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For now, `set_steering_ebpf()` method supported by Linux TAP NetClientState. The method requires an eBPF program file descriptor as an argument.
