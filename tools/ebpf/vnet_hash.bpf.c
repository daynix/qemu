/*
 * eBPF RSS program
 *
 * Developed by Daynix Computing LTD (http://www.daynix.com)
 *
 * Authors:
 *  Andrew Melnychenko <andrew@daynix.com>
 *  Yuri Benditovich <yuri.benditovich@daynix.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Prepare:
 * Requires llvm, clang, bpftool, linux kernel tree
 *
 * Build vnet_hash.bpf.skeleton.h:
 * make -f Makefile.ebpf clean all
 */

#include "rss.bpf.h"

SEC("vnet_hash")
int tun_rss_steering_prog(struct __sk_buff *skb)
{
    all(skb,
        &skb->vnet_hash_value, &skb->vnet_hash_report, &skb->vnet_rss_queue);

    return 0;
}
