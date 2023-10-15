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
 * Build socket.bpf.skeleton.h:
 * make -f Makefile.ebpf clean all
 */

#include "rss.bpf.h"

SEC("socket")
int tun_rss_steering_prog(struct __sk_buff *skb)
{
    __u32 hash_value;
    __u16 hash_report;
    __u16 rss_queue = 0;

    all(skb, &hash_value, &hash_report, &rss_queue);

    return rss_queue;
}
