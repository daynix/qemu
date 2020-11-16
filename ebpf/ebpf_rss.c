/*
 * eBPF RSS loader
 *
 * Developed by Daynix Computing LTD (http://www.daynix.com)
 *
 * Authors:
 *  Andrew Melnychenko <andrew@daynix.com>
 *  Yuri Benditovich <yuri.benditovich@daynix.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "hw/virtio/virtio-net.h" /* VIRTIO_NET_RSS_MAX_TABLE_LEN */

#include "ebpf/ebpf_rss.h"
#include "ebpf/tun_rss_steering.h"
#include "trace.h"

void ebpf_rss_init(struct EBPFRSSContext *ctx)
{
    if (ctx != NULL) {
        ctx->obj = NULL;
    }
}

bool ebpf_rss_is_loaded(struct EBPFRSSContext *ctx)
{
    return ctx != NULL && ctx->obj != NULL;
}

bool ebpf_rss_load(struct EBPFRSSContext *ctx)
{
    struct bpf_object *object = NULL;
    struct bpf_program *prog  = NULL;

    if (ctx == NULL) {
        return false;
    }

    object = bpf_object__open_mem(data_tun_rss_steering,
                                  sizeof(data_tun_rss_steering), NULL);
    if (object == NULL) {
        trace_ebpf_error("eBPF RSS", "can not open eBPF object");
        return false;
    }

    prog = bpf_object__find_program_by_title(object, "tun_rss_steering");
    if (prog == NULL) {
        trace_ebpf_error("eBPF RSS", "can not find RSS program");
        goto l_issue;
    }

    bpf_program__set_socket_filter(prog);

    if (bpf_object__load(object)) {
        trace_ebpf_error("eBPF RSS", "can not load RSS program");
        goto l_issue;
    }

    ctx->obj = object;
    ctx->program_fd = bpf_program__fd(prog);

    ctx->map_configuration =
            bpf_object__find_map_fd_by_name(object,
                                            "tap_rss_map_configurations");
    if (ctx->map_configuration < 0) {
        trace_ebpf_error("eBPF RSS", "can not find MAP for configurations");
        goto l_issue;
    }

    ctx->map_toeplitz_key =
            bpf_object__find_map_fd_by_name(object,
                                            "tap_rss_map_toeplitz_key");
    if (ctx->map_toeplitz_key < 0) {
        trace_ebpf_error("eBPF RSS", "can not find MAP for toeplitz key");
        goto l_issue;
    }

    ctx->map_indirections_table =
            bpf_object__find_map_fd_by_name(object,
                                            "tap_rss_map_indirection_table");
    if (ctx->map_indirections_table < 0) {
        trace_ebpf_error("eBPF RSS", "can not find MAP for indirections table");
        goto l_issue;
    }

    return true;

l_issue:
    bpf_object__close(object);
    ctx->obj = NULL;
    return false;
}

static bool ebpf_rss_set_config(struct EBPFRSSContext *ctx,
                                struct EBPFRSSConfig *config)
{
    if (!ebpf_rss_is_loaded(ctx)) {
        return false;
    }
    uint32_t map_key = 0;
    if (bpf_map_update_elem(ctx->map_configuration,
                            &map_key, config, 0) < 0) {
        return false;
    }
    return true;
}

static bool ebpf_rss_set_indirections_table(struct EBPFRSSContext *ctx,
                                            uint16_t *indirections_table,
                                            size_t len)
{
    if (!ebpf_rss_is_loaded(ctx) || indirections_table == NULL ||
       len > VIRTIO_NET_RSS_MAX_TABLE_LEN) {
        return false;
    }
    uint32_t i = 0;

    for (; i < len; ++i) {
        if (bpf_map_update_elem(ctx->map_indirections_table, &i,
                                indirections_table + i, 0) < 0) {
            return false;
        }
    }
    return true;
}

static bool ebpf_rss_set_toepliz_key(struct EBPFRSSContext *ctx,
                                     uint8_t *toeplitz_key)
{
    if (!ebpf_rss_is_loaded(ctx) || toeplitz_key == NULL) {
        return false;
    }
    uint32_t map_key = 0;

    /* prepare toeplitz key */
    uint8_t toe[VIRTIO_NET_RSS_MAX_KEY_SIZE] = {};
    memcpy(toe, toeplitz_key, VIRTIO_NET_RSS_MAX_KEY_SIZE);
    *(uint32_t *)toe = ntohl(*(uint32_t *)toe);

    if (bpf_map_update_elem(ctx->map_toeplitz_key, &map_key, toe,
                            0) < 0) {
        return false;
    }
    return true;
}

bool ebpf_rss_set_all(struct EBPFRSSContext *ctx, struct EBPFRSSConfig *config,
                      uint16_t *indirections_table, uint8_t *toeplitz_key)
{
    if (!ebpf_rss_is_loaded(ctx) || config == NULL ||
        indirections_table == NULL || toeplitz_key == NULL) {
        return false;
    }

    if (!ebpf_rss_set_config(ctx, config)) {
        return false;
    }

    if (!ebpf_rss_set_indirections_table(ctx, indirections_table,
                                      config->indirections_len)) {
        return false;
    }

    if (!ebpf_rss_set_toepliz_key(ctx, toeplitz_key)) {
        return false;
    }

    return true;
}

void ebpf_rss_unload(struct EBPFRSSContext *ctx)
{
    if (!ebpf_rss_is_loaded(ctx)) {
        return;
    }

    bpf_object__close(ctx->obj);
    ctx->obj = NULL;
}
