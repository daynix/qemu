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
#include "ebpf/rss.bpf.skeleton.h"
#include "trace.h"

void ebpf_rss_init(struct EBPFRSSContext *ctx)
{
    if (ctx != NULL) {
        ctx->obj = NULL;
        ctx->program_fd = -1;
        ctx->mmap_configuration = NULL;
    }
}

bool ebpf_rss_is_loaded(struct EBPFRSSContext *ctx)
{
    return ctx != NULL && (ctx->obj != NULL || ctx->program_fd != -1);
}

bool ebpf_rss_load(struct EBPFRSSContext *ctx)
{
    struct rss_bpf *rss_bpf_ctx;

    if (ctx == NULL || ebpf_rss_is_loaded(ctx)) {
        return false;
    }

    rss_bpf_ctx = rss_bpf__open();
    if (rss_bpf_ctx == NULL) {
        trace_ebpf_error("eBPF RSS", "can not open eBPF RSS object");
        goto error;
    }

    bpf_program__set_socket_filter(rss_bpf_ctx->progs.tun_rss_steering_prog);

    if (rss_bpf__load(rss_bpf_ctx)) {
        trace_ebpf_error("eBPF RSS", "can not load RSS program");
        goto error;
    }

    ctx->obj = rss_bpf_ctx;
    ctx->program_fd = bpf_program__fd(
            rss_bpf_ctx->progs.tun_rss_steering_prog);
    ctx->map_configuration = bpf_map__fd(
            rss_bpf_ctx->maps.tap_rss_map_configurations);

    ctx->mmap_configuration = mmap(NULL, qemu_real_host_page_size,
                                   PROT_READ | PROT_WRITE, MAP_SHARED,
                                   ctx->map_configuration, 0);
    if (ctx->mmap_configuration == MAP_FAILED) {
        trace_ebpf_error("eBPF RSS", "can not mmap eBPF configuration array");
        goto error;
    }

    return true;
error:
    rss_bpf__destroy(rss_bpf_ctx);
    ctx->obj = NULL;
    ctx->program_fd = -1;
    ctx->mmap_configuration = NULL;

    return false;
}

bool ebpf_rss_load_fds(struct EBPFRSSContext *ctx, int program_fd,
                       int config_fd, int toeplitz_fd, int table_fd)
{
    if (ctx == NULL || ebpf_rss_is_loaded(ctx)) {
        return false;
    }

    ctx->program_fd = program_fd;
    ctx->map_configuration = config_fd;

    ctx->mmap_configuration = mmap(NULL, qemu_real_host_page_size,
                                   PROT_READ | PROT_WRITE, MAP_SHARED,
                                   ctx->map_configuration, 0);
    if (ctx->mmap_configuration == MAP_FAILED) {
        trace_ebpf_error("eBPF RSS", "can not mmap eBPF configuration array");
        return false;
    }

    return true;
}

bool ebpf_rss_set_all(struct EBPFRSSContext *ctx, struct EBPFRSSConfig *config,
                      uint16_t *indirections_table, uint8_t *toeplitz_key)
{
    if (!ebpf_rss_is_loaded(ctx) || config == NULL ||
        indirections_table == NULL || toeplitz_key == NULL ||
        config->indirections_len > VIRTIO_NET_RSS_MAX_TABLE_LEN) {
        return false;
    }

    struct {
        struct EBPFRSSConfig config;
        uint8_t toeplitz_key[VIRTIO_NET_RSS_MAX_KEY_SIZE];
        uint16_t indirections_table[VIRTIO_NET_RSS_MAX_TABLE_LEN];
    } __attribute__((packed)) ebpf_config;

    /* Setting up configurations */
    memcpy(&ebpf_config.config, config, sizeof(*config));

    /* Setting up toeplitz key data */
    memcpy(&ebpf_config.toeplitz_key, toeplitz_key,
           VIRTIO_NET_RSS_MAX_KEY_SIZE);
    *(uint32_t *)ebpf_config.toeplitz_key =
            ntohl(*(uint32_t *)ebpf_config.toeplitz_key);

    /* Setting up indirections table */
    memcpy(&ebpf_config.indirections_table, indirections_table,
           config->indirections_len * sizeof(*indirections_table));

    if (ctx->mmap_configuration != NULL) {
        memcpy(ctx->mmap_configuration, &ebpf_config, sizeof(ebpf_config));
    }

    return true;
}

void ebpf_rss_unload(struct EBPFRSSContext *ctx)
{
    if (!ebpf_rss_is_loaded(ctx)) {
        return;
    }

    if (ctx->mmap_configuration) {
        munmap(ctx->mmap_configuration, qemu_real_host_page_size);
    }

    if (ctx->obj != NULL) {
        rss_bpf__destroy(ctx->obj);
    } else {
        close(ctx->program_fd);
        close(ctx->map_configuration);
    }

    ctx->obj = NULL;
    ctx->program_fd = -1;
    ctx->mmap_configuration = NULL;
}
