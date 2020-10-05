#include <unistd.h>
#include <bpf/libbpf.h>

#include "ebpf/ebpf_rss.h"
#include "ebpf_rss_data.h"

bool ebpf_rss_is_loaded(struct EBPFRSSContext *ctx)
{
    return ctx != NULL && ctx->obj != NULL;
}

bool ebpf_rss_load(struct EBPFRSSContext *ctx)
{
    int err = 0;
    struct bpf_object *object = NULL;
    struct bpf_program *prog  = NULL;

    if (ctx == NULL) {
        return false;
    }

    object = bpf_object__open_mem(ebpf_rss_elf_data,
                                  sizeof(ebpf_rss_elf_data), NULL);
    if (object == NULL) {
        return false;
    }

    prog = bpf_object__find_program_by_title(object, "tun_rss_steering");
    if (prog == NULL) {
        bpf_object__close(object);
        return false;
    }

    bpf_program__set_socket_filter(prog);

    err = bpf_object__load(object);

    if (err) {
        bpf_object__close(object);
        return false;
    }

    ctx->obj = object;
    ctx->program_fd = bpf_program__fd(prog);

    ctx->map_configuration =
            bpf_object__find_map_fd_by_name(object,
            "tap_rss_map_configurations");
    if (ctx->map_configuration < 0) {
        goto map_issue;
    }

    ctx->map_toeplitz_key =
            bpf_object__find_map_fd_by_name(object,
            "tap_rss_map_toeplitz_key");
    if (ctx->map_toeplitz_key < 0) {
        goto map_issue;
    }

    ctx->map_indirections_table =
            bpf_object__find_map_fd_by_name(object,
            "tap_rss_map_indirection_table");
    if (ctx->map_indirections_table < 0) {
        goto map_issue;
    }

    return true;
map_issue:
    bpf_object__close(object);
    ctx->obj = NULL;
    return false;
}

bool ebpf_rss_set_config(struct EBPFRSSContext *ctx,
                         struct EBPFRSSConfig *config)
{
    if (!ebpf_rss_is_loaded(ctx)) {
        return false;
    }

    uint32_t map_key = 0;
    if (bpf_map_update_elem(ctx->map_configuration,
                            &map_key, config, BPF_ANY) < 0) {
        return false;
    }

    return true;
}

bool ebpf_rss_set_inirection_table(struct EBPFRSSContext *ctx,
                                   uint16_t *indirection_table, size_t len)
{
    if (!ebpf_rss_is_loaded(ctx) ||
       len > EBPF_RSS_INDIRECTION_TABLE_SIZE) {
        return false;
    }
    uint32_t i = 0;

    for (; i < len; ++i) {
        if (bpf_map_update_elem(ctx->map_configuration, &i,
                                indirection_table + i, BPF_ANY) < 0) {
            return false;
        }
    }

    return true;
}

bool ebpf_rss_set_toepliz_key(struct EBPFRSSContext *ctx, uint8_t *toeplitz_key)
{
    if (!ebpf_rss_is_loaded(ctx)) {
        return false;
    }

    uint32_t map_key = 0;
    if (bpf_map_update_elem(ctx->map_configuration, &map_key, toeplitz_key,
                            BPF_ANY) < 0) {
        return false;
    }

    return true;
}

bool ebpf_rss_set_all(struct EBPFRSSContext *ctx, struct EBPFRSSConfig *config,
                      uint16_t *indirection_table, uint8_t *toeplitz_key)
{
    if (!ebpf_rss_is_loaded(ctx) || config == NULL ||
        indirection_table == NULL || toeplitz_key == NULL) {
        return false;
    }

    if (!ebpf_rss_set_config(ctx, config)) {
        return false;
    }

    if (!ebpf_rss_set_inirection_table(ctx, indirection_table,
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
