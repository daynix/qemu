#ifndef QEMU_EBPF_RSS_H
#define QEMU_EBPF_RSS_H

#include <stdint.h>
#include <stdbool.h>

struct EBPFRSSContext {
    int program_fd;
    int map_configuration;
    int map_toeplitz_key;
    int map_indirections_table;
};

struct EBPFRSSConfig {
    uint8_t redirect;
    uint8_t populate_hash;
    uint32_t hash_types;
    uint16_t indirections_len;
    uint16_t default_queue;
};

bool ebpf_rss_is_loaded(struct EBPFRSSContext *ctx);

bool ebpf_rss_load(struct EBPFRSSContext *ctx);

bool ebpf_rss_set_config(struct EBPFRSSContext *ctx,
                         struct EBPFRSSConfig *config);

bool ebpf_rss_set_inirections_table(struct EBPFRSSContext *ctx,
                                    uint16_t *indirections_table, size_t len);

bool ebpf_rss_set_toepliz_key(struct EBPFRSSContext *ctx,
                              uint8_t *toeplitz_key);

bool ebpf_rss_set_all(struct EBPFRSSContext *ctx, struct EBPFRSSConfig *config,
                      uint16_t *indirections_table, uint8_t *toeplitz_key);

void ebpf_rss_unload(struct EBPFRSSContext *ctx);

#endif /* QEMU_EBPF_RSS_H */
