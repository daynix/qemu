#include "ebpf/ebpf.h"

int bpf_create_map(enum bpf_map_type map_type,
                   unsigned int key_size,
                   unsigned int value_size,
                   unsigned int max_entries)
{
    return -1;
}

int bpf_lookup_elem(int fd, const void *key, void *value)
{
    return -1;
}

int bpf_update_elem(int fd, const void *key, const void *value,
                    uint64_t flags)
{
    return -1;
}

int bpf_delete_elem(int fd, const void *key)
{
    return -1;
}

int bpf_prog_load(enum bpf_prog_type type,
                  const struct bpf_insn *insns, int insn_cnt,
                  const char *license)
{
    return -1;
}

unsigned int bpf_fixup_mapfd(struct fixup_mapfd_t *table,
                             size_t table_size, struct bpf_insn *insn,
                             size_t insn_len, const char *map_name, int fd)
{
    return 0;
}
