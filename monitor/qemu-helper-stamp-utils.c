/*
 * QEMU helper stamp check utils.
 *
 * Developed by Daynix Computing LTD (http://www.daynix.com)
 *
 * Authors:
 *  Andrew Melnychenko <andrew@daynix.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Description: This file mostly implements helper stamp checking.
 *              The stamp is implemented in a similar way as in qemu modules.
 *              The helper should contain a specific symbol.
 *              Not in a similar way is symbol checking - here we parse
 *              the ELF file. For now(10.07.2021), only eBPF helper contains
 *              the stamp, and the stamp is generated from
 *              sha1 ebpf/rss.bpf.skeleton.h (see meson.build).
 */

#include "qemu/osdep.h"
#include "elf.h"
#include "qemu-helper-stamp-utils.h"

#ifdef CONFIG_LINUX

static void *file_allocate_and_read(int fd, off_t off, size_t size)
{
    void *data;
    int err;

    if (fd < 0) {
        return NULL;
    }

    err = lseek(fd, off, SEEK_SET);
    if (err < 0) {
        return NULL;
    }

    data = g_new0(char, size);
    if (data == NULL) {
        return NULL;
    }

    err = read(fd, data, size);
    if (err < 0) {
        g_free(data);
        return NULL;
    }

    return data;
}

static Elf64_Shdr *elf64_get_section_table(int fd, Elf64_Ehdr *elf_header)
{
    if (elf_header == NULL) {
        return NULL;
    }
    return (Elf64_Shdr *)file_allocate_and_read(fd, elf_header->e_shoff,
                             elf_header->e_shnum * elf_header->e_shentsize);
}

static Elf32_Shdr *elf32_get_section_table(int fd, Elf32_Ehdr *elf_header)
{
    if (elf_header == NULL) {
        return NULL;
    }
    return (Elf32_Shdr *)file_allocate_and_read(fd, elf_header->e_shoff,
                             elf_header->e_shnum * elf_header->e_shentsize);
}

static void *elf64_get_section_data(int fd, const Elf64_Shdr* section_header)
{
    if (fd < 0 || section_header == NULL) {
        return NULL;
    }
    return file_allocate_and_read(fd, section_header->sh_offset,
                                  section_header->sh_size);
}

static void *elf32_get_section_data(int fd, const Elf32_Shdr* section_header)
{
    if (fd < 0 || section_header == NULL) {
        return NULL;
    }
    return file_allocate_and_read(fd, section_header->sh_offset,
                                  section_header->sh_size);
}

static bool elf64_check_symbol_in_symbol_table(int fd,
                                               Elf64_Shdr *section_table,
                                               Elf64_Shdr *symbol_section,
                                               const char *symbol)
{
    Elf64_Sym *symbol_table;
    char *string_table;
    uint32_t i;
    bool ret = false;

    symbol_table = (Elf64_Sym *) elf64_get_section_data(fd, symbol_section);
    if (symbol_table == NULL) {
        return false;
    }

    string_table = (char *) elf64_get_section_data(
            fd, section_table + symbol_section->sh_link);
    if (string_table == NULL) {
        g_free(symbol_table);
        return false;
    }

    for (i = 0; i < (symbol_section->sh_size / sizeof(Elf64_Sym)); ++i) {
        if (strncmp((string_table + symbol_table[i].st_name),
                     symbol, strlen(symbol)) == 0)
        {
            ret = true;
            break;
        }
    }

    g_free(string_table);
    g_free(symbol_table);
    return ret;
}

static bool elf32_check_symbol_in_symbol_table(int fd,
                                               Elf32_Shdr *section_table,
                                               Elf32_Shdr *symbol_section,
                                               const char *symbol)
{
    Elf32_Sym *symbol_table;
    char *string_table;
    uint32_t i;
    bool ret = false;

    symbol_table = (Elf32_Sym *) elf32_get_section_data(fd, symbol_section);
    if (symbol_table == NULL) {
        return false;
    }

    string_table = (char *) elf32_get_section_data(fd,
                                       section_table + symbol_section->sh_link);
    if (string_table == NULL) {
        g_free(symbol_table);
        return false;
    }

    for (i = 0; i < (symbol_section->sh_size / sizeof(Elf32_Sym)); ++i) {
        if (strncmp((string_table + symbol_table[i].st_name),
                     symbol, strlen(symbol)) == 0)
        {
            ret = true;
            break;
        }
    }

    g_free(string_table);
    g_free(symbol_table);
    return ret;
}

static bool elf64_check_stamp(int fd, Elf64_Ehdr *elf_header, const char *stamp)
{
    Elf64_Shdr *section_table;
    size_t i;
    bool ret = false;

    section_table = elf64_get_section_table(fd, elf_header);
    if (section_table == NULL) {
        return false;
    }

    for (i = 0; i < elf_header->e_shnum; ++i) {
        if ((section_table[i].sh_type == SHT_SYMTAB)
             || (section_table[i].sh_type == SHT_DYNSYM)) {
            if (elf64_check_symbol_in_symbol_table(fd, section_table,
                                                   section_table + i, stamp)) {
                ret = true;
                break;
            }
        }
    }

    g_free(section_table);
    return ret;
}

static bool elf32_check_stamp(int fd, Elf32_Ehdr *elf_header, const char *stamp)
{
    Elf32_Shdr *section_table;
    size_t i;
    bool ret = false;

    section_table = elf32_get_section_table(fd, elf_header);
    if (section_table == NULL) {
        return false;
    }

    for (i = 0; i < elf_header->e_shnum; ++i) {
        if ((section_table[i].sh_type == SHT_SYMTAB)
             || (section_table[i].sh_type == SHT_DYNSYM)) {
            if (elf32_check_symbol_in_symbol_table(fd, section_table,
                                                   section_table + i, stamp)) {
                ret = true;
                break;
            }
        }
    }

    g_free(section_table);
    return ret;
}

bool qemu_check_helper_stamp(const char *path, const char *stamp)
{
    int fd;
    bool ret = false;
    Elf64_Ehdr *elf_header;

    fd = open(path, O_RDONLY | O_SYNC);
    if (fd < 0) {
        return false;
    }

    elf_header = (Elf64_Ehdr *)file_allocate_and_read(
            fd, 0, sizeof(Elf64_Ehdr));
    if (elf_header == NULL) {
        goto error;
    }

    if (strncmp((char *)elf_header->e_ident, ELFMAG, SELFMAG)) {
        g_free(elf_header);
        goto error;
    }

    if (elf_header->e_ident[EI_CLASS] == ELFCLASS64) {
        ret = elf64_check_stamp(fd, elf_header, stamp);
    } else if (elf_header->e_ident[EI_CLASS] == ELFCLASS32) {
        ret = elf32_check_stamp(fd, (Elf32_Ehdr *)elf_header, stamp);
    }

    g_free(elf_header);
error:
    close(fd);
    return ret;
}

#else

bool qemu_check_helper_stamp(const char *path, const char *stamp)
{
    return false;
}

#endif

char *qemu_find_helper(const char *name, bool check_stamp)
{
    char *qemu_exec = NULL;
    char *qemu_dir = NULL;
    char *helper = NULL;

    if (name == NULL) {
        return NULL;
    }

    helper = g_build_filename(CONFIG_QEMU_HELPERDIR, name, NULL);
    if (g_access(helper, F_OK) == 0
        && (!check_stamp
            || qemu_check_helper_stamp(helper, QEMU_HELPER_STAMP_STR))) {
        return helper;
    }
    g_free(helper);

#ifdef CONFIG_LINUX
    qemu_exec = g_file_read_link("/proc/self/exe", NULL);
#else
    qemu_exec = NULL;
#endif
    if (qemu_exec != NULL) {
        qemu_dir = g_path_get_dirname(qemu_exec);
        g_free(qemu_exec);
        helper = g_build_filename(qemu_dir, name, NULL);
        g_free(qemu_dir);
        if (g_access(helper, F_OK) == 0
           && (!check_stamp
               || qemu_check_helper_stamp(helper, QEMU_HELPER_STAMP_STR))) {
            return helper;
        }
        g_free(helper);
    }

    return NULL;
}
