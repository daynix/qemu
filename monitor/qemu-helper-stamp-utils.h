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
 */

#ifndef QEMU_QEMU_HELPER_STAMP_UTILS_H
#define QEMU_QEMU_HELPER_STAMP_UTILS_H

#include "qemu-helper-stamp.h" /* generated stamp per build */

#define QEMU_HELPER_STAMP_STR     stringify(QEMU_HELPER_STAMP)

#define QEMU_DEFAULT_EBPF_HELPER_BIN_NAME "qemu-ebpf-rss-helper"

char *qemu_find_default_ebpf_helper(void);

char *qemu_check_suggested_ebpf_helper(const char *path);

#endif /* QEMU_QEMU_HELPER_STAMP_UTILS_H */
