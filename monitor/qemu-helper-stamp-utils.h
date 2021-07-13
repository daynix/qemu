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

bool qemu_check_helper_stamp(const char *path, const char *stamp);

char *qemu_find_helper(const char *name, bool check_stamp);

#endif /* QEMU_QEMU_HELPER_STAMP_UTILS_H */
