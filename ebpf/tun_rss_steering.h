#ifndef TUN_RSS_STEERING
#define TUN_RSS_STEERING

struct bpf_insn instun_rss_steering[] = {
    {0xbf, 0x08, 0x01, 0x0000, 0x00000000},
    {0xb7, 0x09, 0x00, 0x0000, 0x00000000},
    {0x63, 0x0a, 0x09, 0xff4c, 0x00000000},
    {0xbf, 0x06, 0x0a, 0x0000, 0x00000000},
    {0x07, 0x06, 0x00, 0x0000, 0xffffff4c},
    {0x18, 0x01, 0x00, 0x0000, 0x00000000},
    {0x00, 0x00, 0x00, 0x0000, 0x00000000},
    {0xbf, 0x02, 0x06, 0x0000, 0x00000000},
    {0x85, 0x00, 0x00, 0x0000, 0x00000001},
    {0xbf, 0x07, 0x00, 0x0000, 0x00000000},
    {0x18, 0x01, 0x00, 0x0000, 0x00000000},
    {0x00, 0x00, 0x00, 0x0000, 0x00000000},
    {0xbf, 0x02, 0x06, 0x0000, 0x00000000},
    {0x85, 0x00, 0x00, 0x0000, 0x00000001},
    {0x15, 0x07, 0x00, 0x017d, 0x00000000},
    {0xbf, 0x05, 0x00, 0x0000, 0x00000000},
    {0x15, 0x05, 0x00, 0x017b, 0x00000000},
    {0xb7, 0x01, 0x00, 0x0000, 0x00000000},
    {0x63, 0x0a, 0x01, 0xffc0, 0x00000000},
    {0x7b, 0x0a, 0x01, 0xffb8, 0x00000000},
    {0x7b, 0x0a, 0x01, 0xffb0, 0x00000000},
    {0x7b, 0x0a, 0x01, 0xffa8, 0x00000000},
    {0x7b, 0x0a, 0x01, 0xffa0, 0x00000000},
    {0x63, 0x0a, 0x01, 0xff98, 0x00000000},
    {0x7b, 0x0a, 0x01, 0xff90, 0x00000000},
    {0x7b, 0x0a, 0x01, 0xff88, 0x00000000},
    {0x7b, 0x0a, 0x01, 0xff80, 0x00000000},
    {0x7b, 0x0a, 0x01, 0xff78, 0x00000000},
    {0x7b, 0x0a, 0x01, 0xff70, 0x00000000},
    {0x7b, 0x0a, 0x01, 0xff68, 0x00000000},
    {0x7b, 0x0a, 0x01, 0xff60, 0x00000000},
    {0x7b, 0x0a, 0x01, 0xff58, 0x00000000},
    {0x7b, 0x0a, 0x01, 0xff50, 0x00000000},
    {0x15, 0x08, 0x00, 0x0083, 0x00000000},
    {0x61, 0x01, 0x08, 0x0010, 0x00000000},
    {0xdc, 0x01, 0x00, 0x0000, 0x00000010},
    {0x15, 0x01, 0x00, 0x0034, 0x000086dd},
    {0x55, 0x01, 0x00, 0x007f, 0x00000800},
    {0x7b, 0x0a, 0x05, 0xff28, 0x00000000},
    {0x7b, 0x0a, 0x00, 0xff30, 0x00000000},
    {0xb7, 0x01, 0x00, 0x0000, 0x00000001},
    {0x73, 0x0a, 0x01, 0xff50, 0x00000000},
    {0xb7, 0x01, 0x00, 0x0000, 0x00000000},
    {0x63, 0x0a, 0x01, 0xffe0, 0x00000000},
    {0x7b, 0x0a, 0x01, 0xffd8, 0x00000000},
    {0x7b, 0x0a, 0x01, 0xffd0, 0x00000000},
    {0xbf, 0x03, 0x0a, 0x0000, 0x00000000},
    {0x07, 0x03, 0x00, 0x0000, 0xffffffd0},
    {0xbf, 0x01, 0x08, 0x0000, 0x00000000},
    {0xb7, 0x02, 0x00, 0x0000, 0x00000000},
    {0xb7, 0x04, 0x00, 0x0000, 0x00000014},
    {0xb7, 0x05, 0x00, 0x0000, 0x00000001},
    {0x85, 0x00, 0x00, 0x0000, 0x00000044},
    {0x61, 0x01, 0x0a, 0xffdc, 0x00000000},
    {0x63, 0x0a, 0x01, 0xff5c, 0x00000000},
    {0x61, 0x01, 0x0a, 0xffe0, 0x00000000},
    {0x63, 0x0a, 0x01, 0xff60, 0x00000000},
    {0x71, 0x06, 0x0a, 0xffd9, 0x00000000},
    {0x71, 0x01, 0x0a, 0xffd0, 0x00000000},
    {0x67, 0x01, 0x00, 0x0000, 0x00000002},
    {0x57, 0x01, 0x00, 0x0000, 0x0000003c},
    {0x7b, 0x0a, 0x01, 0xff40, 0x00000000},
    {0x57, 0x06, 0x00, 0x0000, 0x000000ff},
    {0x15, 0x06, 0x00, 0x0054, 0x00000011},
    {0x79, 0x00, 0x0a, 0xff30, 0x00000000},
    {0x79, 0x05, 0x0a, 0xff28, 0x00000000},
    {0x55, 0x06, 0x00, 0x0062, 0x00000006},
    {0xb7, 0x01, 0x00, 0x0000, 0x00000001},
    {0x73, 0x0a, 0x01, 0xff53, 0x00000000},
    {0xb7, 0x01, 0x00, 0x0000, 0x00000000},
    {0x63, 0x0a, 0x01, 0xffe0, 0x00000000},
    {0x7b, 0x0a, 0x01, 0xffd8, 0x00000000},
    {0x7b, 0x0a, 0x01, 0xffd0, 0x00000000},
    {0xbf, 0x03, 0x0a, 0x0000, 0x00000000},
    {0x07, 0x03, 0x00, 0x0000, 0xffffffd0},
    {0xbf, 0x01, 0x08, 0x0000, 0x00000000},
    {0x79, 0x02, 0x0a, 0xff40, 0x00000000},
    {0xb7, 0x04, 0x00, 0x0000, 0x00000014},
    {0xbf, 0x08, 0x05, 0x0000, 0x00000000},
    {0xb7, 0x05, 0x00, 0x0000, 0x00000001},
    {0xbf, 0x06, 0x00, 0x0000, 0x00000000},
    {0x85, 0x00, 0x00, 0x0000, 0x00000044},
    {0xbf, 0x05, 0x08, 0x0000, 0x00000000},
    {0xbf, 0x00, 0x06, 0x0000, 0x00000000},
    {0x69, 0x01, 0x0a, 0xffd0, 0x00000000},
    {0x6b, 0x0a, 0x01, 0xff56, 0x00000000},
    {0x69, 0x01, 0x0a, 0xffd2, 0x00000000},
    {0x6b, 0x0a, 0x01, 0xff58, 0x00000000},
    {0x05, 0x00, 0x00, 0x004c, 0x00000000},
    {0x7b, 0x0a, 0x05, 0xff28, 0x00000000},
    {0x7b, 0x0a, 0x00, 0xff30, 0x00000000},
    {0x7b, 0x0a, 0x07, 0xff10, 0x00000000},
    {0xb7, 0x07, 0x00, 0x0000, 0x00000001},
    {0x73, 0x0a, 0x07, 0xff51, 0x00000000},
    {0xb7, 0x01, 0x00, 0x0000, 0x00000000},
    {0x7b, 0x0a, 0x01, 0xfff0, 0x00000000},
    {0x7b, 0x0a, 0x01, 0xffe8, 0x00000000},
    {0x7b, 0x0a, 0x01, 0xffe0, 0x00000000},
    {0x7b, 0x0a, 0x01, 0xffd8, 0x00000000},
    {0x7b, 0x0a, 0x01, 0xffd0, 0x00000000},
    {0xbf, 0x03, 0x0a, 0x0000, 0x00000000},
    {0x07, 0x03, 0x00, 0x0000, 0xffffffd0},
    {0xb7, 0x01, 0x00, 0x0000, 0x00000028},
    {0x7b, 0x0a, 0x01, 0xff40, 0x00000000},
    {0xbf, 0x01, 0x08, 0x0000, 0x00000000},
    {0xb7, 0x02, 0x00, 0x0000, 0x00000000},
    {0xb7, 0x04, 0x00, 0x0000, 0x00000028},
    {0xb7, 0x05, 0x00, 0x0000, 0x00000001},
    {0x85, 0x00, 0x00, 0x0000, 0x00000044},
    {0x79, 0x01, 0x0a, 0xffd8, 0x00000000},
    {0x63, 0x0a, 0x01, 0xff5c, 0x00000000},
    {0x77, 0x01, 0x00, 0x0000, 0x00000020},
    {0x63, 0x0a, 0x01, 0xff60, 0x00000000},
    {0x79, 0x01, 0x0a, 0xffe0, 0x00000000},
    {0x63, 0x0a, 0x01, 0xff64, 0x00000000},
    {0x77, 0x01, 0x00, 0x0000, 0x00000020},
    {0x63, 0x0a, 0x01, 0xff68, 0x00000000},
    {0x79, 0x01, 0x0a, 0xffe8, 0x00000000},
    {0x63, 0x0a, 0x01, 0xff6c, 0x00000000},
    {0x77, 0x01, 0x00, 0x0000, 0x00000020},
    {0x63, 0x0a, 0x01, 0xff70, 0x00000000},
    {0x79, 0x01, 0x0a, 0xfff0, 0x00000000},
    {0x63, 0x0a, 0x01, 0xff74, 0x00000000},
    {0x77, 0x01, 0x00, 0x0000, 0x00000020},
    {0x63, 0x0a, 0x01, 0xff78, 0x00000000},
    {0x71, 0x06, 0x0a, 0xffd6, 0x00000000},
    {0x25, 0x06, 0x00, 0x0132, 0x0000003c},
    {0x6f, 0x07, 0x06, 0x0000, 0x00000000},
    {0x18, 0x01, 0x00, 0x0000, 0x00000001},
    {0x00, 0x00, 0x00, 0x0000, 0x1c001800},
    {0x5f, 0x07, 0x01, 0x0000, 0x00000000},
    {0x55, 0x07, 0x00, 0x0001, 0x00000000},
    {0x05, 0x00, 0x00, 0x012c, 0x00000000},
    {0xb7, 0x09, 0x00, 0x0000, 0x00000000},
    {0x6b, 0x0a, 0x09, 0xfffe, 0x00000000},
    {0xb7, 0x01, 0x00, 0x0000, 0x00000028},
    {0x7b, 0x0a, 0x01, 0xff40, 0x00000000},
    {0xbf, 0x01, 0x0a, 0x0000, 0x00000000},
    {0x07, 0x01, 0x00, 0x0000, 0xffffff8c},
    {0x7b, 0x0a, 0x01, 0xff20, 0x00000000},
    {0xbf, 0x01, 0x0a, 0x0000, 0x00000000},
    {0x07, 0x01, 0x00, 0x0000, 0xffffff54},
    {0x7b, 0x0a, 0x01, 0xff18, 0x00000000},
    {0x18, 0x07, 0x00, 0x0000, 0x00000001},
    {0x00, 0x00, 0x00, 0x0000, 0x1c001800},
    {0xb7, 0x01, 0x00, 0x0000, 0x00000000},
    {0x7b, 0x0a, 0x01, 0xff38, 0x00000000},
    {0x05, 0x00, 0x00, 0x0160, 0x00000000},
    {0xb7, 0x01, 0x00, 0x0000, 0x00000001},
    {0x73, 0x0a, 0x01, 0xff52, 0x00000000},
    {0xb7, 0x01, 0x00, 0x0000, 0x00000000},
    {0x7b, 0x0a, 0x01, 0xffd0, 0x00000000},
    {0xbf, 0x03, 0x0a, 0x0000, 0x00000000},
    {0x07, 0x03, 0x00, 0x0000, 0xffffffd0},
    {0xbf, 0x01, 0x08, 0x0000, 0x00000000},
    {0x79, 0x02, 0x0a, 0xff40, 0x00000000},
    {0xb7, 0x04, 0x00, 0x0000, 0x00000008},
    {0xb7, 0x05, 0x00, 0x0000, 0x00000001},
    {0x85, 0x00, 0x00, 0x0000, 0x00000044},
    {0x69, 0x01, 0x0a, 0xffd0, 0x00000000},
    {0x6b, 0x0a, 0x01, 0xff56, 0x00000000},
    {0x69, 0x01, 0x0a, 0xffd2, 0x00000000},
    {0x6b, 0x0a, 0x01, 0xff58, 0x00000000},
    {0x79, 0x00, 0x0a, 0xff30, 0x00000000},
    {0x79, 0x05, 0x0a, 0xff28, 0x00000000},
    {0x71, 0x01, 0x0a, 0xff50, 0x00000000},
    {0x15, 0x01, 0x00, 0x000f, 0x00000000},
    {0x61, 0x01, 0x07, 0x0004, 0x00000000},
    {0x71, 0x02, 0x0a, 0xff53, 0x00000000},
    {0x15, 0x02, 0x00, 0x002c, 0x00000000},
    {0xbf, 0x02, 0x01, 0x0000, 0x00000000},
    {0x57, 0x02, 0x00, 0x0000, 0x00000002},
    {0x15, 0x02, 0x00, 0x0029, 0x00000000},
    {0x61, 0x01, 0x0a, 0xff5c, 0x00000000},
    {0x63, 0x0a, 0x01, 0xffa0, 0x00000000},
    {0x61, 0x01, 0x0a, 0xff60, 0x00000000},
    {0x63, 0x0a, 0x01, 0xffa4, 0x00000000},
    {0x69, 0x01, 0x0a, 0xff56, 0x00000000},
    {0x6b, 0x0a, 0x01, 0xffa8, 0x00000000},
    {0x69, 0x01, 0x0a, 0xff58, 0x00000000},
    {0x6b, 0x0a, 0x01, 0xffaa, 0x00000000},
    {0x05, 0x00, 0x00, 0x0060, 0x00000000},
    {0xb7, 0x08, 0x00, 0x0000, 0x00000000},
    {0x71, 0x01, 0x0a, 0xff51, 0x00000000},
    {0x15, 0x01, 0x00, 0x00b7, 0x00000000},
    {0x61, 0x01, 0x07, 0x0004, 0x00000000},
    {0x71, 0x02, 0x0a, 0xff53, 0x00000000},
    {0x15, 0x02, 0x00, 0x0028, 0x00000000},
    {0xbf, 0x02, 0x01, 0x0000, 0x00000000},
    {0x57, 0x02, 0x00, 0x0000, 0x00000010},
    {0x15, 0x02, 0x00, 0x0025, 0x00000000},
    {0xbf, 0x03, 0x0a, 0x0000, 0x00000000},
    {0x07, 0x03, 0x00, 0x0000, 0xffffff5c},
    {0xbf, 0x02, 0x0a, 0x0000, 0x00000000},
    {0x07, 0x02, 0x00, 0x0000, 0xffffff7c},
    {0x71, 0x04, 0x0a, 0xff54, 0x00000000},
    {0x55, 0x04, 0x00, 0x0001, 0x00000000},
    {0xbf, 0x02, 0x03, 0x0000, 0x00000000},
    {0xbf, 0x06, 0x05, 0x0000, 0x00000000},
    {0x67, 0x01, 0x00, 0x0000, 0x00000038},
    {0xc7, 0x01, 0x00, 0x0000, 0x00000038},
    {0xb7, 0x04, 0x00, 0x0000, 0x00000000},
    {0x6d, 0x04, 0x01, 0x0001, 0x00000000},
    {0xbf, 0x02, 0x03, 0x0000, 0x00000000},
    {0xbf, 0x03, 0x0a, 0x0000, 0x00000000},
    {0x07, 0x03, 0x00, 0x0000, 0xffffff6c},
    {0xbf, 0x05, 0x0a, 0x0000, 0x00000000},
    {0x07, 0x05, 0x00, 0x0000, 0xffffff8c},
    {0x6d, 0x04, 0x01, 0x0001, 0x00000000},
    {0xbf, 0x05, 0x03, 0x0000, 0x00000000},
    {0x71, 0x01, 0x0a, 0xff55, 0x00000000},
    {0x15, 0x01, 0x00, 0x0029, 0x00000000},
    {0xbf, 0x03, 0x05, 0x0000, 0x00000000},
    {0x05, 0x00, 0x00, 0x0027, 0x00000000},
    {0x71, 0x02, 0x0a, 0xff52, 0x00000000},
    {0x15, 0x02, 0x00, 0x0004, 0x00000000},
    {0xbf, 0x02, 0x01, 0x0000, 0x00000000},
    {0x57, 0x02, 0x00, 0x0000, 0x00000004},
    {0x15, 0x02, 0x00, 0x0001, 0x00000000},
    {0x05, 0x00, 0x00, 0xffd1, 0x00000000},
    {0xb7, 0x08, 0x00, 0x0000, 0x00000000},
    {0x57, 0x01, 0x00, 0x0000, 0x00000001},
    {0x15, 0x01, 0x00, 0x0091, 0x00000000},
    {0x61, 0x01, 0x0a, 0xff5c, 0x00000000},
    {0x63, 0x0a, 0x01, 0xffa0, 0x00000000},
    {0x61, 0x01, 0x0a, 0xff60, 0x00000000},
    {0x63, 0x0a, 0x01, 0xffa4, 0x00000000},
    {0x05, 0x00, 0x00, 0x0032, 0x00000000},
    {0x71, 0x02, 0x0a, 0xff52, 0x00000000},
    {0x15, 0x02, 0x00, 0x00a8, 0x00000000},
    {0xbf, 0x02, 0x01, 0x0000, 0x00000000},
    {0x57, 0x02, 0x00, 0x0000, 0x00000020},
    {0x15, 0x02, 0x00, 0x00a5, 0x00000000},
    {0xbf, 0x02, 0x0a, 0x0000, 0x00000000},
    {0x07, 0x02, 0x00, 0x0000, 0xffffff5c},
    {0x71, 0x04, 0x0a, 0xff54, 0x00000000},
    {0xbf, 0x03, 0x02, 0x0000, 0x00000000},
    {0x15, 0x04, 0x00, 0x0002, 0x00000000},
    {0xbf, 0x03, 0x0a, 0x0000, 0x00000000},
    {0x07, 0x03, 0x00, 0x0000, 0xffffff7c},
    {0xbf, 0x06, 0x05, 0x0000, 0x00000000},
    {0x57, 0x01, 0x00, 0x0000, 0x00000100},
    {0x15, 0x01, 0x00, 0x0001, 0x00000000},
    {0xbf, 0x02, 0x03, 0x0000, 0x00000000},
    {0xbf, 0x03, 0x0a, 0x0000, 0x00000000},
    {0x07, 0x03, 0x00, 0x0000, 0xffffff6c},
    {0x71, 0x05, 0x0a, 0xff55, 0x00000000},
    {0xbf, 0x04, 0x03, 0x0000, 0x00000000},
    {0x15, 0x05, 0x00, 0x0002, 0x00000000},
    {0xbf, 0x04, 0x0a, 0x0000, 0x00000000},
    {0x07, 0x04, 0x00, 0x0000, 0xffffff8c},
    {0x15, 0x01, 0x00, 0x0001, 0x00000000},
    {0xbf, 0x03, 0x04, 0x0000, 0x00000000},
    {0x61, 0x01, 0x02, 0x0004, 0x00000000},
    {0x67, 0x01, 0x00, 0x0000, 0x00000020},
    {0x61, 0x04, 0x02, 0x0000, 0x00000000},
    {0x4f, 0x01, 0x04, 0x0000, 0x00000000},
    {0x7b, 0x0a, 0x01, 0xffa0, 0x00000000},
    {0x61, 0x01, 0x02, 0x0008, 0x00000000},
    {0x61, 0x02, 0x02, 0x000c, 0x00000000},
    {0x67, 0x02, 0x00, 0x0000, 0x00000020},
    {0x4f, 0x02, 0x01, 0x0000, 0x00000000},
    {0x7b, 0x0a, 0x02, 0xffa8, 0x00000000},
    {0x61, 0x01, 0x03, 0x0000, 0x00000000},
    {0x61, 0x02, 0x03, 0x0004, 0x00000000},
    {0x61, 0x04, 0x03, 0x0008, 0x00000000},
    {0x61, 0x03, 0x03, 0x000c, 0x00000000},
    {0x69, 0x05, 0x0a, 0xff58, 0x00000000},
    {0x6b, 0x0a, 0x05, 0xffc2, 0x00000000},
    {0x69, 0x05, 0x0a, 0xff56, 0x00000000},
    {0x6b, 0x0a, 0x05, 0xffc0, 0x00000000},
    {0x67, 0x03, 0x00, 0x0000, 0x00000020},
    {0x4f, 0x03, 0x04, 0x0000, 0x00000000},
    {0x7b, 0x0a, 0x03, 0xffb8, 0x00000000},
    {0x67, 0x02, 0x00, 0x0000, 0x00000020},
    {0x4f, 0x02, 0x01, 0x0000, 0x00000000},
    {0x7b, 0x0a, 0x02, 0xffb0, 0x00000000},
    {0xbf, 0x05, 0x06, 0x0000, 0x00000000},
    {0xb7, 0x01, 0x00, 0x0000, 0x00000000},
    {0x07, 0x00, 0x00, 0x0000, 0x00000004},
    {0x61, 0x02, 0x05, 0x0000, 0x00000000},
    {0xb7, 0x04, 0x00, 0x0000, 0x00000000},
    {0xbf, 0x03, 0x0a, 0x0000, 0x00000000},
    {0x07, 0x03, 0x00, 0x0000, 0xffffffa0},
    {0x0f, 0x03, 0x01, 0x0000, 0x00000000},
    {0x71, 0x03, 0x03, 0x0000, 0x00000000},
    {0xbf, 0x08, 0x03, 0x0000, 0x00000000},
    {0x67, 0x08, 0x00, 0x0000, 0x00000038},
    {0xc7, 0x08, 0x00, 0x0000, 0x0000003f},
    {0x5f, 0x08, 0x02, 0x0000, 0x00000000},
    {0xaf, 0x08, 0x04, 0x0000, 0x00000000},
    {0xbf, 0x04, 0x00, 0x0000, 0x00000000},
    {0x0f, 0x04, 0x01, 0x0000, 0x00000000},
    {0x71, 0x04, 0x04, 0x0000, 0x00000000},
    {0x67, 0x02, 0x00, 0x0000, 0x00000001},
    {0xbf, 0x05, 0x04, 0x0000, 0x00000000},
    {0x77, 0x05, 0x00, 0x0000, 0x00000007},
    {0x4f, 0x02, 0x05, 0x0000, 0x00000000},
    {0xbf, 0x05, 0x03, 0x0000, 0x00000000},
    {0x67, 0x05, 0x00, 0x0000, 0x00000039},
    {0xc7, 0x05, 0x00, 0x0000, 0x0000003f},
    {0x5f, 0x05, 0x02, 0x0000, 0x00000000},
    {0xaf, 0x08, 0x05, 0x0000, 0x00000000},
    {0xbf, 0x05, 0x04, 0x0000, 0x00000000},
    {0x77, 0x05, 0x00, 0x0000, 0x00000006},
    {0x57, 0x05, 0x00, 0x0000, 0x00000001},
    {0x67, 0x02, 0x00, 0x0000, 0x00000001},
    {0x4f, 0x02, 0x05, 0x0000, 0x00000000},
    {0xbf, 0x05, 0x03, 0x0000, 0x00000000},
    {0x67, 0x05, 0x00, 0x0000, 0x0000003a},
    {0xc7, 0x05, 0x00, 0x0000, 0x0000003f},
    {0x5f, 0x05, 0x02, 0x0000, 0x00000000},
    {0xaf, 0x08, 0x05, 0x0000, 0x00000000},
    {0x67, 0x02, 0x00, 0x0000, 0x00000001},
    {0xbf, 0x05, 0x04, 0x0000, 0x00000000},
    {0x77, 0x05, 0x00, 0x0000, 0x00000005},
    {0x57, 0x05, 0x00, 0x0000, 0x00000001},
    {0x4f, 0x02, 0x05, 0x0000, 0x00000000},
    {0xbf, 0x05, 0x03, 0x0000, 0x00000000},
    {0x67, 0x05, 0x00, 0x0000, 0x0000003b},
    {0xc7, 0x05, 0x00, 0x0000, 0x0000003f},
    {0x5f, 0x05, 0x02, 0x0000, 0x00000000},
    {0xaf, 0x08, 0x05, 0x0000, 0x00000000},
    {0x67, 0x02, 0x00, 0x0000, 0x00000001},
    {0xbf, 0x05, 0x04, 0x0000, 0x00000000},
    {0x77, 0x05, 0x00, 0x0000, 0x00000004},
    {0x57, 0x05, 0x00, 0x0000, 0x00000001},
    {0x4f, 0x02, 0x05, 0x0000, 0x00000000},
    {0xbf, 0x05, 0x03, 0x0000, 0x00000000},
    {0x67, 0x05, 0x00, 0x0000, 0x0000003c},
    {0xc7, 0x05, 0x00, 0x0000, 0x0000003f},
    {0x5f, 0x05, 0x02, 0x0000, 0x00000000},
    {0xaf, 0x08, 0x05, 0x0000, 0x00000000},
    {0xbf, 0x05, 0x04, 0x0000, 0x00000000},
    {0x77, 0x05, 0x00, 0x0000, 0x00000003},
    {0x57, 0x05, 0x00, 0x0000, 0x00000001},
    {0x67, 0x02, 0x00, 0x0000, 0x00000001},
    {0x4f, 0x02, 0x05, 0x0000, 0x00000000},
    {0xbf, 0x05, 0x03, 0x0000, 0x00000000},
    {0x67, 0x05, 0x00, 0x0000, 0x0000003d},
    {0xc7, 0x05, 0x00, 0x0000, 0x0000003f},
    {0x5f, 0x05, 0x02, 0x0000, 0x00000000},
    {0xaf, 0x08, 0x05, 0x0000, 0x00000000},
    {0xbf, 0x05, 0x04, 0x0000, 0x00000000},
    {0x77, 0x05, 0x00, 0x0000, 0x00000002},
    {0x57, 0x05, 0x00, 0x0000, 0x00000001},
    {0x67, 0x02, 0x00, 0x0000, 0x00000001},
    {0x4f, 0x02, 0x05, 0x0000, 0x00000000},
    {0xbf, 0x05, 0x03, 0x0000, 0x00000000},
    {0x67, 0x05, 0x00, 0x0000, 0x0000003e},
    {0xc7, 0x05, 0x00, 0x0000, 0x0000003f},
    {0x5f, 0x05, 0x02, 0x0000, 0x00000000},
    {0xaf, 0x08, 0x05, 0x0000, 0x00000000},
    {0xbf, 0x05, 0x04, 0x0000, 0x00000000},
    {0x77, 0x05, 0x00, 0x0000, 0x00000001},
    {0x57, 0x05, 0x00, 0x0000, 0x00000001},
    {0x67, 0x02, 0x00, 0x0000, 0x00000001},
    {0x4f, 0x02, 0x05, 0x0000, 0x00000000},
    {0x57, 0x03, 0x00, 0x0000, 0x00000001},
    {0x87, 0x03, 0x00, 0x0000, 0x00000000},
    {0x5f, 0x03, 0x02, 0x0000, 0x00000000},
    {0xaf, 0x08, 0x03, 0x0000, 0x00000000},
    {0x57, 0x04, 0x00, 0x0000, 0x00000001},
    {0x67, 0x02, 0x00, 0x0000, 0x00000001},
    {0x4f, 0x02, 0x04, 0x0000, 0x00000000},
    {0x07, 0x01, 0x00, 0x0000, 0x00000001},
    {0xbf, 0x04, 0x08, 0x0000, 0x00000000},
    {0x55, 0x01, 0x00, 0xffaa, 0x00000024},
    {0x18, 0x01, 0x00, 0x0000, 0x48534148},
    {0x00, 0x00, 0x00, 0x0000, 0x7825203a},
    {0x7b, 0x0a, 0x01, 0xff50, 0x00000000},
    {0xb7, 0x01, 0x00, 0x0000, 0x0000000a},
    {0x6b, 0x0a, 0x01, 0xff58, 0x00000000},
    {0xbf, 0x01, 0x0a, 0x0000, 0x00000000},
    {0x07, 0x01, 0x00, 0x0000, 0xffffff50},
    {0xb7, 0x02, 0x00, 0x0000, 0x0000000a},
    {0xbf, 0x03, 0x08, 0x0000, 0x00000000},
    {0x85, 0x00, 0x00, 0x0000, 0x00000006},
    {0xb7, 0x09, 0x00, 0x0000, 0x00000000},
    {0xbf, 0x01, 0x08, 0x0000, 0x00000000},
    {0x67, 0x01, 0x00, 0x0000, 0x00000020},
    {0x77, 0x01, 0x00, 0x0000, 0x00000020},
    {0x15, 0x01, 0x00, 0x000d, 0x00000000},
    {0x69, 0x02, 0x07, 0x0008, 0x00000000},
    {0x3f, 0x01, 0x02, 0x0000, 0x00000000},
    {0x2f, 0x01, 0x02, 0x0000, 0x00000000},
    {0x1f, 0x08, 0x01, 0x0000, 0x00000000},
    {0x63, 0x0a, 0x08, 0xff50, 0x00000000},
    {0xbf, 0x02, 0x0a, 0x0000, 0x00000000},
    {0x07, 0x02, 0x00, 0x0000, 0xffffff50},
    {0x18, 0x01, 0x00, 0x0000, 0x00000000},
    {0x00, 0x00, 0x00, 0x0000, 0x00000000},
    {0x85, 0x00, 0x00, 0x0000, 0x00000001},
    {0x55, 0x00, 0x00, 0x0001, 0x00000000},
    {0x05, 0x00, 0x00, 0x0001, 0x00000000},
    {0x69, 0x09, 0x00, 0x0000, 0x00000000},
    {0xbf, 0x00, 0x09, 0x0000, 0x00000000},
    {0x95, 0x00, 0x00, 0x0000, 0x00000000},
    {0xbf, 0x02, 0x01, 0x0000, 0x00000000},
    {0x57, 0x02, 0x00, 0x0000, 0x00000008},
    {0x15, 0x02, 0x00, 0xffdf, 0x00000000},
    {0xbf, 0x02, 0x0a, 0x0000, 0x00000000},
    {0x07, 0x02, 0x00, 0x0000, 0xffffff5c},
    {0x71, 0x04, 0x0a, 0xff54, 0x00000000},
    {0xbf, 0x03, 0x02, 0x0000, 0x00000000},
    {0x15, 0x04, 0x00, 0x0002, 0x00000000},
    {0xbf, 0x03, 0x0a, 0x0000, 0x00000000},
    {0x07, 0x03, 0x00, 0x0000, 0xffffff7c},
    {0x57, 0x01, 0x00, 0x0000, 0x00000040},
    {0x15, 0x01, 0x00, 0x0001, 0x00000000},
    {0xbf, 0x02, 0x03, 0x0000, 0x00000000},
    {0x61, 0x03, 0x02, 0x0004, 0x00000000},
    {0x67, 0x03, 0x00, 0x0000, 0x00000020},
    {0x61, 0x04, 0x02, 0x0000, 0x00000000},
    {0x4f, 0x03, 0x04, 0x0000, 0x00000000},
    {0x7b, 0x0a, 0x03, 0xffa0, 0x00000000},
    {0x61, 0x03, 0x02, 0x0008, 0x00000000},
    {0x61, 0x02, 0x02, 0x000c, 0x00000000},
    {0x67, 0x02, 0x00, 0x0000, 0x00000020},
    {0x4f, 0x02, 0x03, 0x0000, 0x00000000},
    {0x7b, 0x0a, 0x02, 0xffa8, 0x00000000},
    {0x15, 0x01, 0x00, 0x0077, 0x00000000},
    {0x71, 0x01, 0x0a, 0xff55, 0x00000000},
    {0x15, 0x01, 0x00, 0x0075, 0x00000000},
    {0x61, 0x01, 0x0a, 0xff98, 0x00000000},
    {0x67, 0x01, 0x00, 0x0000, 0x00000020},
    {0x61, 0x02, 0x0a, 0xff94, 0x00000000},
    {0x4f, 0x01, 0x02, 0x0000, 0x00000000},
    {0x7b, 0x0a, 0x01, 0xffb8, 0x00000000},
    {0x61, 0x01, 0x0a, 0xff90, 0x00000000},
    {0x67, 0x01, 0x00, 0x0000, 0x00000020},
    {0x61, 0x02, 0x0a, 0xff8c, 0x00000000},
    {0x05, 0x00, 0x00, 0x0074, 0x00000000},
    {0x15, 0x06, 0x00, 0xfed3, 0x00000087},
    {0x05, 0x00, 0x00, 0x003f, 0x00000000},
    {0x0f, 0x06, 0x09, 0x0000, 0x00000000},
    {0xbf, 0x02, 0x06, 0x0000, 0x00000000},
    {0x07, 0x02, 0x00, 0x0000, 0x00000001},
    {0x71, 0x03, 0x0a, 0xffff, 0x00000000},
    {0x67, 0x03, 0x00, 0x0000, 0x00000003},
    {0x3d, 0x02, 0x03, 0x0022, 0x00000000},
    {0x55, 0x01, 0x00, 0x000c, 0x000000c9},
    {0x79, 0x01, 0x0a, 0xff40, 0x00000000},
    {0x0f, 0x06, 0x01, 0x0000, 0x00000000},
    {0x07, 0x06, 0x00, 0x0000, 0x00000002},
    {0xbf, 0x01, 0x07, 0x0000, 0x00000000},
    {0xbf, 0x02, 0x06, 0x0000, 0x00000000},
    {0x79, 0x03, 0x0a, 0xff18, 0x00000000},
    {0xb7, 0x04, 0x00, 0x0000, 0x00000001},
    {0xb7, 0x05, 0x00, 0x0000, 0x00000001},
    {0x85, 0x00, 0x00, 0x0000, 0x00000044},
    {0xb7, 0x01, 0x00, 0x0000, 0x00000001},
    {0x73, 0x0a, 0x01, 0xff54, 0x00000000},
    {0x05, 0x00, 0x00, 0x0015, 0x00000000},
    {0x07, 0x08, 0x00, 0x0000, 0xffffffff},
    {0xbf, 0x01, 0x08, 0x0000, 0x00000000},
    {0x67, 0x01, 0x00, 0x0000, 0x00000020},
    {0x77, 0x01, 0x00, 0x0000, 0x00000020},
    {0xbf, 0x09, 0x06, 0x0000, 0x00000000},
    {0x15, 0x01, 0x00, 0x000f, 0x00000000},
    {0xbf, 0x02, 0x09, 0x0000, 0x00000000},
    {0x79, 0x01, 0x0a, 0xff40, 0x00000000},
    {0x0f, 0x02, 0x01, 0x0000, 0x00000000},
    {0xbf, 0x03, 0x0a, 0x0000, 0x00000000},
    {0x07, 0x03, 0x00, 0x0000, 0xfffffff8},
    {0xb7, 0x06, 0x00, 0x0000, 0x00000001},
    {0xbf, 0x01, 0x07, 0x0000, 0x00000000},
    {0xb7, 0x04, 0x00, 0x0000, 0x00000002},
    {0xb7, 0x05, 0x00, 0x0000, 0x00000001},
    {0x85, 0x00, 0x00, 0x0000, 0x00000044},
    {0x71, 0x01, 0x0a, 0xfff8, 0x00000000},
    {0x15, 0x01, 0x00, 0xffdb, 0x00000000},
    {0x71, 0x06, 0x0a, 0xfff9, 0x00000000},
    {0x07, 0x06, 0x00, 0x0000, 0x00000002},
    {0x05, 0x00, 0x00, 0xffd8, 0x00000000},
    {0xbf, 0x08, 0x07, 0x0000, 0x00000000},
    {0xb7, 0x09, 0x00, 0x0000, 0x00000000},
    {0x18, 0x07, 0x00, 0x0000, 0x00000001},
    {0x00, 0x00, 0x00, 0x0000, 0x1c001800},
    {0x71, 0x01, 0x0a, 0xffff, 0x00000000},
    {0x67, 0x01, 0x00, 0x0000, 0x00000003},
    {0x79, 0x02, 0x0a, 0xff40, 0x00000000},
    {0x0f, 0x02, 0x01, 0x0000, 0x00000000},
    {0x07, 0x02, 0x00, 0x0000, 0x00000008},
    {0x7b, 0x0a, 0x02, 0xff40, 0x00000000},
    {0x71, 0x06, 0x0a, 0xfffe, 0x00000000},
    {0x25, 0x06, 0x00, 0x0034, 0x0000003c},
    {0xb7, 0x01, 0x00, 0x0000, 0x00000001},
    {0x6f, 0x01, 0x06, 0x0000, 0x00000000},
    {0x5f, 0x01, 0x07, 0x0000, 0x00000000},
    {0x55, 0x01, 0x00, 0x0001, 0x00000000},
    {0x05, 0x00, 0x00, 0x002f, 0x00000000},
    {0x79, 0x01, 0x0a, 0xff38, 0x00000000},
    {0x07, 0x01, 0x00, 0x0000, 0x00000001},
    {0x7b, 0x0a, 0x01, 0xff38, 0x00000000},
    {0x67, 0x01, 0x00, 0x0000, 0x00000020},
    {0x77, 0x01, 0x00, 0x0000, 0x00000020},
    {0x55, 0x01, 0x00, 0x0002, 0x0000000b},
    {0x79, 0x07, 0x0a, 0xff10, 0x00000000},
    {0x05, 0x00, 0x00, 0xfe4a, 0x00000000},
    {0xbf, 0x03, 0x0a, 0x0000, 0x00000000},
    {0x07, 0x03, 0x00, 0x0000, 0xfffffffe},
    {0xbf, 0x01, 0x08, 0x0000, 0x00000000},
    {0x79, 0x02, 0x0a, 0xff40, 0x00000000},
    {0xb7, 0x04, 0x00, 0x0000, 0x00000002},
    {0xb7, 0x05, 0x00, 0x0000, 0x00000001},
    {0x85, 0x00, 0x00, 0x0000, 0x00000044},
    {0xbf, 0x01, 0x06, 0x0000, 0x00000000},
    {0x15, 0x01, 0x00, 0x0019, 0x0000003c},
    {0x55, 0x01, 0x00, 0xffe1, 0x0000002b},
    {0x63, 0x0a, 0x09, 0xfff8, 0x00000000},
    {0xbf, 0x03, 0x0a, 0x0000, 0x00000000},
    {0x07, 0x03, 0x00, 0x0000, 0xfffffff8},
    {0xbf, 0x01, 0x08, 0x0000, 0x00000000},
    {0x79, 0x02, 0x0a, 0xff40, 0x00000000},
    {0xb7, 0x04, 0x00, 0x0000, 0x00000004},
    {0xb7, 0x05, 0x00, 0x0000, 0x00000001},
    {0x85, 0x00, 0x00, 0x0000, 0x00000044},
    {0xb7, 0x01, 0x00, 0x0000, 0x00000002},
    {0x73, 0x0a, 0x01, 0xfffa, 0x00000000},
    {0x71, 0x01, 0x0a, 0xfff9, 0x00000000},
    {0x55, 0x01, 0x00, 0xffd5, 0x00000002},
    {0x71, 0x01, 0x0a, 0xfffb, 0x00000000},
    {0x55, 0x01, 0x00, 0xffd3, 0x00000001},
    {0x79, 0x02, 0x0a, 0xff40, 0x00000000},
    {0x07, 0x02, 0x00, 0x0000, 0x00000008},
    {0xbf, 0x01, 0x08, 0x0000, 0x00000000},
    {0x79, 0x03, 0x0a, 0xff20, 0x00000000},
    {0xb7, 0x04, 0x00, 0x0000, 0x00000010},
    {0xb7, 0x05, 0x00, 0x0000, 0x00000001},
    {0x85, 0x00, 0x00, 0x0000, 0x00000044},
    {0xb7, 0x01, 0x00, 0x0000, 0x00000001},
    {0x73, 0x0a, 0x01, 0xff55, 0x00000000},
    {0x05, 0x00, 0x00, 0xffc9, 0x00000000},
    {0xbf, 0x07, 0x08, 0x0000, 0x00000000},
    {0x6b, 0x0a, 0x09, 0xfff8, 0x00000000},
    {0xb7, 0x09, 0x00, 0x0000, 0x00000002},
    {0xb7, 0x08, 0x00, 0x0000, 0x0000001e},
    {0x05, 0x00, 0x00, 0xffb1, 0x00000000},
    {0x15, 0x06, 0x00, 0xffd0, 0x00000087},
    {0x05, 0x00, 0x00, 0xffd5, 0x00000000},
    {0x61, 0x01, 0x0a, 0xff78, 0x00000000},
    {0x67, 0x01, 0x00, 0x0000, 0x00000020},
    {0x61, 0x02, 0x0a, 0xff74, 0x00000000},
    {0x4f, 0x01, 0x02, 0x0000, 0x00000000},
    {0x7b, 0x0a, 0x01, 0xffb8, 0x00000000},
    {0x61, 0x01, 0x0a, 0xff70, 0x00000000},
    {0x67, 0x01, 0x00, 0x0000, 0x00000020},
    {0x61, 0x02, 0x0a, 0xff6c, 0x00000000},
    {0x4f, 0x01, 0x02, 0x0000, 0x00000000},
    {0x7b, 0x0a, 0x01, 0xffb0, 0x00000000},
    {0x05, 0x00, 0x00, 0xfeee, 0x00000000},
};

struct fixup_mapfd_t reltun_rss_steering[] = {
    {"tap_rss_map_configurations", 5},
    {"tap_rss_map_toeplitz_key", 10},
    {"tap_rss_map_indirection_table", 390},
};

#endif /* TUN_RSS_STEERING */
