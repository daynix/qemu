/*******************************************************************************

  Intel PRO/1000 Linux driver
  Copyright(c) 1999 - 2006 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, see <http://www.gnu.org/licenses/>.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  Linux NICS <linux.nics@intel.com>
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

/* e1000_hw.h
 * Structures, enums, and macros for the MAC
 */

#ifndef HW_E1000_REGS_H
#define HW_E1000_REGS_H

#include "e1000x_regs.h"
#define E1000_EIAC     0x000DC  /* Ext. Interrupt Auto Clear - RW */
#define E1000_IVAR     0x000E4  /* Interrupt Vector Allocation Register - RW */
#define E1000_EITR     0x000E8  /* Extended Interrupt Throttling Rate - RW */
#define E1000_RDTR1    0x02820  /* RX Delay Timer (1) - RW */
#define E1000_RDBAL1   0x02900  /* RX Descriptor Base Address Low (1) - RW */
#define E1000_RDBAH1   0x02904  /* RX Descriptor Base Address High (1) - RW */
#define E1000_RDLEN1   0x02908  /* RX Descriptor Length (1) - RW */
#define E1000_RDH1     0x02910  /* RX Descriptor Head (1) - RW */
#define E1000_RDT1     0x02918  /* RX Descriptor Tail (1) - RW */
#define E1000_RDBAL    0x02800  /* RX Descriptor Base Address Low - RW */
#define E1000_RDBAH    0x02804  /* RX Descriptor Base Address High - RW */
#define E1000_RDLEN    0x02808  /* RX Descriptor Length - RW */
#define E1000_RDH      0x02810  /* RX Descriptor Head - RW */
#define E1000_RDT      0x02818  /* RX Descriptor Tail - RW */
#define E1000_RDTR     0x02820  /* RX Delay Timer - RW */
#define E1000_RDTR_A   0x00108  /* Alias to RDTR */
#define E1000_RDBAL0   E1000_RDBAL /* RX Desc Base Address Low (0) - RW */
#define E1000_RDBAL0_A 0x00110     /* Alias to RDBAL0 */
#define E1000_RDBAH0   E1000_RDBAH /* RX Desc Base Address High (0) - RW */
#define E1000_RDBAH0_A 0x00114     /* Alias to RDBAH0 */
#define E1000_RDLEN0   E1000_RDLEN /* RX Desc Length (0) - RW */
#define E1000_RDLEN0_A 0x00118     /* Alias to RDLEN0 */
#define E1000_RDH0     E1000_RDH   /* RX Desc Head (0) - RW */
#define E1000_RDH0_A   0x00120     /* Alias to RDH0 */
#define E1000_RDT0     E1000_RDT   /* RX Desc Tail (0) - RW */
#define E1000_RDT0_A   0x00128     /* Alias to RDT0 */
#define E1000_RDTR0    E1000_RDTR  /* RX Delay Timer (0) - RW */
#define E1000_RXDCTL   0x02828  /* RX Descriptor Control queue 0 - RW */
#define E1000_RXDCTL1  0x02928  /* RX Descriptor Control queue 1 - RW */
#define E1000_RADV     0x0282C  /* RX Interrupt Absolute Delay Timer - RW */
#define E1000_RSRPD    0x02C00  /* RX Small Packet Detect - RW */
#define E1000_RAID     0x02C08  /* Receive Ack Interrupt Delay - RW */
#define E1000_TDBAL    0x03800  /* TX Descriptor Base Address Low - RW */
#define E1000_TDBAL_A  0x00420  /* Alias to TDBAL */
#define E1000_TDBAH    0x03804  /* TX Descriptor Base Address High - RW */
#define E1000_TDBAH_A  0x00424  /* Alias to TDBAH */
#define E1000_TDLEN    0x03808  /* TX Descriptor Length - RW */
#define E1000_TDLEN_A  0x00428  /* Alias to TDLEN */
#define E1000_TDH      0x03810  /* TX Descriptor Head - RW */
#define E1000_TDH_A    0x00430  /* Alias to TDH */
#define E1000_TDT      0x03818  /* TX Descripotr Tail - RW */
#define E1000_TDT_A    0x00438  /* Alias to TDT */
#define E1000_TIDV     0x03820  /* TX Interrupt Delay Value - RW */
#define E1000_TIDV_A   0x00440  /* Alias to TIDV */
#define E1000_TXDCTL   0x03828  /* TX Descriptor Control - RW */
#define E1000_TADV     0x0382C  /* TX Interrupt Absolute Delay Val - RW */
#define E1000_TDBAL1   0x03900  /* TX Desc Base Address Low (1) - RW */
#define E1000_TDBAH1   0x03904  /* TX Desc Base Address High (1) - RW */
#define E1000_TDLEN1   0x03908  /* TX Desc Length (1) - RW */
#define E1000_TDH1     0x03910  /* TX Desc Head (1) - RW */
#define E1000_TDT1     0x03918  /* TX Desc Tail (1) - RW */
#define E1000_TXDCTL1  0x03928  /* TX Descriptor Control (1) - RW */
#define E1000_ICRXOC   0x04124  /* Interrupt Cause Receiver Overrun Count */
#define E1000_RA       0x05400  /* Receive Address - RW Array */
#define E1000_RA_A     0x00040  /* Alias to RA */

#define E1000_RSS_QUEUE(reta, hash) ((E1000_RETA_VAL(reta, hash) & BIT(7)) >> 7)

#define E1000_XDBAL_MASK            (~(BIT(4) - 1))

#define E1000_RFCTL_ACK_DIS             0x00001000
#define E1000_RFCTL_ACK_DATA_DIS        0x00002000

#define E1000_CTRL_EXT_DRV_LOAD 0x10000000 /* Driver loaded bit for FW */

#define E1000_STATUS_FUNC_MASK  0x0000000C      /* PCI Function Mask */
#define E1000_STATUS_FUNC_SHIFT 2
#define E1000_STATUS_FUNC_0     0x00000000      /* Function 0 */
#define E1000_STATUS_FUNC_1     0x00000004      /* Function 1 */
#define E1000_STATUS_TXOFF      0x00000010      /* transmission paused */
#define E1000_STATUS_TBIMODE    0x00000020      /* TBI mode */
#define E1000_STATUS_SPEED_MASK 0x000000C0
#define E1000_STATUS_LAN_INIT_DONE 0x00000200   /* Lan Init Completion
                                                   by EEPROM/Flash */
#define E1000_STATUS_ASDV       0x00000300      /* Auto speed detect value */
#define E1000_STATUS_ASDV_10    0x00000000      /* ASDV 10Mb */
#define E1000_STATUS_ASDV_100   0x00000100      /* ASDV 100Mb */
#define E1000_STATUS_ASDV_1000  0x00000200      /* ASDV 1Gb */
#define E1000_STATUS_DOCK_CI    0x00000800      /* Change in Dock/Undock state. Clear on write '0'. */
#define E1000_STATUS_MTXCKOK    0x00000400      /* MTX clock running OK */
#define E1000_STATUS_PCI66      0x00000800      /* In 66Mhz slot */
#define E1000_STATUS_BUS64      0x00001000      /* In 64 bit slot */
#define E1000_STATUS_PCIX_MODE  0x00002000      /* PCI-X mode */
#define E1000_STATUS_PCIX_SPEED 0x0000C000      /* PCI-X bus speed */
#define E1000_STATUS_BMC_SKU_0  0x00100000 /* BMC USB redirect disabled */
#define E1000_STATUS_BMC_SKU_1  0x00200000 /* BMC SRAM disabled */
#define E1000_STATUS_BMC_SKU_2  0x00400000 /* BMC SDRAM disabled */
#define E1000_STATUS_BMC_CRYPTO 0x00800000 /* BMC crypto disabled */
#define E1000_STATUS_BMC_LITE   0x01000000 /* BMC external code execution disabled */
#define E1000_STATUS_RGMII_ENABLE 0x02000000 /* RGMII disabled */
#define E1000_STATUS_FUSE_8       0x04000000
#define E1000_STATUS_FUSE_9       0x08000000
#define E1000_STATUS_SERDES0_DIS  0x10000000 /* SERDES disabled on port 0 */
#define E1000_STATUS_SERDES1_DIS  0x20000000 /* SERDES disabled on port 1 */
#define E1000_STATUS_SPEED_SHIFT  6
#define E1000_STATUS_ASDV_SHIFT   8

/* Transmit Descriptor */
struct e1000_tx_desc {
    uint64_t buffer_addr;       /* Address of the descriptor's data buffer */
    union {
        uint32_t data;
        struct {
            uint16_t length;    /* Data buffer length */
            uint8_t cso;        /* Checksum offset */
            uint8_t cmd;        /* Descriptor control */
        } flags;
    } lower;
    union {
        uint32_t data;
        struct {
            uint8_t status;     /* Descriptor status */
            uint8_t css;        /* Checksum start */
            uint16_t special;
        } fields;
    } upper;
};

#define E1000_TXD_POPTS_IXSM 0x01       /* Insert IP checksum */
#define E1000_TXD_POPTS_TXSM 0x02       /* Insert TCP/UDP checksum */

#endif /* HW_E1000_REGS_H */
