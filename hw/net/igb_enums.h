/*
* QEMU e1000(e) emulation - shared code
*
* Copyright (c) 2008 Qumranet
*
* Based on work done by:
* Nir Peleg, Tutis Systems Ltd. for Qumranet Inc.
* Copyright (c) 2007 Dan Aloni
* Copyright (c) 2004 Antony T Curtis
*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public
* License as published by the Free Software Foundation; either
* version 2.1 of the License, or (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef HW_NET_IGB_ENUMS_H
#define HW_NET_IGB_ENUMS_H

#include "igb_regs.h"

#define defreg(x) x = (E1000_##x >> 2)
#define defreg_indexed(x, i) x##i = (E1000_##x(i) >> 2)

#define defregd(x) defreg_indexed(x, 0), defreg_indexed(x, 1), \
                   defreg_indexed(x, 2), defreg_indexed(x, 3), \
                   defreg_indexed(x, 4), defreg_indexed(x, 5), \
                   defreg_indexed(x, 6), defreg_indexed(x, 7), \
                   defreg_indexed(x, 8), defreg_indexed(x, 9), \
                   defreg_indexed(x, 10), defreg_indexed(x, 11), \
                   defreg_indexed(x, 12), defreg_indexed(x, 13), \
                   defreg_indexed(x, 14), defreg_indexed(x, 15)

#define defregv(x) defreg_indexed(x, 0), defreg_indexed(x, 1), \
                   defreg_indexed(x, 2), defreg_indexed(x, 3), \
                   defreg_indexed(x, 4), defreg_indexed(x, 5), \
                   defreg_indexed(x, 6), defreg_indexed(x, 7)

enum {
    defreg(CTRL),    defreg(EECD),    defreg(EERD),    defreg(GPRC),
    defreg(GPTC),    defreg(ICR),     defreg(ICS),     defreg(IMC),
    defreg(IMS),     defreg(LEDCTL),  defreg(MANC),    defreg(MDIC),
    defreg(MPC),     defreg(PBA),     defreg(RCTL),
    defreg(STATUS),  defreg(SWSM),    defreg(TCTL),
    defreg(TORH),    defreg(TORL),    defreg(TOTH),
    defreg(TOTL),    defreg(TPR),     defreg(TPT),
    defreg(WUFC),    defreg(RA),      defreg(MTA),     defreg(CRCERRS),
    defreg(VFTA),    defreg(VET),
    defreg(ITR),     defreg(SCC),     defreg(ECOL),
    defreg(MCC),     defreg(LATECOL), defreg(COLC),    defreg(DC),
    defreg(TNCRS),   defreg(SEQEC),   defreg(CEXTERR), defreg(RLEC),
    defreg(XONRXC),  defreg(XONTXC),  defreg(XOFFRXC), defreg(XOFFTXC),
    defreg(FCRUC),   defreg(AIT),     defreg(TDFH),    defreg(TDFT),
    defreg(TDFHS),   defreg(TDFTS),   defreg(TDFPC),   defreg(WUC),
    defreg(WUS),     defreg(POEMB),   defreg(PBS),     defreg(RDFH),
    defreg(RDFT),    defreg(RDFHS),   defreg(RDFTS),   defreg(RDFPC),
    defreg(PBM),     defreg(IPAV),    defreg(IP4AT),   defreg(IP6AT),
    defreg(WUPM),    defreg(FFLT),    defreg(FFMT),    defreg(FFVT),
    defreg(TARC0),   defreg(TARC1),   defreg(IAM),     defreg(EXTCNF_CTRL),
    defreg(GCR),     defreg(TIMINCA), defreg(EIAC),    defreg(CTRL_EXT),
    defreg(IVAR0),   defreg(MFUTP01), defreg(MFUTP23), defreg(MANC2H),
    defreg(MFVAL),   defreg(MDEF),    defreg(FACTPS),  defreg(FTFT),
    defreg(RUC),     defreg(ROC),     defreg(RFC),     defreg(RJC),
    defreg(PRC64),   defreg(PRC127),  defreg(PRC255),  defreg(PRC511),
    defreg(PRC1023), defreg(PRC1522), defreg(PTC64),   defreg(PTC127),
    defreg(PTC255),  defreg(PTC511),  defreg(PTC1023), defreg(PTC1522),
    defreg(GORCL),   defreg(GORCH),   defreg(GOTCL),   defreg(GOTCH),
    defreg(RNBC),    defreg(BPRC),    defreg(MPRC),    defreg(RFCTL),
    defreg(PSRCTL),  defreg(MPTC),    defreg(BPTC),    defreg(TSCTFC),
    defreg(IAC),     defreg(MGTPRC),  defreg(MGTPDC),  defreg(MGTPTC),
    defreg(TSCTC),   defreg(RXCSUM),  defreg(FUNCTAG), defreg(GSCL_1),
    defreg(GSCL_2),  defreg(GSCL_3),  defreg(GSCL_4),  defreg(GSCN_0),
    defreg(GSCN_1),  defreg(GSCN_2),  defreg(GSCN_3),  defreg(GCR2),
    defreg_indexed(EITR, 0),
    defreg(MRQC),    defreg(RETA),    defreg(RSSRK),
    defreg(PBACLR),  defreg(FCAL),    defreg(FCAH),    defreg(FCT),
    defreg(FCRTH),   defreg(FCRTL),   defreg(FCTTV),   defreg(FCRTV),
    defreg(FLA),     defreg(EEWR),    defreg(FLOP),    defreg(FLOL),
    defreg(FLSWCTL), defreg(FLSWCNT),
    defreg(MAVTV0),  defreg(MAVTV1),  defreg(MAVTV2),  defreg(MAVTV3),
    defreg(TXSTMPL), defreg(TXSTMPH), defreg(SYSTIML), defreg(SYSTIMH),
    defreg(RXCFGL),  defreg(RXUDP),   defreg(TIMADJL), defreg(TIMADJH),
    defreg(RXSTMPH), defreg(RXSTMPL), defreg(RXSATRL), defreg(RXSATRH),
    defreg(FLASHT),  defreg(TIPG),
    defreg(FLSWDATA),
    defreg(CTRL_DUP),
    defreg(EXTCNF_SIZE),
    defreg(EEMNGCTL),
    defreg(EEMNGDATA),
    defreg(FLMNGCTL),
    defreg(FLMNGDATA),
    defreg(FLMNGCNT),
    defreg(TSYNCRXCTL),
    defreg(TSYNCTXCTL),
    defreg(RLPML),
    defreg(UTA),

    /* Aliases */
    defreg(RDFH_A),
    defreg(RDFT_A),
    defreg(TDFH_A),  defreg(TDFT_A),  defreg(RA_ALT),
    defreg(VFTA_A),
    defreg(FCRTL_A), defreg(FCRTH_A),

    /* Additional regs used by IGB */
    defreg(FWSM),   defreg(SW_FW_SYNC), defreg(HTCBDPC), defreg(GPIE),
    defreg(EICR),   defreg(EICS),       defreg(EIMS),    defreg(EIAM),
    defreg(EIMC),   defreg(TXPBS),      defreg(TCTL_EXT),
    defreg(DTXCTL), defreg(RXPBS),      defreg_indexed(RQDPC, 0), defreg(RA2),

    defregd(RDBAL), defregd(RDBAH), defregd(RDLEN), defregd(SRRCTL),
    defregd(RDH), defregd(RDT), defregd(RXDCTL),

    defregd(TDBAL), defregd(TDBAH), defregd(TDLEN), defregd(TDH),
    defregd(TDT), defregd(TXDCTL), defregd(TXCTL),

    defregv(P2VMAILBOX),      defregv(V2PMAILBOX), defreg(MBVFICR), defregv(VMBMEM),
    defreg(MBVFIMR),          defreg(VFLRE),  defreg(VFRE),   defreg(VFTE),
    defreg(QDE),              defreg(DTXSWC), defreg(WVBR),
    defreg_indexed(VMVIR, 0), defreg_indexed(VMOLR, 0),
    defreg(RPLOLR), defreg_indexed(VLVF, 0),

    defregv(PVTCTRL), defregv(PVTEICS), defregv(PVTEIMS), defregv(PVTEIMC),
    defregv(PVTEIAC), defregv(PVTEIAM), defregv(PVTEICR), defregv(PVFGPRC),
    defregv(PVFGPTC), defregv(PVFGORC), defregv(PVFGOTC), defregv(PVFMPRC),
    defregv(PVFGPRLBC),  defregv(PVFGPTLBC), defregv(PVFGORLBC), defregv(PVFGOTLBC),

    defreg(IVAR_MISC),  defreg(VTIVAR), defreg(VTIVAR_MISC),

    defreg(CTRL_ALT),
    defreg(ICR_ALT),
    defreg(ICS_ALT),
    defreg(IMS_ALT),
    defreg(IMC_ALT),
    defreg(IAM_ALT),
    defreg(FCRTL_ALT),
    defreg(RDBAL0_ALT),
    defreg(RDBAH0_ALT),
    defreg(RDLEN0_ALT),
    defreg(SRRCTL0_ALT),
    defreg(RDH0_ALT),
    defreg(RDT0_ALT),
    defreg(RXDCTL0_ALT),
    defreg(RXCTL0_ALT),
    defreg(RQDPC0_ALT),
    defreg(RDBAL1_ALT),
    defreg(RDBAL2_ALT),
    defreg(RDBAL3_ALT),
    defreg(RDBAH1_ALT),
    defreg(RDBAH2_ALT),
    defreg(RDBAH3_ALT),
    defreg(RDLEN1_ALT),
    defreg(RDLEN2_ALT),
    defreg(RDLEN3_ALT),
    defreg(SRRCTL1_ALT),
    defreg(SRRCTL2_ALT),
    defreg(SRRCTL3_ALT),
    defreg(RDH1_ALT),
    defreg(RDH2_ALT),
    defreg(RDH3_ALT),
    defreg(RDT1_ALT),
    defreg(RDT2_ALT),
    defreg(RDT3_ALT),
    defreg(RXDCTL1_ALT),
    defreg(RXDCTL2_ALT),
    defreg(RXDCTL3_ALT),
    defreg(RXCTL1_ALT),
    defreg(RXCTL2_ALT),
    defreg(RXCTL3_ALT),
    defreg(RQDPC1_ALT),
    defreg(RQDPC2_ALT),
    defreg(RQDPC3_ALT),
    defreg(MTA_ALT),
    defreg(VFTA_ALT),
    defreg(TDBAL0_ALT),
    defreg(TDBAH0_ALT),
    defreg(TDLEN0_ALT),
    defreg(TDH0_ALT),
    defreg(TDT0_ALT),
    defreg(TXCTL0_ALT),
    defreg(TDWBAL0_ALT),
    defreg(TDWBAH0_ALT),
    defreg(TDBAL1_ALT),
    defreg(TDBAL2_ALT),
    defreg(TDBAL3_ALT),
    defreg(TDBAH1_ALT),
    defreg(TDBAH2_ALT),
    defreg(TDBAH3_ALT),
    defreg(TDLEN1_ALT),
    defreg(TDLEN2_ALT),
    defreg(TDLEN3_ALT),
    defreg(TDH1_ALT),
    defreg(TDH2_ALT),
    defreg(TDH3_ALT),
    defreg(TDT1_ALT),
    defreg(TDT2_ALT),
    defreg(TDT3_ALT),
    defreg(TXDCTL0_ALT),
    defreg(TXDCTL1_ALT),
    defreg(TXDCTL2_ALT),
    defreg(TXDCTL3_ALT),
    defreg(TXCTL1_ALT),
    defreg(TXCTL2_ALT),
    defreg(TXCTL3_ALT),
    defreg(TDWBAL1_ALT),
    defreg(TDWBAL2_ALT),
    defreg(TDWBAL3_ALT),
    defreg(TDWBAH1_ALT),
    defreg(TDWBAH2_ALT),
    defreg(TDWBAH3_ALT),
};

#endif
