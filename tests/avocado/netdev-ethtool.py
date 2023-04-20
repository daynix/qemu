# ethtool tests for emulated network devices
#
# This test leverages ethtool's --test sequence to validate network
# device behaviour.
#
# SPDX-License-Identifier: GPL-2.0-or-late

from avocado import skip
from avocado.utils.iso9660 import ISO9660PyCDLib
from avocado_qemu import LinuxTest
from avocado_qemu import wait_for_console_pattern
import os

class NetDevEthtool(LinuxTest):
    """
    :avocado: tags=arch:x86_64
    :avocado: tags=machine:q35
    :avocado: tags=distro:fedora
    :avocado: tags=distro_version:38
    """

    # Runs in about 17s under KVM, 19s under TCG, 25s under GCOV
    timeout = 45

    def common_test_code(self, netdev, extra_args=None):
        ethtool_url = 'https://dl.fedoraproject.org/pub/fedora/linux/releases/38/Everything/x86_64/os/Packages/e/ethtool-6.2-1.fc38.x86_64.rpm'
        ethtool_hash = '72c0123b8966371fa93fb1fa1839ec34139d0b48'
        ethtool = self.fetch_asset(ethtool_url, asset_hash=ethtool_hash)

        kernel_url = 'http://dl.fedoraproject.org/pub/fedora/linux/releases/38/Server/x86_64/os/images/pxeboot/vmlinuz'
        kernel_hash = '5cf10eaae2cc64d9c17d0128df05c1a9d98e221a'
        kernel = self.fetch_asset(kernel_url, asset_hash=kernel_hash)

        append = 'root=PARTUUID=c310a368-941b-4830-bdf2-5f7ebbced630 rw rootflags=subvol=root no_timer_check net.ifnames=0 console=tty1 console=ttyS0,115200n8'

        # any additional kernel tweaks for the test
        if extra_args:
            append += extra_args

        # finally invoke ethtool directly
        append += ' init=/bin/sh -- -c "/sbin/modprobe igb && mount -o ro /dev/sr0 /mnt && rpm -i /mnt/ethtool.rpm && /sbin/ethtool -t eth0 offline"'

        ethtool_iso = os.path.join(self.workdir, 'ethtool.iso')
        cd = ISO9660PyCDLib(ethtool_iso)
        cd.create()
        with open(ethtool, 'rb') as ethtool_file:
            cd.write("ethtool.rpm", ethtool_file.read())
        cd.close()

        self.vm.add_args('-kernel', kernel,
                         '-append', append,
                         '-drive', f"file={ethtool_iso},format=raw,media=cdrom",
                         '-device', netdev)

        self.vm.set_console(console_index=0)
        self.vm.launch()

        wait_for_console_pattern(self,
                                 "The test result is PASS",
                                 "The test result is FAIL",
                                 vm=None)
        # no need to gracefully shutdown, just finish
        self.vm.kill()

    def test_igb(self):
        """
        :avocado: tags=device:igb
        """
        self.common_test_code("igb")

    def test_igb_nomsi(self):
        """
        :avocado: tags=device:igb
        """
        self.common_test_code("igb", "pci=nomsi")

    # It seems the other popular cards we model in QEMU currently fail
    # the pattern test with:
    #
    #   pattern test failed (reg 0x00178): got 0x00000000 expected 0x00005A5A
    #
    # So for now we skip them.

    @skip("Incomplete reg 0x00178 support")
    def test_e1000(self):
        """
        :avocado: tags=device:e1000
        """
        self.common_test_code("e1000")

    @skip("Incomplete reg 0x00178 support")
    def test_i82550(self):
        """
        :avocado: tags=device:i82550
        """
        self.common_test_code("i82550")
