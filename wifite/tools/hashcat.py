#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
wifite/tools/hashcat.py — V3
Wrappers for hashcat, hcxdumptool, and hcxpcapngtool.

V3 Changes:
- HcxPcapTool now uses hcxpcapngtool (replaces obsolete hcxpcaptool)
- Hash format migrated from 16800 to 22000 (hc22000)
- Hashcat cracking uses -m 22000 for both WPA handshake and PMKID
- hcxdumptool uses modern --filterlist_ap flag (hcxdumptool >= 6.0)
"""

from .dependency import Dependency
from ..config import Configuration
from ..util.process import Process
from ..util.color import Color

import os


class Hashcat(Dependency):
    dependency_required = False
    dependency_name = 'hashcat'
    dependency_url = 'https://hashcat.net/hashcat/'

    @staticmethod
    def should_use_force():
        """Returns True if hashcat needs --force flag (no GPU detected)."""
        command = ['hashcat', '-I']
        stdout, stderr = Process(command).get_output()
        output = stdout + stderr
        return 'No devices found/left' in output

    @staticmethod
    def get_optimum_workload():
        """
        Parses device query output to determine if openCL/CUDA acceleration is present.
        Returns workload profile arguments like ['-w', '3'] if GPU exists, else empty list.
        """
        command = ['hashcat', '-I']
        stdout, stderr = Process(command).get_output()
        output = stdout + stderr
        if any(dev in output.lower() for dev in ('cuda', 'opencl', 'nvidia', 'amd', 'radeon', 'intel(r)')):
            return ['-w', '3']
        return []

    @staticmethod
    def crack_handshake(handshake, show_command=False):
        """
        Cracks a WPA handshake using hashcat mode 22000.
        V3: Uses hcxpcapngtool to generate .hc22000 file (replaces .hccapx / mode 2500).

        Args:
            handshake - Handshake model instance with capfile path.
            show_command - If True, print the hashcat command before running.
        Returns:
            Cracked key (str) if successful, None otherwise.
        """
        hc22000_file = HcxPcapTool.generate_hc22000_file(
            handshake, show_command=show_command)

        if hc22000_file is None:
            return None

        key = None
        # Run hashcat, then --show to catch previously cracked passwords
        for additional_arg in ([], ['--show']):
            command = [
                'hashcat',
                '--quiet',
                '-m', '22000',   # V3: WPA-PBKDF2-PMKID+EAPOL (unified)
                hc22000_file,
                Configuration.wordlist
            ]
            command.extend(Hashcat.get_optimum_workload())
            if Hashcat.should_use_force():
                command.append('--force')
            command.extend(additional_arg)
            if show_command:
                Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))
            process = Process(command)
            stdout, stderr = process.get_output()
            if ':' not in stdout:
                continue
            else:
                key = stdout.split(':', 5)[-1].strip()
                break

        if os.path.exists(hc22000_file):
            os.remove(hc22000_file)

        return key

    @staticmethod
    def crack_pmkid(pmkid_file, verbose=False):
        """
        Cracks a PMKID hash file using hashcat mode 22000.
        V3: Uses -m 22000 (replaces obsolete -m 16800).

        Args:
            pmkid_file - Path to .hc22000 hash file.
            verbose    - If True, print the hashcat command.
        Returns:
            Cracked key (str) if successful, None otherwise.
        """
        for additional_arg in ([], ['--show']):
            command = [
                'hashcat',
                '--quiet',
                '-m', '22000',  # V3: Unified WPA-PBKDF2-PMKID+EAPOL
                '-a', '0',      # Wordlist attack mode
                pmkid_file,
                Configuration.wordlist
            ]
            command.extend(Hashcat.get_optimum_workload())
            if Hashcat.should_use_force():
                command.append('--force')
            command.extend(additional_arg)
            if verbose and additional_arg == []:
                Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))

            hashcat_proc = Process(command)
            hashcat_proc.wait()
            stdout = hashcat_proc.stdout()

            if ':' not in stdout:
                continue
            else:
                key = stdout.strip().split(':', 1)[1]
                return key

        return None


class HcxDumpTool(Dependency):
    """
    Wrapper for hcxdumptool.
    V3: Uses modern --filterlist_ap flag (hcxdumptool >= 6.0).
        Old --filterlist / --filtermode flags removed.
    """
    dependency_required = False
    dependency_name = 'hcxdumptool'
    dependency_url = 'https://github.com/ZerBea/hcxdumptool'

    def __init__(self, target, pcapng_file, channel=None):
        """
        Starts hcxdumptool capture targeting a specific BSSID.

        Args:
            target     - Target model instance (must have .bssid and .channel)
            pcapng_file - Output .pcapng file path
            channel    - Override channel (defaults to target.channel)
        """
        # Create filterlist file (one BSSID per line, no colons)
        filterlist = Configuration.temp('pmkid.filterlist')
        bssid_clean = target.bssid.replace(':', '').lower()
        with open(filterlist, 'w') as filter_handle:
            filter_handle.write(bssid_clean + '\n')

        if os.path.exists(pcapng_file):
            os.remove(pcapng_file)

        cap_channel = str(channel) if channel is not None else str(target.channel)

        # V3: Use --filterlist_ap (modern hcxdumptool >= 6.0 flag)
        command = [
            'hcxdumptool',
            '-i', Configuration.interface,
            '--filterlist_ap', filterlist,
            '--enable_status=1',
            '-c', cap_channel,
            '-o', pcapng_file
        ]

        self.proc = Process(command)

    def poll(self):
        """Returns process poll result (None = still running)."""
        return self.proc.poll()

    def interrupt(self):
        """Interrupts the hcxdumptool process."""
        self.proc.interrupt()


class HcxPcapTool(Dependency):
    """
    Wrapper for hcxpcapngtool.
    V3: Replaces obsolete hcxpcaptool with hcxpcapngtool.
        Output format is now 22000 (.hc22000) instead of 16800 (.16800).
    """
    dependency_required = False
    dependency_name = 'hcxpcapngtool'   # V3: was 'hcxpcaptool'
    dependency_url = 'https://github.com/ZerBea/hcxtools'

    def __init__(self, target):
        self.target = target
        self.bssid = self.target.bssid.lower().replace(':', '')
        # V3: .hc22000 extension (was .16800)
        self.pmkid_file = Configuration.temp('pmkid-%s.hc22000' % self.bssid)

    @staticmethod
    def generate_hc22000_file(handshake, show_command=False):
        """
        Converts a .cap file to .hc22000 format using hcxpcapngtool.
        V3: Replaces generate_hccapx_file() which used hcxpcaptool -o.

        Args:
            handshake    - Handshake model with .capfile path.
            show_command - Print command if True.
        Returns:
            Path to generated .hc22000 file, or None on failure.
        """
        hc22000_file = Configuration.temp('generated.hc22000')
        if os.path.exists(hc22000_file):
            os.remove(hc22000_file)

        command = [
            'hcxpcapngtool',
            '-o', hc22000_file,
            handshake.capfile
        ]

        if show_command:
            Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))

        process = Process(command)
        stdout, stderr = process.get_output()

        if not os.path.exists(hc22000_file) or os.path.getsize(hc22000_file) == 0:
            Color.pl('{!} {R}hcxpcapngtool failed to generate .hc22000 file{W}')
            if stderr.strip():
                Color.pl('{!} {O}stderr: %s{W}' % stderr.strip()[:300])
            return None

        return hc22000_file

    @staticmethod
    def generate_hccapx_file(handshake, show_command=False):
        """
        Legacy compatibility wrapper. V3 redirects to generate_hc22000_file().
        hccapx format (mode 2500) is deprecated by hashcat.
        """
        Color.pl('{!} {O}Note: hccapx format is deprecated. Using hc22000 instead.{W}')
        return HcxPcapTool.generate_hc22000_file(handshake, show_command)

    @staticmethod
    def generate_john_file(handshake, show_command=False):
        """
        Generates a John the Ripper compatible file from a .cap capture.
        Uses hcxpcapngtool -j flag.
        """
        john_file = Configuration.temp('generated.john')
        if os.path.exists(john_file):
            os.remove(john_file)

        command = [
            'hcxpcapngtool',   # V3: was hcxpcaptool
            '-j', john_file,
            handshake.capfile
        ]

        if show_command:
            Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))

        process = Process(command)
        stdout, stderr = process.get_output()
        if not os.path.exists(john_file):
            raise ValueError('Failed to generate .john file, output: \n%s\n%s' % (
                stdout, stderr))

        return john_file

    def get_pmkid_hash(self, pcapng_file):
        """
        Extracts PMKID hash in 22000 format from a pcapng capture file.
        V3: Uses hcxpcapngtool -o (was hcxpcaptool -z for 16800 format).

        Returns:
            PMKID hash line (str) matching this target's BSSID, or None.
        """
        if os.path.exists(self.pmkid_file):
            os.remove(self.pmkid_file)

        command = [
            'hcxpcapngtool',   # V3: was hcxpcaptool
            '-o', self.pmkid_file,  # V3: -o for 22000 format (was -z for 16800)
            pcapng_file
        ]
        hcxpcap_proc = Process(command)
        hcxpcap_proc.wait()

        if not os.path.exists(self.pmkid_file) or os.path.getsize(self.pmkid_file) == 0:
            return None

        with open(self.pmkid_file, 'r') as f:
            output = f.read()

        # 22000 format line: WPA*01*pmkid*bssid*station*essid*...
        # or WPA*02*mic*bssid*station*essid*... for full handshakes
        matching_hash = None
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            parts = line.split('*')
            if len(parts) >= 4:
                bssid_in_hash = parts[3].lower()
                if bssid_in_hash == self.bssid:
                    matching_hash = line
                    break

        if os.path.exists(self.pmkid_file):
            os.remove(self.pmkid_file)
        return matching_hash
