from ..util.color import Color
from ..util.scorer import score as vuln_score, badge as vuln_badge, sort_targets
from ..tools.airodump import Airodump
from ..util.input import raw_input, xrange
from ..model.target import Target, WPSState
from ..config import Configuration

from time import sleep, time

class Scanner(object):
    ''' Scans wifi networks & provides menu for selecting targets '''

    # Console code for moving up one line
    UP_CHAR = '\x1B[1F'

    def __init__(self):
        '''
        Scans for targets via Airodump.
        Loops until scan is interrupted via user or config.
        Note: Sets this object's `targets` attrbute (list[Target]) upon interruption.
        '''
        self.previous_target_count = 0
        self.targets = []
        self.target = None # Target specified by user (based on ESSID/BSSID)

        max_scan_time = Configuration.scan_time

        self.err_msg = None

        # Loads airodump with interface/channel/etc from Configuration
        try:
            with Airodump() as airodump:
                # Loop until interrupted (Ctrl+C)
                scan_start_time = time()

                while True:
                    if airodump.pid.poll() is not None:
                        return  # Airodump process died

                    self.targets = airodump.get_targets(old_targets=self.targets)

                    if self.found_target():
                        return  # We found the target we want

                    if airodump.pid.poll() is not None:
                        return  # Airodump process died

                    # V3: Enrich targets with RSN info (PMF, WPA3, AKM)
                    # Find the most recent .cap file from airodump
                    cap_files = airodump.find_files(endswith='.cap')
                    if cap_files:
                        self._enrich_targets_rsn(self.targets, cap_files[0])

                    for target in self.targets:
                        if target.bssid in airodump.decloaked_bssids:
                            target.decloaked = True

                    self.print_targets()

                    target_count = len(self.targets)
                    client_count = sum(len(t.clients) for t in self.targets)

                    outline = '\r{+} Scanning'
                    if airodump.decloaking:
                        outline += ' & decloaking'
                    outline += '. Found'
                    outline += ' {G}%d{W} target(s),' % target_count
                    outline += ' {G}%d{W} client(s).' % client_count
                    outline += ' {O}Ctrl+C{W} when ready '
                    Color.clear_entire_line()
                    Color.p(outline)

                    if max_scan_time > 0 and time() > scan_start_time + max_scan_time:
                        return

                    sleep(1)

        except KeyboardInterrupt:
            pass


    def found_target(self):
        '''
        Detect if we found a target specified by the user (optional).
        Sets this object's `target` attribute if found.
        Returns: True if target was specified and found, False otherwise.
        '''
        bssid = Configuration.target_bssid
        essid = Configuration.target_essid

        if bssid is None and essid is None:
            return False  # No specific target from user.

        for target in self.targets:
            if Configuration.wps_only and target.wps not in [WPSState.UNLOCKED, WPSState.LOCKED]:
                continue
            if bssid and target.bssid and bssid.lower() == target.bssid.lower():
                self.target = target
                break
            if essid and target.essid and essid.lower() == target.essid.lower():
                self.target = target
                break

        if self.target:
            Color.pl('\n{+} {C}found target{G} %s {W}({G}%s{W})'
                % (self.target.bssid, self.target.essid))
            return True

        return False


    def print_targets(self):
        if len(self.targets) == 0:
            Color.p('\r')
            return

        ranked = sort_targets(self.targets)

        if self.previous_target_count > 0:
            if Configuration.verbose <= 1:
                if self.previous_target_count > len(ranked) or \
                   Scanner.get_terminal_height() < self.previous_target_count + 6:
                    from ..util.process import Process
                    Process.call('clear')
                else:
                    Color.p(Scanner.UP_CHAR * (self.previous_target_count + 4))

        self.previous_target_count = len(ranked)

        show_bssids = Configuration.show_bssids
        if show_bssids:
            widths = [3, 24, 17, 3, 4, 5, 4, 6, 3, 4, 16]
        else:
            widths = [3, 24, 3, 4, 5, 4, 6, 3, 4, 16]

        top_border = '┌' + '┬'.join('─' * (w + 2) for w in widths) + '┐'
        mid_border = '├' + '┼'.join('─' * (w + 2) for w in widths) + '┤'
        bot_border = '└' + '┴'.join('─' * (w + 2) for w in widths) + '┘'

        if show_bssids:
            headers = [
                'NUM'.center(3),
                'ESSID'.ljust(24),
                'BSSID'.ljust(17),
                'CH'.center(3),
                'ENCR'.center(4),
                'POWER'.center(5),
                'WPS?'.center(4),
                'CLIENT'.center(6),
                'PMF'.center(3),
                'SEC'.center(4),
                'RISK'.center(16),
            ]
        else:
            headers = [
                'NUM'.center(3),
                'ESSID'.ljust(24),
                'CH'.center(3),
                'ENCR'.center(4),
                'POWER'.center(5),
                'WPS?'.center(4),
                'CLIENT'.center(6),
                'PMF'.center(3),
                'SEC'.center(4),
                'RISK'.center(16),
            ]

        Color.clear_entire_line()
        Color.pl('   ' + top_border)
        Color.clear_entire_line()
        Color.pl('   │ ' + ' │ '.join(headers) + ' │')
        Color.clear_entire_line()
        Color.pl('   ' + mid_border)

        for idx, target in enumerate(ranked, start=1):
            Color.clear_entire_line()
            num_val = '{G}%s{W}' % '{:>3}'.format(idx)

            essid_text = target.essid if target.essid_known else '(%s)' % target.bssid
            if len(essid_text) > 24:
                essid_text = essid_text[:21] + '...'
            else:
                essid_text = essid_text.ljust(24)

            decloaked_char = '*' if target.decloaked else ' '
            essid_text = essid_text[:-1] + decloaked_char

            essid_val = '{C}%s{W}' % essid_text if target.essid_known else '{O}%s{W}' % essid_text

            ch_color = '{G}' if int(target.channel) <= 14 else '{C}'
            ch_val = '%s%s%s' % (ch_color, '{:>3}'.format(target.channel), '{W}')

            enc_color = '{G}' if 'WEP' in target.encryption else '{O}'
            enc_val = '%s%s%s' % (enc_color, '{:>4}'.format(target.encryption), '{W}')

            pwr_color = '{G}' if target.power > 50 else '{O}' if target.power > 35 else '{R}'
            pwr_val = '%s%sdb%s' % (pwr_color, '{:>3}'.format(target.power), '{W}')

            if target.wps == WPSState.UNLOCKED:
                wps_val = '{G} yes{W}'
            elif target.wps == WPSState.NONE:
                wps_val = '{O}  no{W}'
            elif target.wps == WPSState.LOCKED:
                wps_val = '{R}lock{W}'
            else:
                wps_val = '{O} n/a{W}'

            client_val = '{G}%s{W}' % '{:>6}'.format(len(target.clients)) if len(target.clients) > 0 else '      '

            if target.pmf_required:
                pmf_val = '{R}REQ{W}'
            elif target.pmf:
                pmf_val = '{O}yes{W}'
            else:
                pmf_val = '{G} no{W}'

            sec_val = '{C}WPA3{W}' if target.wpa3 else '    '

            pts = vuln_score(target)
            risk_raw = vuln_badge(pts)
            risk_val = risk_raw

            if show_bssids:
                bssid_val = '{O}%s{W}' % '{:<17}'.format(target.bssid)
                row_cells = [num_val, essid_val, bssid_val, ch_val, enc_val, pwr_val, wps_val, client_val, pmf_val, sec_val, risk_val]
            else:
                row_cells = [num_val, essid_val, ch_val, enc_val, pwr_val, wps_val, client_val, pmf_val, sec_val, risk_val]

            Color.pl('   │ ' + ' │ '.join(row_cells) + ' │')

        Color.clear_entire_line()
        Color.pl('   ' + bot_border)

    def _enrich_targets_rsn(self, targets, capfile):
        try:
            from ..tools.tshark import Tshark
            Tshark.enrich_targets_rsn_batch(capfile, targets)
        except Exception:
            pass

    @staticmethod
    def get_terminal_height():
        import os
        (rows, columns) = os.popen('stty size', 'r').read().split()
        return int(rows)

    @staticmethod
    def get_terminal_width():
        import os
        (rows, columns) = os.popen('stty size', 'r').read().split()
        return int(columns)

    def select_targets(self):
        '''
        Returns list(target)
        Either a specific target if user specified -bssid or --essid.
        Otherwise, prompts user to select targets and returns the selection.
        '''

        if self.target:
            # When user specifies a specific target
            return [self.target]

        if len(self.targets) == 0:
            if self.err_msg is not None:
                Color.pl(self.err_msg)

            # TODO Print a more-helpful reason for failure.
            # 1. Link to wireless drivers wiki,
            # 2. How to check if your device supporst monitor mode,
            # 3. Provide airodump-ng command being executed.
            raise Exception('No targets found.'
                + ' You may need to wait longer,'
                + ' or you may have issues with your wifi card')

        # Return all targets if user specified a wait time ('pillage').
        if Configuration.scan_time > 0:
            return self.targets

        # Ask user for targets.
        self.print_targets()
        Color.clear_entire_line()

        if self.err_msg is not None:
            Color.pl(self.err_msg)

        input_str  = '{+} select target(s)'
        input_str += ' ({G}1-%d{W})' % len(self.targets)
        input_str += ' separated by commas, dashes'
        input_str += ' or {G}all{W}: '

        chosen_targets = []

        for choice in raw_input(Color.s(input_str)).split(','):
            choice = choice.strip()
            if choice.lower() == 'all':
                chosen_targets = self.targets
                break
            if '-' in choice:
                # User selected a range
                (lower,upper) = [int(x) - 1 for x in choice.split('-')]
                for i in xrange(lower, min(len(self.targets), upper + 1)):
                    chosen_targets.append(self.targets[i])
            elif choice.isdigit():
                choice = int(choice) - 1
                chosen_targets.append(self.targets[choice])

        return chosen_targets


if __name__ == '__main__':
    # 'Test' script will display targets and selects the appropriate one
    Configuration.initialize()
    try:
        s = Scanner()
        targets = s.select_targets()
    except Exception as e:
        Color.pl('\r {!} {R}Error{W}: %s' % str(e))
        Configuration.exit_gracefully(0)
    for t in targets:
        Color.pl('    {W}Selected: %s' % t)
    Configuration.exit_gracefully(0)

