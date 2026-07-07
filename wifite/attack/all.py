from .wep  import AttackWEP
from .wpa  import AttackWPA
from .wps  import AttackWPS
from .pmkid import AttackPMKID
from ..config import Configuration
from ..util.color import Color
from ..util.oui   import vendor_key, vendor_name
from ..util.wordgen import write_targeted_wordlist
from ..util.scorer  import score as vuln_score, label as vuln_label, badge as vuln_badge

import os


class AttackAll(object):

    @classmethod
    def _pre_attack_briefing(cls, target, index, total):
        bssid = target.bssid
        essid = target.essid if target.essid_known else '(hidden)'
        pts   = vuln_score(target)
        badge = vuln_badge(pts)

        vkey  = vendor_key(bssid)
        vname = vendor_name(bssid)

        Color.pl('\n{+} (%s%d{W}/{G}%d{W}) {W}%s {C}%s{W}' % (
            '{G}', index, total, bssid, essid))
        Color.pl('    \033[2mVendor:\033[0m \033[96m%-18s\033[0m  Risk: %s' % (vname, badge))

        if getattr(target, 'wpa3', False):
            Color.pl('    \033[96m[WPA3/SAE]\033[0m Protocol: SAE Dragonfly — active cracking vector')
        if getattr(target, 'pmf', False):
            level = 'REQUIRED' if getattr(target, 'pmf_required', False) else 'ENABLED'
            Color.pl('    \033[33m[PMF 802.11w %s]\033[0m Deauth frames will be suppressed' % level)

        targeted_wl = None
        if 'WPA' in target.encryption and Configuration.wordlist:
            targeted_wl, isp = write_targeted_wordlist(essid, bssid)
            if targeted_wl:
                Color.pl('    \033[92m[INTEL]\033[0m Targeted wordlist generated'
                         ' (\033[93m%s\033[0m pattern detected)' % (isp or 'generic'))
                Configuration._targeted_wordlist = targeted_wl
            else:
                Configuration._targeted_wordlist = None

        return targeted_wl

    @classmethod
    def attack_multiple(cls, targets):
        if any(t.wps for t in targets) and not AttackWPS.can_attack_wps():
            Color.pl('{!} {O}WPS attacks unavailable — {C}reaver{O}/{C}bully{O} not found{W}')

        attacked_targets  = 0
        targets_remaining = len(targets)

        for index, target in enumerate(targets, start=1):
            attacked_targets  += 1
            targets_remaining -= 1

            cls._pre_attack_briefing(target, index, len(targets))
            should_continue = cls.attack_single(target, targets_remaining)
            if not should_continue:
                break

        return attacked_targets

    @classmethod
    def attack_single(cls, target, targets_remaining):
        attacks = []

        if Configuration.use_eviltwin:
            pass

        elif 'WEP' in target.encryption:
            attacks.append(AttackWEP(target))

        elif 'WPA' in target.encryption:
            if getattr(target, 'wpa3', False) and not Configuration.use_pmkid_only:
                try:
                    from .wpa3 import AttackWPA3
                    attacks.append(AttackWPA3(target))
                except ImportError:
                    Color.pl('{!} {O}WPA3 attack module unavailable{W}')

            if not Configuration.use_pmkid_only:
                if target.wps != False and AttackWPS.can_attack_wps():
                    if Configuration.wps_pixie:
                        attacks.append(AttackWPS(target, pixie_dust=True))
                    if Configuration.wps_pin:
                        attacks.append(AttackWPS(target, pixie_dust=False))

            if not Configuration.wps_only:
                attacks.append(AttackPMKID(target))
                if not Configuration.use_pmkid_only:
                    attacks.append(AttackWPA(target))

        if len(attacks) == 0:
            Color.pl('{!} {R}Error: {O}No attacks available for this target{W}')
            return True

        while len(attacks) > 0:
            attack = attacks.pop(0)
            try:
                result = attack.run()
                if result:
                    break
            except Exception as e:
                err_msg = str(e)
                Color.pl('{!} {R}Attack failed:{O} %s{W}' % err_msg)
                # Dynamic fallback: if WPS attack is locked, clear other WPS attacks and fallback to PMKID/WPA
                if 'Locked' in err_msg or 'rate limiting' in err_msg:
                    Color.pl('{!} {O}WPS is locked on target — skipping remaining WPS attacks, switching to offline vectors...{W}')
                    attacks = [a for a in attacks if not hasattr(a, 'pixie_dust')]
                continue
            except KeyboardInterrupt:
                Color.pl('\n{!} {O}Interrupted{W}\n')
                answer = cls.user_wants_to_continue(targets_remaining, len(attacks))
                if answer is True:
                    continue
                elif answer is None:
                    return True
                else:
                    return False

        targeted_wl = getattr(Configuration, '_targeted_wordlist', None)
        if targeted_wl and os.path.exists(targeted_wl):
            os.remove(targeted_wl)
            Configuration._targeted_wordlist = None

        if attack.success:
            attack.crack_result.save()

        return True



    @classmethod
    def user_wants_to_continue(cls, targets_remaining, attacks_remaining=0):
        '''
        Asks user if attacks should continue.
        Returns True (continue), None (skip), False (exit).
        '''
        if attacks_remaining == 0 and targets_remaining == 0:
            return

        prompt_list = []
        if attacks_remaining > 0:
            prompt_list.append(Color.s('{C}%d{W} attack(s)' % attacks_remaining))
        if targets_remaining > 0:
            prompt_list.append(Color.s('{C}%d{W} target(s)' % targets_remaining))
        prompt = ' and '.join(prompt_list) + ' remain'
        Color.pl('{+} %s' % prompt)

        prompt = '{+} Do you want to'
        options = '('

        if attacks_remaining > 0:
            prompt += ' {G}continue{W} attacking,'
            options += '{G}C{W}{D}, {W}'

        if targets_remaining > 0:
            prompt += ' {O}skip{W} to the next target,'
            options += '{O}s{W}{D}, {W}'

        options += '{R}e{W})'
        prompt += ' or {R}exit{W} %s? {C}' % options

        from ..util.input import raw_input
        answer = raw_input(Color.s(prompt)).lower()

        if answer.startswith('s'):
            return None
        elif answer.startswith('e'):
            return False
        else:
            return True
