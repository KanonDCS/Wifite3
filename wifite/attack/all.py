#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
wifite/attack/all.py — V3
Attack orchestration: determines which attacks to run per target.

V3 attack priority:
  WPA3 target:
    1. AttackWPA3 (SAE capture)
    2. AttackPMKID (fallback — PMKID works regardless of WPA version)

  WPA2 target:
    1. AttackWPS (Pixie-Dust, if WPS available)
    2. AttackWPS (PIN, if WPS available)
    3. AttackPMKID (no clients needed)
    4. AttackWPA (4-way handshake; deauth skipped if PMF)

  WEP target:
    1. AttackWEP (unchanged)
"""

from .wep import AttackWEP
from .wpa import AttackWPA
from .wps import AttackWPS
from .pmkid import AttackPMKID
from ..config import Configuration
from ..util.color import Color


class AttackAll(object):

    @classmethod
    def attack_multiple(cls, targets):
        '''
        Attacks all given targets until user interruption.
        Returns: Number of targets that were attacked (int)
        '''
        if any(t.wps for t in targets) and not AttackWPS.can_attack_wps():
            Color.pl('{!} {O}Note: WPS attacks are not possible because you do not have {C}reaver{O} nor {C}bully{W}')

        attacked_targets = 0
        targets_remaining = len(targets)
        for index, target in enumerate(targets, start=1):
            attacked_targets += 1
            targets_remaining -= 1

            bssid = target.bssid
            essid = target.essid if target.essid_known else '{O}ESSID unknown{W}'

            Color.pl('\n{+} ({G}%d{W}/{G}%d{W})' % (index, len(targets)) +
                     ' Starting attacks against {C}%s{W} ({C}%s{W})' % (bssid, essid))

            # V3: Log WPA3/PMF status
            if getattr(target, 'wpa3', False):
                Color.pl('{!} {C}WPA3/SAE{W} network detected — using SAE capture first')
            elif getattr(target, 'pmf', False):
                pmf_level = 'required' if getattr(target, 'pmf_required', False) else 'enabled'
                Color.pl('{!} {O}PMF (802.11w) is %s — deauth will be skipped{W}' % pmf_level)

            should_continue = cls.attack_single(target, targets_remaining)
            if not should_continue:
                break

        return attacked_targets

    @classmethod
    def attack_single(cls, target, targets_remaining):
        '''
        Attacks a single target.
        V3: WPA3 targets get AttackWPA3 first.
        Returns: True if attacks should continue, False otherwise.
        '''
        attacks = []

        if Configuration.use_eviltwin:
            # TODO: EvilTwin attack
            pass

        elif 'WEP' in target.encryption:
            attacks.append(AttackWEP(target))

        elif 'WPA' in target.encryption:

            # V3: WPA3/SAE targets
            if getattr(target, 'wpa3', False) and not Configuration.use_pmkid_only:
                try:
                    from .wpa3 import AttackWPA3
                    attacks.append(AttackWPA3(target))
                except ImportError:
                    Color.pl('{!} {O}WPA3 attack module not available{W}')

            if not Configuration.use_pmkid_only:
                # WPS attacks (skip if WPA3-only network)
                if target.wps != False and AttackWPS.can_attack_wps():
                    if Configuration.wps_pixie:
                        attacks.append(AttackWPS(target, pixie_dust=True))
                    if Configuration.wps_pin:
                        attacks.append(AttackWPS(target, pixie_dust=False))

            if not Configuration.wps_only:
                # PMKID (works with and without clients; works even with PMF in some cases)
                attacks.append(AttackPMKID(target))

                # 4-way handshake (deauth skipped in AttackWPA if target.pmf is True)
                if not Configuration.use_pmkid_only:
                    attacks.append(AttackWPA(target))

        if len(attacks) == 0:
            Color.pl('{!} {R}Error: {O}Unable to attack: no attacks available')
            return True

        while len(attacks) > 0:
            attack = attacks.pop(0)
            try:
                result = attack.run()
                if result:
                    break
            except Exception as e:
                Color.pexception(e)
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
