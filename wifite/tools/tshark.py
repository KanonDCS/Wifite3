#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
wifite/tools/tshark.py — V3
Wrapper for the tshark packet analysis tool.

V3 additions:
- get_rsn_info()  — extract RSN IE capabilities and AKM suites
- detect_pmf()    — detect Protected Management Frames (802.11w)
- detect_wpa3()   — detect WPA3/SAE via AKM suite 0x8
"""

from .dependency import Dependency
from ..model.target import WPSState
from ..util.process import Process
import re

class Tshark(Dependency):
    ''' Wrapper for Tshark program. '''
    dependency_required = False
    dependency_name = 'tshark'
    dependency_url = 'apt-get install wireshark'

    def __init__(self):
        pass


    @staticmethod
    def _extract_src_dst_index_total(line):
        # Extract BSSIDs, handshake # (1-4) and handshake 'total' (4)
        mac_regex = ('[a-zA-Z0-9]{2}:' * 6)[:-1]
        match = re.search(r'(%s)\s*.*\s*(%s).*Message.*(\d).*of.*(\d)' % (mac_regex, mac_regex), line)
        if match is None:
            # Line doesn't contain src, dst, Message numbers
            return None, None, None, None
        (src, dst, index, total) = match.groups()
        return src, dst, index, total


    @staticmethod
    def _build_target_client_handshake_map(output, bssid=None):
        # Map of target_ssid,client_ssid -> handshake #s
        target_client_msg_nums = {}

        for line in output.split('\n'):
            src, dst, index, total = Tshark._extract_src_dst_index_total(line)

            if src is None: continue

            index = int(index)
            total = int(total)

            if total != 4: continue  # Handshake X of 5? X of 3? Skip it.

            # Identify the client and target MAC addresses
            if index % 2 == 1:
                target = src
                client = dst
            else:
                client = src
                target = dst

            if bssid is not None and bssid.lower() != target.lower():
                continue

            target_client_key = '%s,%s' % (target, client)

            if index == 1:
                target_client_msg_nums[target_client_key] = 1
            elif target_client_key not in target_client_msg_nums:
                continue
            elif index - 1 != target_client_msg_nums[target_client_key]:
                continue
            else:
                target_client_msg_nums[target_client_key] = index

        return target_client_msg_nums


    @staticmethod
    def bssids_with_handshakes(capfile, bssid=None):
        if not Tshark.exists():
            return []

        command = [
            'tshark',
            '-r', capfile,
            '-n',
            '-Y', 'eapol'
        ]
        tshark = Process(command, devnull=False)

        target_client_msg_nums = Tshark._build_target_client_handshake_map(tshark.stdout(), bssid=bssid)

        bssids = set()
        for (target_client, num) in target_client_msg_nums.items():
            if num == 4:
                this_bssid = target_client.split(',')[0]
                bssids.add(this_bssid)

        return list(bssids)


    @staticmethod
    def bssid_essid_pairs(capfile, bssid):
        if not Tshark.exists():
            return []

        ssid_pairs = set()

        command = [
            'tshark',
            '-r', capfile,
            '-n',
            '-Y', '"wlan.fc.type_subtype == 0x08 || wlan.fc.type_subtype == 0x05"',
        ]
        tshark = Process(command, devnull=False)

        for line in tshark.stdout().split('\n'):
            mac_regex = ('[a-zA-Z0-9]{2}:' * 6)[:-1]
            match = re.search('(%s) [^ ]* (%s).*.*SSID=(.*)$' % (mac_regex, mac_regex), line)
            if match is None:
                continue

            (src, dst, essid) = match.groups()

            if dst.lower() == 'ff:ff:ff:ff:ff:ff':
                continue

            if bssid is not None:
                if bssid.lower() == src.lower():
                    ssid_pairs.add((src, essid))
            else:
                ssid_pairs.add((src, essid))

        return list(ssid_pairs)


    @staticmethod
    def check_for_wps_and_update_targets(capfile, targets):
        '''
            Given a cap file and list of targets, use TShark to
            find which BSSIDs in the cap file use WPS.
            Then update the 'wps' flag for those BSSIDs in the targets.
        '''
        from ..config import Configuration

        if not Tshark.exists():
            raise ValueError('Cannot detect WPS networks: Tshark does not exist')

        command = [
            'tshark',
            '-r', capfile,
            '-n',
            '-Y', 'wps.wifi_protected_setup_state && wlan.da == ff:ff:ff:ff:ff:ff',
            '-T', 'fields',
            '-e', 'wlan.ta',
            '-e', 'wps.ap_setup_locked',
            '-E', 'separator=,'
        ]
        p = Process(command)

        try:
            p.wait()
            lines = p.stdout()
        except Exception:
            return

        wps_bssids = set()
        locked_bssids = set()
        for line in lines.split('\n'):
            if ',' not in line:
                continue
            bssid, locked = line.split(',')
            if '1' not in locked:
                wps_bssids.add(bssid.upper())
            else:
                locked_bssids.add(bssid.upper())

        for t in targets:
            target_bssid = t.bssid.upper()
            if target_bssid in wps_bssids:
                t.wps = WPSState.UNLOCKED
            elif target_bssid in locked_bssids:
                t.wps = WPSState.LOCKED
            else:
                t.wps = WPSState.NONE


    @staticmethod
    def get_rsn_info(capfile, bssid):
        result = {
            'pmf_capable':  False,
            'pmf_required': False,
            'akm_suites':   [],
        }

        if not Tshark.exists():
            return result

        command = [
            'tshark',
            '-r', capfile,
            '-n',
            '-Y', 'wlan.ta == %s && (wlan.fc.type_subtype == 0x08 || wlan.fc.type_subtype == 0x05)' % bssid,
            '-T', 'fields',
            '-e', 'wlan.rsn.capabilities',
            '-e', 'wlan.rsn.akms.type',
            '-E', 'separator=|',
            '-E', 'occurrence=f',
        ]

        try:
            proc = Process(command, devnull=False)
            proc.wait()
            output = proc.stdout()
        except Exception:
            return result

        for line in output.split('\n'):
            line = line.strip()
            if not line or '|' not in line:
                continue

            parts = line.split('|')
            if len(parts) < 2:
                continue

            rsn_caps_hex = parts[0].strip()
            akm_types_raw = parts[1].strip() if len(parts) > 1 else ''

            if rsn_caps_hex:
                try:
                    rsn_caps = int(rsn_caps_hex, 16)
                    if rsn_caps & 0x0080:
                        result['pmf_capable'] = True
                    if rsn_caps & 0x0040:
                        result['pmf_required'] = True
                except (ValueError, TypeError):
                    pass

            if akm_types_raw:
                akm_map = {
                    '1':  '802.1X',
                    '2':  'PSK',
                    '6':  'PSK-SHA256',
                    '8':  'SAE',
                    '18': 'OWE',
                    '24': 'FILS-SHA256',
                }
                for akm_type in akm_types_raw.split(','):
                    akm_type = akm_type.strip()
                    name = akm_map.get(akm_type, 'UNKNOWN(%s)' % akm_type)
                    if name not in result['akm_suites']:
                        result['akm_suites'].append(name)

            if rsn_caps_hex or akm_types_raw:
                break

        return result

    @staticmethod
    def detect_pmf(capfile, bssid):
        info = Tshark.get_rsn_info(capfile, bssid)
        return info['pmf_capable'] or info['pmf_required']

    @staticmethod
    def detect_pmf_required(capfile, bssid):
        info = Tshark.get_rsn_info(capfile, bssid)
        return info['pmf_required']

    @staticmethod
    def detect_wpa3(capfile, bssid):
        info = Tshark.get_rsn_info(capfile, bssid)
        return 'SAE' in info['akm_suites']

    @staticmethod
    def get_akm_suite(capfile, bssid):
        info = Tshark.get_rsn_info(capfile, bssid)
        if info['akm_suites']:
            return info['akm_suites'][0]
        return 'PSK'

    @staticmethod
    def enrich_target_rsn(capfile, target):
        info = Tshark.get_rsn_info(capfile, target.bssid)
        target.pmf          = info['pmf_capable'] or info['pmf_required']
        target.pmf_required = info['pmf_required']
        target.wpa3         = 'SAE' in info['akm_suites']
        target.akm          = info['akm_suites'][0] if info['akm_suites'] else 'PSK'
        if target.wpa3:
            target.pmf = True

    @staticmethod
    def enrich_targets_rsn_batch(capfile, targets):
        if not Tshark.exists():
            return

        command = [
            'tshark',
            '-r', capfile,
            '-n',
            '-Y', 'wlan.fc.type_subtype == 0x08 || wlan.fc.type_subtype == 0x05',
            '-T', 'fields',
            '-e', 'wlan.ta',
            '-e', 'wlan.rsn.capabilities',
            '-e', 'wlan.rsn.akms.type',
            '-E', 'separator=|'
        ]

        try:
            proc = Process(command, devnull=False)
            proc.wait()
            output = proc.stdout()
        except Exception:
            return

        bssid_rsn = {}
        for line in output.split('\n'):
            line = line.strip()
            if not line or '|' not in line:
                continue

            parts = line.split('|')
            if len(parts) < 2:
                continue

            bssid = parts[0].strip().lower()
            rsn_caps_hex = parts[1].strip()
            akm_types_raw = parts[2].strip() if len(parts) > 2 else ''

            if not bssid or bssid in bssid_rsn:
                continue

            pmf_capable = False
            pmf_required = False
            akm_suites = []

            if rsn_caps_hex:
                try:
                    rsn_caps = int(rsn_caps_hex, 16)
                    if rsn_caps & 0x0080:
                        pmf_capable = True
                    if rsn_caps & 0x0040:
                        pmf_required = True
                except (ValueError, TypeError):
                    pass

            if akm_types_raw:
                akm_map = {
                    '1':  '802.1X',
                    '2':  'PSK',
                    '6':  'PSK-SHA256',
                    '8':  'SAE',
                    '18': 'OWE',
                    '24': 'FILS-SHA256',
                }
                for akm_type in akm_types_raw.split(','):
                    akm_type = akm_type.strip()
                    name = akm_map.get(akm_type, 'UNKNOWN(%s)' % akm_type)
                    if name not in akm_suites:
                        akm_suites.append(name)

            bssid_rsn[bssid] = {
                'pmf_capable': pmf_capable,
                'pmf_required': pmf_required,
                'akm_suites': akm_suites
            }

        for target in targets:
            b_lc = target.bssid.lower()
            if b_lc in bssid_rsn:
                info = bssid_rsn[b_lc]
                target.pmf = info['pmf_capable'] or info['pmf_required']
                target.pmf_required = info['pmf_required']
                target.wpa3 = 'SAE' in info['akm_suites']
                target.akm = info['akm_suites'][0] if info['akm_suites'] else 'PSK'
                if target.wpa3:
                    target.pmf = True

