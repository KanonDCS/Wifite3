#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys

class Color(object):
    colors = {
        'W' : '\033[0m',
        'R' : '\033[31m',
        'G' : '\033[32m',
        'O' : '\033[33m',
        'B' : '\033[34m',
        'P' : '\033[35m',
        'C' : '\033[36m',
        'GR': '\033[37m',
        'D' : '\033[2m',
        'BD': '\033[1m',
        'UL': '\033[4m'
    }

    replacements = {
        '{+}': ' {W}{G}➔{W}',
        '{!}': ' {R}⚠{W}',
        '{?}': ' {C}❓{W}'
    }

    last_sameline_length = 0

    @staticmethod
    def p(text):
        sys.stdout.write(Color.s(text))
        sys.stdout.flush()
        if '\r' in text:
            text = text[text.rfind('\r')+1:]
            Color.last_sameline_length = len(text)
        else:
            Color.last_sameline_length += len(text)

    @staticmethod
    def pl(text):
        Color.p('%s\n' % text)
        Color.last_sameline_length = 0

    @staticmethod
    def pe(text):
        sys.stderr.write(Color.s('%s\n' % text))
        Color.last_sameline_length = 0

    @staticmethod
    def s(text):
        output = text
        for (key,value) in Color.replacements.items():
            output = output.replace(key, value)
        for (key,value) in Color.colors.items():
            output = output.replace('{%s}' % key, value)
        return output

    @staticmethod
    def clear_line():
        spaces = ' ' * Color.last_sameline_length
        sys.stdout.write('\r%s\r' % spaces)
        sys.stdout.flush()
        Color.last_sameline_length = 0

    @staticmethod
    def clear_entire_line():
        import os
        (rows, columns) = os.popen('stty size', 'r').read().split()
        Color.p('\r' + (' ' * int(columns)) + '\r')

    @staticmethod
    def pattack(attack_type, target, attack_name, progress):
        essid = '{C}%s{W}' % target.essid if target.essid_known else '{O}unknown{W}'
        Color.p('\r{+} {G}%s{W} ({C}%sdb{W}) {G}%s {C}%s{W}: %s ' % (
            essid, target.power, attack_type, attack_name, progress))

    @staticmethod
    def pexception(exception):
        Color.pl('\n{!} {R}Error: {O}%s' % str(exception))

        if 'No targets found' in str(exception):
            return

        from ..config import Configuration
        if Configuration.verbose > 0 or Configuration.print_stack_traces:
            Color.pl('\n{!} {O}Full stack trace below')
            from traceback import format_exc
            Color.p('\n{!}    ')
            err = format_exc().strip()
            err = err.replace('\n', '\n{!} {C}   ')
            err = err.replace('  File', '{W}File')
            err = err.replace('  Exception: ', '{R}Exception: {O}')
            Color.pl(err)


if __name__ == '__main__':
    Color.pl('{R}Testing{G}One{C}Two{P}Three{W}Done')
    print(Color.s('{C}Testing{P}String{W}'))
    Color.pl('{+} Good line')
    Color.pl('{!} Danger')
