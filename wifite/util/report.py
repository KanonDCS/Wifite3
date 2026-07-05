import os
import json
import time
from ..util.color import Color

class ReportEntry(object):
    def __init__(self, target, attack_type, result, duration_s, key=None):
        self.bssid       = target.bssid
        self.essid       = target.essid or '(hidden)'
        self.channel     = target.channel
        self.encryption  = target.encryption
        self.pmf         = getattr(target, 'pmf', False)
        self.pmf_required= getattr(target, 'pmf_required', False)
        self.wpa3        = getattr(target, 'wpa3', False)
        self.akm         = getattr(target, 'akm', 'PSK')
        self.wps         = target.wps
        self.power       = target.power
        self.attack_type = attack_type
        self.result      = result
        self.duration_s  = round(duration_s, 1)
        self.key         = key
        self.timestamp   = time.strftime('%Y-%m-%dT%H:%M:%S')

    def to_dict(self):
        return {
            'bssid':        self.bssid,
            'essid':        self.essid,
            'channel':      self.channel,
            'encryption':   self.encryption,
            'pmf':          self.pmf,
            'pmf_required': self.pmf_required,
            'wpa3':         self.wpa3,
            'akm':          self.akm,
            'power_db':     self.power,
            'attack_type':  self.attack_type,
            'result':       self.result,
            'duration_s':   self.duration_s,
            'key':          self.key,
            'timestamp':    self.timestamp,
        }

class ReportGenerator(object):
    def __init__(self):
        self.entries = []
        self.session_start = time.strftime('%Y-%m-%dT%H:%M:%S')

    def add_result(self, target, attack_type, result, duration_s, key=None):
        entry = ReportEntry(target, attack_type, result, duration_s, key)
        self.entries.append(entry)

    def add_from_crack_result(self, crack_result, attack_type, duration_s):
        class _FakeTarget:
            def __init__(self, cr):
                self.bssid = cr.bssid
                self.essid = cr.essid
                self.channel = getattr(cr, 'channel', '?')
                self.encryption = 'WPA'
                self.pmf = False
                self.pmf_required = False
                self.wpa3 = False
                self.akm = 'PSK'
                self.wps = 0
                self.power = 0

        ft = _FakeTarget(crack_result)
        result = 'CRACKED' if crack_result.key else 'CAPTURED'
        self.add_result(ft, attack_type, result, duration_s, key=crack_result.key)

    def save_json(self, path='wifite_report.json'):
        data = {
            'wifite_version': '3.0.0',
            'session_start':  self.session_start,
            'session_end':    time.strftime('%Y-%m-%dT%H:%M:%S'),
            'total_targets':  len(self.entries),
            'cracked':        sum(1 for e in self.entries if e.result == 'CRACKED'),
            'results':        [e.to_dict() for e in self.entries],
        }
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
        Color.pl('{+} {G}JSON report saved:{W} {C}%s{W}' % path)
        return path

    def save_markdown(self, path='wifite_report.md'):
        cracked = [e for e in self.entries if e.result == 'CRACKED']
        captured = [e for e in self.entries if e.result == 'CAPTURED']
        failed  = [e for e in self.entries if e.result == 'FAILED']

        lines = [
            '# Wifite 3 — Audit Report',
            '',
            '| | |',
            '|---|---|',
            '| **Session Start** | %s |' % self.session_start,
            '| **Session End**   | %s |' % time.strftime('%Y-%m-%dT%H:%M:%S'),
            '| **Targets**       | %d |' % len(self.entries),
            '| **Cracked**       | %d |' % len(cracked),
            '| **Captured**      | %d |' % len(captured),
            '| **Failed**        | %d |' % len(failed),
            '',
        ]

        if cracked:
            lines += [
                '## 🔓 Cracked Networks',
                '',
                '| ESSID | BSSID | Channel | Encryption | PMF | WPA3 | Attack | Key | Duration |',
                '|---|---|---|---|---|---|---|---|---|',
            ]
            for e in cracked:
                lines.append(
                    '| `%s` | `%s` | %s | %s | %s | %s | %s | `%s` | %ds |' % (
                        e.essid, e.bssid, e.channel, e.encryption,
                        '✅' if e.pmf else '❌',
                        '✅' if e.wpa3 else '❌',
                        e.attack_type,
                        e.key or '',
                        e.duration_s
                    )
                )
            lines.append('')

        if captured:
            lines += [
                '## 📦 Captured (Not Cracked)',
                '',
                '| ESSID | BSSID | Channel | Encryption | PMF | WPA3 | Attack | Duration |',
                '|---|---|---|---|---|---|---|---|',
            ]
            for e in captured:
                lines.append(
                    '| `%s` | `%s` | %s | %s | %s | %s | %s | %ds |' % (
                        e.essid, e.bssid, e.channel, e.encryption,
                        '✅' if e.pmf else '❌',
                        '✅' if e.wpa3 else '❌',
                        e.attack_type,
                        e.duration_s
                    )
                )
            lines.append('')

        if failed:
            lines += [
                '## ❌ Failed Targets',
                '',
                '| ESSID | BSSID | Channel | Encryption | PMF | WPA3 | Attack | Duration |',
                '|---|---|---|---|---|---|---|---|',
            ]
            for e in failed:
                lines.append(
                    '| `%s` | `%s` | %s | %s | %s | %s | %s | %ds |' % (
                        e.essid, e.bssid, e.channel, e.encryption,
                        '✅' if e.pmf else '❌',
                        '✅' if e.wpa3 else '❌',
                        e.attack_type,
                        e.duration_s
                    )
                )
            lines.append('')

        lines += [
            '---',
            '*Generated by Wifite 3 — https://github.com/KanonDCS/Wifite3*',
        ]

        with open(path, 'w') as f:
            f.write('\n'.join(lines))
        Color.pl('{+} {G}Markdown report saved:{W} {C}%s{W}' % path)
        return path

    def save_html(self, path='wifite_report.html'):
        cracked  = [e for e in self.entries if e.result == 'CRACKED']
        captured = [e for e in self.entries if e.result == 'CAPTURED']
        failed   = [e for e in self.entries if e.result == 'FAILED']

        def _row(e, show_key=True):
            key_cell = ('<td class="key">%s</td>' % (e.key or '')) if show_key else ''
            pmf_cell = '<td class="badge pmf">PMF</td>' if e.pmf else '<td></td>'
            wpa3_cell = '<td class="badge wpa3">WPA3</td>' if e.wpa3 else '<td></td>'
            result_cls = e.result.lower()
            return (
                '<tr class="%s">'
                '<td>%s</td><td><code>%s</code></td>'
                '<td>%s</td><td>%s</td>'
                '%s%s'
                '<td>%s</td>'
                '%s'
                '<td>%ds</td>'
                '<td>%s</td>'
                '</tr>' % (
                    result_cls,
                    e.essid, e.bssid,
                    e.channel, e.encryption,
                    pmf_cell, wpa3_cell,
                    e.attack_type,
                    key_cell,
                    e.duration_s,
                    e.timestamp,
                )
            )

        all_rows = (
            [_row(e, show_key=True)  for e in cracked] +
            [_row(e, show_key=False) for e in captured] +
            [_row(e, show_key=False) for e in failed]
        )

        html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Wifite 3 — Audit Report</title>
<style>
  :root {{
    --bg: #0d1117;
    --surface: #161b22;
    --border: #30363d;
    --text: #c9d1d9;
    --green: #3fb950;
    --red: #f85149;
    --orange: #d29922;
    --blue: #58a6ff;
    --purple: #bc8cff;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace;
    padding: 2rem;
    line-height: 1.6;
  }}
  h1 {{
    font-size: 1.8rem;
    color: var(--blue);
    margin-bottom: 0.5rem;
  }}
  .meta {{
    color: #8b949e;
    font-size: 0.9rem;
    margin-bottom: 2rem;
  }}
  .summary {{
    display: flex;
    gap: 1rem;
    flex-wrap: wrap;
    margin-bottom: 2rem;
  }}
  .card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1rem 1.5rem;
    min-width: 140px;
    text-align: center;
  }}
  .card .num {{ font-size: 2rem; font-weight: bold; }}
  .card .label {{ font-size: 0.75rem; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; }}
  .card.green .num {{ color: var(--green); }}
  .card.orange .num {{ color: var(--orange); }}
  .card.red .num {{ color: var(--red); }}
  .card.blue .num {{ color: var(--blue); }}
  table {{
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 2rem;
    font-size: 0.9rem;
  }}
  th {{
    background: var(--surface);
    border: 1px solid var(--border);
    padding: 0.6rem 1rem;
    text-align: left;
    color: #8b949e;
    font-weight: 600;
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }}
  td {{
    border: 1px solid var(--border);
    padding: 0.6rem 1rem;
    vertical-align: middle;
  }}
  tr.cracked {{ background: rgba(63, 185, 80, 0.08); }}
  tr.captured {{ background: rgba(88, 166, 255, 0.06); }}
  tr.failed {{ background: rgba(248, 81, 73, 0.06); }}
  tr:hover td {{ background: rgba(255,255,255,0.04); }}
  code {{
    font-family: 'Courier New', monospace;
    font-size: 0.85em;
    color: var(--purple);
  }}
  .key {{ color: var(--green); font-weight: bold; font-family: monospace; }}
  .badge {{
    font-size: 0.7rem;
    font-weight: bold;
    padding: 2px 6px;
    border-radius: 4px;
    text-align: center;
  }}
  .badge.pmf {{ background: rgba(210, 153, 34, 0.25); color: var(--orange); }}
  .badge.wpa3 {{ background: rgba(88, 166, 255, 0.2); color: var(--blue); }}
  footer {{ color: #8b949e; font-size: 0.8rem; margin-top: 2rem; text-align: center; }}
  a {{ color: var(--blue); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>
<h1>&#x1F4E1; Wifite 3 — Audit Report</h1>
<div class="meta">Session: {session_start} &rarr; {session_end}</div>

<div class="summary">
  <div class="card blue"><div class="num">{total}</div><div class="label">Targets</div></div>
  <div class="card green"><div class="num">{n_cracked}</div><div class="label">Cracked</div></div>
  <div class="card orange"><div class="num">{n_captured}</div><div class="label">Captured</div></div>
  <div class="card red"><div class="num">{n_failed}</div><div class="label">Failed</div></div>
</div>

<table>
  <thead>
    <tr>
      <th>ESSID</th>
      <th>BSSID</th>
      <th>CH</th>
      <th>ENC</th>
      <th>PMF</th>
      <th>WPA3</th>
      <th>Attack</th>
      <th>Key</th>
      <th>Duration</th>
      <th>Timestamp</th>
    </tr>
  </thead>
  <tbody>
    {rows}
  </tbody>
</table>

<footer>
  Generated by <a href="https://github.com/KanonDCS/Wifite3">Wifite 3</a>
</footer>
</body>
</html>""".format(
            session_start=self.session_start,
            session_end=time.strftime('%Y-%m-%dT%H:%M:%S'),
            total=len(self.entries),
            n_cracked=len(cracked),
            n_captured=len(captured),
            n_failed=len(failed),
            rows='\n    '.join(all_rows),
        )

        with open(path, 'w') as f:
            f.write(html)
        Color.pl('{+} {G}HTML report saved:{W} {C}%s{W}' % path)
        return path

    def print_summary(self):
        if not self.entries:
            Color.pl('{!} {O}No results to report.{W}')
            return

        cracked = [e for e in self.entries if e.result == 'CRACKED']
        captured = [e for e in self.entries if e.result == 'CAPTURED']

        Color.pl('\n{+} {W}===== Wifite 3 Session Summary ====={W}')
        Color.pl('{+} Targets attacked:  {C}%d{W}' % len(self.entries))
        Color.pl('{+} Cracked:           {G}%d{W}' % len(cracked))
        Color.pl('{+} Hashes captured:   {O}%d{W}' % len(captured))

        if cracked:
            Color.pl('\n{+} {G}Cracked networks:{W}')
            for e in cracked:
                Color.pl('    {G}%-25s{W} {C}%s{W}  key: {G}%s{W}' % (
                    e.essid, e.bssid, e.key))
        Color.pl('')
