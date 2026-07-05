# Wifite 3 — High-Performance Wireless Network Auditor

Wifite 3 is a complete, modernized redesign of the original wireless network auditor, rebuilt for modern security professionals, penetration testers, and red-teams. 

This major upgrade (Wifite 3) is developed and maintained by **KanonDCS**.

It wraps existing wireless auditing tools into a clean, automated CLI interface. No more memorizing complex arguments, switches, and command sequences.

---

## What is new in Wifite 3?

Wifite 3 upgrades the codebase to support modern Wi-Fi encryption, performance optimizations, and operational security (OpSec) standards:

1. **WPA3 & SAE Support**: Native scanning and passive capture of WPA3/SAE handshake structures, converting capture frames directly to hashcat's modern **22000 format** (`.hc22000`) for cracking.
2. **PMF (802.11w) Awareness**: Detects Protected Management Frames (PMF Required or PMF Capable) dynamically from the RSN Information Elements. Automatically skips deauth routines for PMF-required networks to maintain stealth and avoid useless injections.
3. **High-Speed Batch Scanning**: Spawns exactly one single-pass `tshark` background process to parse and enrich all discovered AP capabilities (PMF, WPA3, and AKM suites) in real-time, eliminating the bottleneck of running a subprocess per BSSID.
4. **Scapy Validation Engine**: Replaces the abandoned `pyrit` validator with a robust, modern Scapy EAPOL framework for structural and cryptographical sanity checks of captured handshakes.
5. **Stealth Secure Shredding (OpSec)**: Includes a forensic cleanup engine that overwrites all temporary PCAP/CAP capture frames and filter files with random bytes (3 passes) and syncs changes physically via `os.fsync()` before deletion.
6. **Modern Unicode Interface**: Upgraded the CLI scan table using professional Unicode box-drawing borders and headers (`┌`, `┬`, `┐`, `│`, `├`, `┼`, `┤`, `└`, `┴`, `┘`) for clean, responsive real-time output.
7. **PEP 668 Distro Support**: Updated installer scripts to integrate cleanly with Kali and Parrot OS externally-managed environment packages (`python3-scapy`, `python3-tqdm`, `python3-colorama`).

---

## Supported Attacks
* **WPA3/SAE**: Passive association handshake capture and mode 22000 offline cracking.
* **WPA2/1 Handshake**: 4-way handshake capture + offline crack.
* **PMKID**: Clientless PMKID hash capture via `hcxdumptool` and conversion to mode 22000 format.
* **WPS**: Pixie-Dust offline attack and online PIN brute-force (via `reaver` or `bully`).
* **WEP**: Various legacy injection attacks (replay, fragmentation, chop-chop, hirte, caffe-latte).

---

## Operating Systems
* **Kali Linux** (Recommended)
* **Parrot OS**
* **Termux / NetHunter** (Android environments)

---

## Requirements

### Wireless Card
A wireless network adapter that supports **Monitor Mode** and **Packet Injection**.

### External Programs
* `aircrack-ng` suite (includes `airmon-ng`, `airodump-ng`, `aireplay-ng`, `aircrack-ng`)
* `iw`
* `tshark` (from Wireshark)
* `hcxdumptool` and `hcxtools` (for PMKID and WPA3)
* `hashcat` (for offline cracking)
* `reaver` or `bully` (for WPS attacks)

---

## Installation

### 1. Clone the repository:
```bash
git clone https://github.com/KanonDCS/wifite3.git
cd wifite3
```

### 2. Install dependencies and program:
```bash
chmod +x install.sh
sudo ./install.sh
```

---

## Execution

### Ask for target selection and attack:
```bash
sudo wifite
```

### Attack only WPA/WPA3 targets and generate an HTML report:
```bash
sudo wifite --wpa --report html
```

### Audit PMKID hashes only:
```bash
sudo wifite --pmkid
```

---

## Credits
Wifite 3 is developed and modernized by **KanonDCS** (<kanondcs@proton.me>).
Original design by derv82.
Licensed under GNU GPLv2.
