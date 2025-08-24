# Networking Triage
**A+ mapping:** 1101 Networking, 1102 Troubleshooting

## Goal
Diagnose and fix DNS misconfig causing name resolution failure.

## Lab Context
Proxmox `vmbr1` (isolated) • Host: Client01 (Win11)

## Steps (detailed)
1. Set bad DNS (x.x.x.x) → reproduce failure.
2. `ipconfig /all`, `nslookup google.com`, `ping 8.8.8.8`, `tracert 8.8.8.8`.
3. Restore DHCP DNS (or correct server) → re-test.
4. Capture outputs and notes.

## Screenshots
- ![before](img/before.png) — nslookup fails; ping to 8.8.8.8 OK (DNS issue).
- ![after](img/after.png) — name resolution restored after fix.

## Troubleshooting notes
- If both name + IP fail, inspect IP/mask/gateway and NIC status first.
- Add Wireshark for packet proof if needed.

## What I learned
- Decision flow: IP → Mask → GW → DNS → Name test → IP test.
