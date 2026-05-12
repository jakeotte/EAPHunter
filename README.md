# EAPHunter

WPA-Enterprise credential harvester. Monitors associated clients on a target
SSID, deauthenticates them to trigger an EAP re-authentication, and extracts
the outer identity (username/domain) and server certificate from the handshake.

Requires no external tools beyond `iw` and `ip`. Everything else runs in Python
via Scapy.

---

## Requirements

```
pip install scapy cryptography
```

System tools: `iw`, `ip` (standard on any Linux distro)

---

## Usage

```
sudo python3 eaphunter.py -e <ESSID> -i <interface>
```

| Flag | Description |
|------|-------------|
| `-e` | Target SSID |
| `-i` | Wireless interface (must support monitor mode) |
| `-o` | Output directory (default: auto-named) |
| `-c` | Capture window in seconds after deauth (default: 20) |

---

## What it does

1. Puts the interface into monitor mode
2. Scans for the target SSID — stops as soon as it's found
3. Locks to the AP's channel and continuously monitors for associated clients
4. Displays a live client table with vendor lookup
5. On selection, starts capturing first, then sends deauth frames
6. Extracts EAP identities in real time from the reconnection handshake
7. Extracts the RADIUS server certificate from the TLS exchange
8. Returns to monitoring — marked clients show `[deauthed]`

Type `auto` at the selection prompt to cycle through all undeauthed clients
automatically, 60 seconds apart. An estimated completion time is shown.

---

## Output

All artifacts are written to the output directory:

| File | Contents |
|------|----------|
| `eap_identities.txt` | All captured EAP outer identities |
| `credentials.txt` | Full identity strings (`DOMAIN\user`, `user@domain`) |
| `usernames.txt` | Parsed usernames |
| `domains.txt` | Parsed domain names |
| `eap_server_cert.der` | RADIUS server certificate (DER format) |
| `eap_server_cert.pem` | RADIUS server certificate (PEM format) |
| `eap_handshake_<mac>.pcap` | Raw capture per deauth target |

---

## Notes

- Outer identities only. Inner credentials (PEAP/TTLS phase 2) are encrypted.
- Random/locally-administered MACs show `UNKNOWN` in the vendor column — this
  is normal for modern devices with MAC randomisation enabled.
- The interface is restored to managed mode on exit.
