# EAPHunter

WPA-Enterprise toolkit. Passive and active modes against 802.1X targets.

```
pip install scapy cryptography
```

`iw` · `ip` required for all modes. `wpa_supplicant` required for `spray` and `authmethods`.

---

## userenum

Deauths clients to force EAP re-auth. Captures outer identity and RADIUS cert.

```
sudo python3 eaphunter.py userenum -e <SSID> -i <iface> [-c <secs>] [-s <secs>] [-o <dir>]
```

Select a client number, `auto` to cycle all, or `q` to quit.
Output: `eap_identities.txt` · `eap_server_cert.der/pem` · `eap_handshake_<mac>.pcap`

---

## analyze

Passively sniffs EAPOL handshakes on a target AP. Reports observed EAP methods.

```
sudo python3 eaphunter.py analyze -e <SSID> -i <iface> [-s <secs>] [-t <secs>] [-o <dir>]
```

`-t` stops after N seconds. Default runs until Ctrl+C.
Output: `analyze_report.tsv`

---

## authmethods

Actively probes which EAP methods a RADIUS server accepts for a given identity.

```
sudo python3 eaphunter.py authmethods -e <SSID> -i <iface> -I <identity> [--cleartext] [-o <dir>]
```

`--cleartext` limits probing to PAP/GTC/OTP (plaintext-in-tunnel, evil-twin interceptable).
`--identityfile` to probe multiple identities in sequence.
Output: `auth_methods_<identity>.txt`

---

## spray

PEAP/MSCHAPv2 credential spray. Password-outer ordering to reduce per-account lockout risk.

```
sudo python3 eaphunter.py spray -e <SSID> -i <iface> \
    [-u <user>] [-U <userfile>] [-p <pass>] [-P <passfile>] [-d <delay>] [-o <dir>]
```

Output: `spray_hits.txt`

---

## deauth

Monitors clients on a target AP and sends deauth frames on demand. No EAP capture.

```
sudo python3 eaphunter.py deauth -e <SSID> -i <iface>
sudo python3 eaphunter.py deauth --bssid <BSSID> -c <channel> -i <iface>
```
