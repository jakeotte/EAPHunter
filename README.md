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

## Output

- `eap_identities.txt` — captured outer identities
- `eap_server_cert.der/.pem` — RADIUS server certificate
- `eap_handshake_<mac>.pcap` — raw capture per target
