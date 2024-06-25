# Net Quality Assurance Check
### Python Modules
* pandas
* tkinter

### Wireshark column Preference
| Source | Src Port | Destination | Destination Port | Protocol | TLS | HTTP | Sequence Number | Length | Calculated window size | Info

### Detections
* TCP Retransmit
* TCP Duplicated
* Bottleneck
* Port Scanning Detection
* HTTP traffic (GET & POST)
* Non standard TLS Port (443)

If you need SSDP Contains in dataset, enable it just comment on this section.
```
df = df_raw
# df = df_raw[~df_raw['Protocol'].str.contains('SSDP')]
```

ref:
```
https://www.malware-traffic-analysis.net/
https://unit42.paloaltonetworks.com/
```
