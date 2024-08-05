# Net Quality Assurance Check
### Python Modules
* pandas
* tkinter

### Wireshark column Preference
Time | Source | Src Port | Destination | Destination Port | Protocol | TLS | HTTP | Sequence Number | Length | TCP Length | Calculated window size | User Agent HTTP | Flags | Info

or import My custom Wireshark Profile
```
https://drive.google.com/file/d/1vEWe9n66ql4q5_BWASJjXf1ODDh7bTjS/view?usp=sharing
```

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
