## Net Quality Assurance Check
Python Modules
* pandas
* tkinter

Wireshark column Preference
| Source | Src Port | Destination | Destination Port | Protocol | TLS | HTTP | Sequence Number | Length | Calculated window size | Info

Detections
* TCP Retransmit
* TCP Duplicated
* Bottleneck
* HTTP traffic (GET POST)
* Non standard TLS Port (443)

No SSDP Contains. 
If you want to enable it just comment on this section
'''
# df = df_raw
df = df_raw[~df_raw['Protocol'].str.contains('SSDP')]
'''
