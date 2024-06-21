#!/usr/bin/python
#
#
# written by @Prima Agus Setiawan 
# a.k.a joeheartless 
# a.k.a IT Kontol2an Tanah
#
# published under universe license which means it's fvckin free.
#
# Modules
# pip3 install pandas tkinter
# 
# The quality of network formula is very simple,
# I simply sum event of TCP Dup, TCP Ret, TCP lost segment and some zero window event.
#
# In wireshark, export packets dissections as CSV file.
# Wireshark columns 
# | Source | Src Port | Destination | Destination Port | Protocol | TLS | HTTP | Sequence Number | Length | Calculated window size | Info

import pandas as pd
from tkinter import filedialog

print(75*'-')
print('               NETWORK QUALITY ASSURANCE CHECK            ')
print(75*'-')

def read_csv():
    return pd.read_csv(filedialog.askopenfilename(filetypes=[("CSV File",".csv")]))

df_raw = read_csv()
print(df_raw[['Source','Destination','Info']])
print(75*'-')
print(df_raw['Protocol'].value_counts().to_string())

did = df_raw['Destination'].mode().item()
dis = df_raw['Source'].mode().item()
if did == dis:  
    print("Host IP Addr: ",did)

print(75*'-')
print('Total captured packets: ', len(df_raw))

df = df_raw[~df_raw['Protocol'].str.contains('SSDP')]
df_ret = df['Info'].str.contains('TCP Ret').sum()
print('Total retransmitted packets:', df_ret)

df_dup = df['Info'].str.contains('TCP Dup').sum()
print('Total duplicated packets:', df_dup)

df_unseen = df['Info'].str.contains('TCP ACKed unseen').sum()
print('Total lost packets during transmission:', df_unseen)

df_rstack = df['Info'].str.contains('RST, ACK').sum()
print('Total TCP handshake failed:', df_rstack)

df_zerowindows = df['Info'].str.contains('TCP Window Full').sum()
df_zerowindows1 = df['Info'].str.contains('TCP ZeroWindow').sum()
df_bottleneck = df_zerowindows + df_zerowindows1
print('Total Zero Window event: ',df_bottleneck)
if df_bottleneck >= 1:
    print(" ===> There are indications of bottleneck")

dff = int(len(df_raw))
df_rett = int(df_ret)
df_dupp = int(df_dup)
df_unseenn = int(df_unseen)
df_rstacks = int(df_rstack)
df_stuck = (df_rett,df_dupp,df_unseenn,df_rstacks)
df_ok = sum(df_stuck) / dff * 100
df_total = 100 - df_ok
print('Packets data transmission quality:', '%.2f'%(df_total),'%')
print(75*'-')
df_ftp = df['Protocol'].str.contains('FTP').sum()
print('Non TLS connection [FTP] :',df_ftp)

df_telnet = df['Protocol'].str.contains('TELNET').sum()
print('Non TLS connection [TELNET] :',df_telnet)

try:
    http = df['HTTP'].isnull() == False
    print('Non TLS connection [HTTP contains link]:', http.sum())
except KeyError:
    print()
print(75*'-')

print('HTTP request methode: GET')   
df_http = df[df['Protocol'].str.contains('HTTP')]
df_get = df_http[df_http['Info'].str.contains('GET')]
print(df_get['HTTP'].value_counts().to_string())
print('-')
print('HTTP request methode: POST')
df_post = df_http[df_http['Info'].str.contains('POST')]
print(df_post['HTTP'].value_counts().to_string())
print('-')
print('Please visit https://urlhaus.abuse.ch/ for website legitimate check.')
print(75*'-')
print()
print('Non Standard TLS Connection')
df_tls = df[df['Protocol'].str.contains('TLS')]
df_freak_tls_src = df_tls[(df_tls['Src Port'] == 443) == False]
df_non_standard_tls_port = df_freak_tls_src[(df_freak_tls_src['Destination Port'] == 443) == False]
print(df_non_standard_tls_port[['Source','Src Port','Destination','Destination Port','Info']])
print('For letigimate check, please open .pcap file and check certificate issuer')
print(75*'-')
