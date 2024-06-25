#!/usr/bin/python
#
#
# Written by Prima Agus Setiawan 
# a.k.a joeheartless 
# 
#
# published under universe license which means it's fvckin free.
#
#
# Modules
# pip3 install pandas tkinter
# 
# The quality of network formula is very simple,
# I simply sum event of TCP Dup, TCP Ret, TCP lost segment and some zero window event.
#
# In wireshark, export packets dissections as CSV file.
# Wireshark columns references for HTTP and TLS section report.
# | Source | Src Port | Destination | Destination Port | Protocol | TLS | HTTP | Sequence Number | Length | Calculated window size | Info

import pandas as pd
from tkinter import filedialog

def gegarisan():
    return print(75*'-')

gegarisan()
print('               NETWORK QUALITY ASSURANCE CHECK            ')
gegarisan()

def read_csv():
    return pd.read_csv(filedialog.askopenfilename(filetypes=[("CSV File",".csv")]))

df_raw = read_csv()
print(df_raw[['Source','Destination','Info']])
gegarisan()
print(df_raw['Protocol'].value_counts().to_string())

did = df_raw['Destination'].mode().item()
dis = df_raw['Source'].mode().item()
if did == dis:  
    print("Host IP Addr: ",did)

gegarisan()
print('Total captured packets: ', len(df_raw))

df = df_raw[~df_raw['Protocol'].str.contains('SSDP')]
df_ret = df['Info'].str.contains('TCP Ret').sum()
print('Total retransmitted packets:', df_ret)

df_dup = df['Info'].str.contains('TCP Dup').sum()
print('Total duplicated packets:', df_dup)

df_unseen = df['Info'].str.contains('TCP ACKed unseen').sum()
print('Total lost packets during transmission:', df_unseen)

df_rstack = df['Info'].str.contains('RST, ACK').sum()
print('Total Reset ACK:', df_rstack)
if df_rstack >= 200:
    print(" ===> There are indications of port scanning")

df_windowfull = df['Info'].str.contains('TCP Window Full').sum()
df_bottlenecksum = df['Info'].str.contains('TCP ZeroWindow').sum()
df_bottleneck = df[df['Info'].str.contains('TCP ZeroWindow')]
print('Total Zero Window event: ',df_bottlenecksum)
if df_bottlenecksum >= 1:
    print(" ===> There are indications of bottleneck")
    print(df_bottleneck[['Source','Destination','Calculated window size','Info']])
print()
def net_quality():
    dff = int(len(df_raw))
    df_rett = int(df_ret)
    df_dupp = int(df_dup)
    df_unseenn = int(df_unseen)
    df_rstacks = int(df_rstack)
    df_stuck = (df_rett,df_dupp,df_unseenn,df_bottlenecksum)
    df_ok = sum(df_stuck) / dff * 100
    df_total = 100 - df_ok
    print('Packets data transmission quality:', '%.2f'%(df_total),'%')
net_quality()
gegarisan()
print()
df_ftp = df['Protocol'].str.contains('FTP').sum()
print('Non TLS connection [FTP] :',df_ftp)

df_telnet = df['Protocol'].str.contains('TELNET').sum()
print('Non TLS connection [TELNET] :',df_telnet)

if 'HTTP' not in df:
    print("Please add 'HTTP' as a column name and fields 'http.host' in Wireshark.")

try:
    http = df['HTTP'].isnull() == False
    print('Non TLS connection [HTTP contains link]:', http.sum())
except KeyError:
    print()
gegarisan()
print()
def http_method():
    df_http = df[df['Protocol'].str.contains('HTTP')]
    df_get = df_http[df_http['Info'].str.contains('GET')]
    df_common = df_http[~df_http['Info'].str.contains('GET')]
    print('Common HTTP traffic')
    print(df_common['HTTP'].value_counts().to_string())
    print()
    print('HTTP request methode: GET')
    print(df_get['HTTP'].value_counts().to_string())
    print('-')
    print('HTTP request methode: POST')
    df_post = df_http[df_http['Info'].str.contains('POST')]
    print(df_post['HTTP'].value_counts().to_string())
    print('-')  
    print('Please visit https://urlhaus.abuse.ch/ for website legitimate check.')

try:
    http_method()
except KeyError:
    print()
gegarisan()
print()

def freak_tls():
    print('Non Standard TLS Connection')
    df_tls = df[df['Protocol'].str.contains('TLS')]
    df_freak_tls_src = df_tls[(df_tls['Src Port'] == 443) == False]
    df_non_standard_tls_port = df_freak_tls_src[(df_freak_tls_src['Destination Port'] == 443) == False]
    print(df_non_standard_tls_port[['Source','Src Port','Destination','Destination Port','Info']])
    print('For letigimate check, please open .pcap file and check certificate issuer')
    
try:
    freak_tls()
except KeyError:
    print()
gegarisan()
