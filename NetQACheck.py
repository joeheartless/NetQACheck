#!/usr/bin/python
#
#
# Written by Prima Agus Setiawan 
# a.k.a joeheartless 
# Time | Source | Src Port | Destination | Destination Port | Protocol | TLS | HTTP | Sequence Number | Length | TCP Length | Calculated window size | User Agent HTTP | Flags | Info

import pandas as pd
from tkinter import filedialog

def print_separator():
    print(75 * '-')

def read_csv_file():
    """Prompts user to select a CSV file and reads it into a DataFrame."""
    file_path = filedialog.askopenfilename(filetypes=[("CSV File", ".csv")])
    if not file_path:
        print("No file selected.")
        return None
    return pd.read_csv(file_path, low_memory=False)

def count_occurrences(df, column, keyword):
    """Counts occurrences of a specific keyword in a DataFrame column."""
    return df[column].str.contains(keyword, na=False).sum()

print_separator()
print('               NETWORK QUALITY ASSURANCE CHECK            ')
print_separator()

df_raw = read_csv_file()
if df_raw is None:
    exit()

print(df_raw[['Source', 'Destination', 'Info']])
print_separator()
print(df_raw['Protocol'].value_counts().to_string())

most_common_dest = df_raw['Destination'].mode().iloc[0]
most_common_source = df_raw['Source'].mode().iloc[0]
if most_common_dest == most_common_source:
    print("Host IP Address: ", most_common_dest)

print_separator()
print('Total captured packets: ', len(df_raw))

df_filtered = df_raw[~df_raw['Protocol'].str.contains('SSDP', na=False)]
retransmitted_packets = count_occurrences(df_filtered, 'Info', 'TCP Ret')
duplicated_packets = count_occurrences(df_filtered, 'Info', 'TCP Dup')
lost_packets = count_occurrences(df_filtered, 'Info', 'TCP ACKed unseen')
reset_ack_packets = count_occurrences(df_filtered, 'Info', 'RST, ACK')
tcp_window_full = count_occurrences(df_filtered, 'Info', 'TCP Window Full')
zero_window_events = count_occurrences(df_filtered, 'Info', 'TCP ZeroWindow')

print('Total retransmitted packets:', retransmitted_packets)
print('Total duplicated packets:', duplicated_packets)
print('Total lost packets during transmission:', lost_packets)
print('Total Reset ACK:', reset_ack_packets)
print('Total Zero Window events:', zero_window_events)
print('Total TCP Window Full events (Congestion):', tcp_window_full)

if reset_ack_packets >= 200:
    print(" ===> Possible port scanning detected")
if zero_window_events >= 1:
    print(" ===> Potential bottleneck detected")
    print(df_filtered[df_filtered['Info'].str.contains('TCP ZeroWindow', na=False)][['Source', 'Destination', 'Info']])

def calculate_network_quality():
    total_packets = len(df_raw)
    if total_packets == 0:
        print("No packets captured, unable to calculate network quality.")
        return

    # Weighted Impact Calculation
    weighted_issues = (
        (1.2 * retransmitted_packets) + 
        (1.0 * duplicated_packets) + 
        (1.5 * lost_packets) + 
        (1.3 * zero_window_events) + 
        (1.4 * tcp_window_full) + 
        (1.1 * reset_ack_packets)
    )
    
    # Normalization to prevent drastic drops
    issue_ratio = min(weighted_issues / total_packets, 1)  # Cap to max 1 (100%)
    quality_score = 100 * (1 - issue_ratio)
    
    print(f"Packet data transmission quality: {quality_score:.2f}%")

calculate_network_quality()
print_separator()

ftp_connections = count_occurrences(df_filtered, 'Protocol', 'FTP')
telnet_connections = count_occurrences(df_filtered, 'Protocol', 'TELNET')

print('Non-TLS connections [FTP]:', ftp_connections)
print('Non-TLS connections [TELNET]:', telnet_connections)

if 'HTTP' not in df_filtered.columns:
    print("Please add 'HTTP' as a column name and include 'http.host' in Wireshark.")
else:
    print('Non-TLS connections [HTTP contains link]:', df_filtered['HTTP'].notnull().sum())

print_separator()

def analyze_http_traffic():
    if 'HTTP' not in df_filtered.columns:
        print("HTTP column not found in data.")
        return

    http_traffic = df_filtered[df_filtered['Protocol'].str.contains('HTTP', na=False)]
    get_requests = http_traffic[http_traffic['Info'].str.contains('GET', na=False)]
    post_requests = http_traffic[http_traffic['Info'].str.contains('POST', na=False)]
    
    print('Common HTTP traffic')
    print(http_traffic['HTTP'].value_counts().to_string())
    print()
    print('HTTP request method: GET')
    print(get_requests['HTTP'].value_counts().to_string())
    print('-')
    print('HTTP request method: POST')
    print(post_requests['HTTP'].value_counts().to_string())
    print('-')
    print('For website legitimacy checks, visit: https://urlhaus.abuse.ch/')

analyze_http_traffic()
print_separator()

def analyze_tls_traffic():
    if 'Src Port' not in df_filtered.columns or 'Destination Port' not in df_filtered.columns:
        print("'Src Port' or 'Destination Port' column not found in data.")
        return

    tls_traffic = df_filtered[df_filtered['Protocol'].str.contains('TLS', na=False)]
    non_standard_tls = tls_traffic[(tls_traffic['Src Port'] != 443) & (tls_traffic['Destination Port'] != 443)]
    
    print('Non-Standard TLS Connections')
    print(non_standard_tls[['Source', 'Src Port', 'Destination', 'Destination Port', 'Info']])
    print('For legitimacy verification, open the .pcap file and check the certificate issuer.')

analyze_tls_traffic()
print_separator()
