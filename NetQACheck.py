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
acked_unseen = count_occurrences(df_filtered, 'Info', 'TCP ACKed unseen')
reset_ack_packets = count_occurrences(df_filtered, 'Info', 'RST, ACK')
tcp_window_full = count_occurrences(df_filtered, 'Info', 'TCP Window Full')
zero_window_events = count_occurrences(df_filtered, 'Info', 'TCP ZeroWindow')

print('Total retransmitted packets:', retransmitted_packets)
print('Total duplicated packets:', duplicated_packets)
print('Total lost packets during transmission:', acked_unseen)
print('Total Reset ACK:', reset_ack_packets)
print('Total Zero Window events:', zero_window_events)
print('Total TCP Window Full events (Congestion):', tcp_window_full)

if reset_ack_packets >= 200:
    print(" ===> Possible port scanning detected")
if zero_window_events >= 1:
    print(" ===> Potential bottleneck detected")
    print(df_filtered[df_filtered['Info'].str.contains('TCP ZeroWindow', na=False)][['Source', 'Destination', 'Info']])

def score_by_rate(rate, excellent, good, fair, poor):
    """
    Convert event rate (%) into score (0-100)

    excellent : maximum rate for score 100
    good      : maximum rate for score 95
    fair      : maximum rate for score 85
    poor      : maximum rate for score 70
    """

    if rate <= excellent:
        return 100
    elif rate <= good:
        return 95
    elif rate <= fair:
        return 85
    elif rate <= poor:
        return 70
    else:
        return 50


def calculate_network_quality():

    tcp_packets = len(
        df_filtered[
            df_filtered["Protocol"].str.contains("TCP", na=False)
        ]
    )

    if tcp_packets == 0:
        tcp_packets = 1

    tcp_sessions = len(
        df_filtered[
            df_filtered["Info"].str.contains("SYN", na=False)
        ]
    )

    if tcp_sessions == 0:
        tcp_sessions = 1

    retrans_rate = retransmitted_packets / tcp_packets * 100
    dup_rate = duplicated_packets / tcp_packets * 100
    previous_segment = count_occurrences(
        df_filtered,
        "Info",
        "Previous segment not captured"
    )

    fast_retrans = count_occurrences(
        df_filtered,
        "Info",
        "Fast Retransmission"
    )

    spurious_retrans = count_occurrences(
        df_filtered,
        "Info",
        "Spurious Retransmission"
    )

    zero_window_rate = zero_window_events / tcp_packets * 100
    congestion_rate = tcp_window_full / tcp_packets * 100
    rst_rate = reset_ack_packets / tcp_sessions * 100

    # -----------------------------
    # Individual Score
    # -----------------------------

    retrans_score = score_by_rate(retrans_rate, 0.10, 0.50, 1.00, 2.00)

    dup_score = score_by_rate(dup_rate, 0.50, 1.00, 2.00, 5.00)

    zero_score = score_by_rate(zero_window_rate, 0.00, 0.05, 0.10, 0.50)

    congestion_score = score_by_rate(congestion_rate, 0.05, 0.20, 0.50, 1.00)

    rst_score = score_by_rate(rst_rate, 1.00, 3.00, 5.00, 10.00)

    # -----------------------------
    # Overall Score
    # -----------------------------

    overall = (
        retrans_score * 0.50
        + dup_score * 0.20
        + congestion_score * 0.10
        + zero_score * 0.10
        + rst_score * 0.10
    )

    # -----------------------------
    # Grade
    # -----------------------------

    if overall >= 97:
        grade = "A+ (Excellent)"
    elif overall >= 94:
        grade = "A (Very Good)"
    elif overall >= 90:
        grade = "B (Good)"
    elif overall >= 80:
        grade = "C (Fair)"
    elif overall >= 70:
        grade = "D (Poor)"
    else:
        grade = "F (Critical)"

    # -----------------------------
    # Report
    # -----------------------------

    print()
    print("==============================")
    print("NETWORK HEALTH REPORT")
    print("==============================")

    print(f"TCP Packets          : {tcp_packets:,}")
    print(f"TCP Sessions         : {tcp_sessions:,}")
    print(f"Retransmission Rate  : {retrans_rate:.3f}%")
    print(f"Duplicate ACK Rate   : {dup_rate:.3f}%")
    print(f"Window Full Rate     : {congestion_rate:.3f}%")
    print(f"Zero Window Rate     : {zero_window_rate:.3f}%")
    print(f"RST Rate             : {rst_rate:.3f}%")
    print()

    print(f"Overall Score        : {overall:.2f}/100")
    print(f"Grade                : {grade}")

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
