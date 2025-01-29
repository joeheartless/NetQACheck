Network Quality Assurance Check

Overview

This script analyzes network packet capture data to assess network quality by identifying various network issues, such as retransmissions, duplicate packets, packet loss, congestion, and potential security threats.

Features

Reads a CSV file containing network packet capture data.

Analyzes packet statistics including:

Protocol distribution

Retransmitted, duplicated, and lost packets

TCP congestion and zero window events

Possible port scanning detection

Calculates overall network quality based on weighted impact factors.

Identifies non-TLS connections (FTP, TELNET, HTTP) and potential security risks.

Analyzes HTTP traffic methods (GET, POST) and identifies unusual activity.

Detects non-standard TLS connections.

Installation

Prerequisites

Python 3.x

Required libraries:

pip install pandas

Usage

Run the script:

python network_qc_analysis.py

Select a network capture CSV file when prompted.

The script will process the data and display network quality metrics.

Network Quality Calculation

The network quality score is calculated as:

quality_score = 100 * (1 - issue_ratio)

Where issue_ratio is determined using weighted occurrences of network issues:

Retransmitted packets: 1.2x weight

Duplicated packets: 1.0x weight

Lost packets: 1.5x weight

Zero window events: 1.3x weight

TCP window full (congestion): 1.4x weight

Reset ACK packets: 1.1x weight

ref:
```
https://www.malware-traffic-analysis.net/
https://unit42.paloaltonetworks.com/
```
