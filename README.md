# Network Quality Assurance Check

## Overview
This script analyzes network packet capture data to assess network quality by identifying various network issues, such as retransmissions, duplicate packets, packet loss, congestion, and potential security threats.

## Features
- Reads a CSV file containing network packet capture data.
- Analyzes packet statistics including:
  - Protocol distribution
  - Retransmitted, duplicated, and lost packets
  - TCP congestion and zero window events
  - Possible port scanning detection
- Calculates overall network quality based on weighted impact factors.
- Identifies non-TLS connections (FTP, TELNET, HTTP) and potential security risks.
- Analyzes HTTP traffic methods (GET, POST) and identifies unusual activity.
- Detects non-standard TLS connections.

## Installation
### Prerequisites
- Python 3.x
- Required libraries:
  ```bash
  pip3 install pandas
  ```

## Usage
1. Run the script:
   ```bash
   python3 NetQACheck.py
   ```
2. Select a network capture CSV file when prompted.
3. The script will process the data and display network quality metrics.

## Network Health Score Calculation

The Network Health Score is calculated using a **weighted event-rate model** rather than raw event counts. This approach ensures that the final score remains consistent regardless of the capture size (e.g., 10,000 packets or 1,000,000 packets).

### Why Event Rate?

Using raw packet counts can produce misleading results. For example:

- Capture A: 100 retransmissions out of 1,000 packets
- Capture B: 100 retransmissions out of 1,000,000 packets

Although both captures contain the same number of retransmissions, the actual network quality is significantly different.

Therefore, every TCP event is normalized into a percentage (event rate).

---

## Event Rate Formula

For TCP packet-based events:

```text
Event Rate (%) =
(Number of Event / Total TCP Packets) × 100
```

Examples:

```text
Retransmission Rate =
(Retransmitted Packets / Total TCP Packets) × 100

Duplicate ACK Rate =
(Duplicate ACK / Total TCP Packets) × 100

Window Full Rate =
(TCP Window Full / Total TCP Packets) × 100

Zero Window Rate =
(TCP Zero Window / Total TCP Packets) × 100
```

For connection-based events:

```text
RST Rate =
(Number of RST Packets / Total TCP Sessions) × 100
```

RST packets are calculated against the number of TCP sessions because they represent connection terminations rather than individual packet transmissions.

---

## Quality Score Conversion

Each event rate is converted into a quality score between **50 and 100**.

### Retransmission Rate

| Rate | Score |
|------|------:|
| ≤ 0.10% | 100 |
| ≤ 0.50% | 95 |
| ≤ 1.00% | 85 |
| ≤ 2.00% | 70 |
| > 2.00% | 50 |

### Duplicate ACK Rate

| Rate | Score |
|------|------:|
| ≤ 0.50% | 100 |
| ≤ 1.00% | 95 |
| ≤ 2.00% | 85 |
| ≤ 5.00% | 70 |
| > 5.00% | 50 |

### TCP Window Full Rate

| Rate | Score |
|------|------:|
| ≤ 0.05% | 100 |
| ≤ 0.20% | 95 |
| ≤ 0.50% | 85 |
| ≤ 1.00% | 70 |
| > 1.00% | 50 |

### TCP Zero Window Rate

| Rate | Score |
|------|------:|
| 0.00% | 100 |
| ≤ 0.05% | 95 |
| ≤ 0.10% | 85 |
| ≤ 0.50% | 70 |
| > 0.50% | 50 |

### TCP Reset (RST) Rate

| Rate | Score |
|------|------:|
| ≤ 1.00% | 100 |
| ≤ 3.00% | 95 |
| ≤ 5.00% | 85 |
| ≤ 10.00% | 70 |
| > 10.00% | 50 |

---

## Overall Network Health Score

The final network health score is calculated using a weighted average.

```text
Overall Score =
(Retransmission Score × 0.50)
+ (Duplicate ACK Score × 0.20)
+ (Window Full Score × 0.10)
+ (Zero Window Score × 0.10)
+ (RST Score × 0.10)
```

The weighting prioritizes TCP retransmissions because they are generally the strongest indicator of network transmission problems.

| Metric | Weight |
|---------|-------:|
| Retransmission | 50% |
| Duplicate ACK | 20% |
| Window Full | 10% |
| Zero Window | 10% |
| RST | 10% |

---

## Network Grade

| Score | Grade | Status |
|-------|-------|----------------|
| 97–100 | A+ | Excellent |
| 94–96 | A | Very Good |
| 90–93 | B | Good |
| 80–89 | C | Fair |
| 70–79 | D | Poor |
| <70 | F | Critical |

---

## Example Output

Below is an example report generated from a Wireshark CSV export.

```text
Host IP Address: 192.168.0.51

---------------------------------------------------------------------------
Total captured packets: 243416
Total retransmitted packets: 693
Total duplicated packets: 2259
TCP ACKed unseen: 23992
Total Reset ACK: 54
Total Zero Window events: 0
Total TCP Window Full events (Congestion): 0

==============================
NETWORK HEALTH REPORT
==============================

TCP Packets          : 182,896
TCP Sessions         : 7,110

Retransmission Rate  : 0.379%
Duplicate ACK Rate   : 1.235%
Window Full Rate     : 0.000%
Zero Window Rate     : 0.000%
RST Rate             : 0.759%

Overall Score        : 94.50/100
Grade                : A (Very Good)
```

### Interpretation

- **Retransmission Rate (0.379%)** indicates that only a small percentage of TCP packets required retransmission, suggesting a stable transmission path.
- **Duplicate ACK Rate (1.235%)** is within a normal range and indicates only minor TCP recovery activity.
- **Window Full Rate (0.000%)** shows no indication of sender-side congestion.
- **Zero Window Rate (0.000%)** indicates that the receiving host did not experience receive-buffer exhaustion.
- **RST Rate (0.759%)** is considered normal for typical client/server communications where connections are frequently opened and closed.

Overall, this capture represents a **healthy TCP network** with only minor retransmissions and no significant congestion detected.

## Design Philosophy

The scoring model is inspired by common network performance assessment practices used in enterprise monitoring solutions. While it is not derived from a single RFC, IEEE standard, or vendor specification, it follows a normalized event-rate and weighted scoring approach to provide a practical and consistent indicator of TCP network health.

It should be noted that the weighting factors and scoring thresholds used in this project are inherently subjective. Currently, there is no universally accepted standard or mathematical formula for calculating a single "Network Health Score" from packet capture data. Different network vendors and monitoring platforms employ their own proprietary methodologies, often combining various performance metrics, heuristics, and operational experience.

Therefore, the scoring system implemented in this project should be interpreted as a practical engineering heuristic rather than an authoritative industry standard. The primary objective is to provide a consistent, repeatable, and easily interpretable assessment of TCP network quality that remains comparable across different packet capture sizes and network environments.


ref:
```
- RFC 793 – Transmission Control Protocol
- RFC 1122 – Requirements for Internet Hosts – Communication Layers
- RFC 5681 – TCP Congestion Control
- RFC 6298 – Computing TCP Retransmission Timer
- Wireshark User Guide – TCP Analysis Flags
- Stevens, W. Richard. TCP/IP Illustrated, Volume 1.
- https://www.malware-traffic-analysis.net/
- https://unit42.paloaltonetworks.com/
```
