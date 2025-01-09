# Compromised Network Printer

## Challenge Description
You are a DFIR Analyst for a corporation. A network printer running in the internal network has been compromised as it was alerted by our IDS.
You have been provided a packet capture to trace the attacker’s action and what data was stolen from the printer server.

File location:/root/Desktop/ChallengeFile/networkprinter.zip

## Approach
Identify the port scan activity performed by the attacker on the network. What was the NAT IP Address(Internal IP Address) assigned to the machine being used by the attacker on the internal network?

   First, I opened the PCAP file using Wireshark and it contained only the ICMP traffic. Here’s what it looked like:

   ![image](https://github.com/user-attachments/assets/c563ce21-04da-4a93-b958-aa482448ffe9)

3. To simplify the analysis, I used tshark to extract only the data from ICMP Echo Requests:

   ```bash
   tshark -r echo_chamber.pcap -Y "icmp.type == 8" -T fields -e data
   ```
   The output showed a repeating sequence of hex data:

   ![image](https://github.com/user-attachments/assets/ccbddfdc-2870-4a62-b01f-49df46c2719e)

4. I noticed that the data had consistent patterns. To extract the hidden message, I decided to take only the last byte of the payload from each Echo Request. Here’s the Python script I used:

```python
import sys
from scapy.all import rdpcap, ICMP

def get_echo_requests(pcap_file):
    packets = rdpcap(pcap_file)
    echo_requests = b""

    for packet in packets:
        # Check if the packet has an ICMP layer and is an Echo Request (Type 8)
        if packet.haslayer(ICMP) and packet[ICMP].type == 8:
            try:
                # Safely access the raw payload data if it exists
                payload = bytes(packet[ICMP].payload)
                # Extract the last byte of the payload
                echo_requests += payload[-1].to_bytes(1, "little")
            except Exception as e:
                print(f"Error processing packet: {e}")

    return echo_requests

# Get the PCAP file from command-line arguments
if len(sys.argv) < 2:
    print("Usage: python3 script.py <pcap_file>")
    sys.exit(1)

# Extract the echo requests and find the flag
out = get_echo_requests(sys.argv[1])

# Parse the flag from the extracted data
try:
    flag = b"flag{" + out.split(b"flag{")[1].split(b"}")[0] + b"}"
    print(flag.decode())
except IndexError:
    print("Flag not found in the extracted data.")
```

4. Running the script on the PCAP file revealed the flag!

   ![image](https://github.com/user-attachments/assets/a9dc8bf5-9c9a-4632-b2b3-2c72597fb43b)

## Flag
flag{6b38aa917a754d8bf384dc73fde633ad}
