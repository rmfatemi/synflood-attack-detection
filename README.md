# synflood-attack-detection
A simple syn-flood attacker and a detector written in Python 2.7 and using Scapy

# Introduction

SYN flood attack was considered to be the most devastating DoS attack method
before the Smurf was discovered. This method uses resource starvation to
achieve the DoS attack. See the figure next slide, during a normal TCP handshake, a client sends a SYN request to the server; then the server responds with
a ACK/SYN to the client, finally the client sends a final ACK back to the server.
But in a SYN flood attack, the attacker sends multiple SYN requests to the victim server with spoofed source addresses for the return address. The spoofed
addresses are nonexistent on network. The victim server then responds with an
ACK/ SYN back to the nonexistent address. Because no address receives this
ACK/SYN, the victim server just waits for the ACK from the client. The ACK
never arrives, and the victim server eventually times out. If the attacker sends
SYN requests often enough, the victim server’s available resources for setting up
a connection will be consumed waiting for these bogus ACKs. These resources
are usually low in number, so relatively few bogus SYN requests can create a
DoS event

# List of proposed features

The system takes live stream IPFIX/Netflow from the machine that the code
is running on as input. The flows can have many attributes. However, not all
of these attributes will be required in the attack detection decision. Two main
features used in this project are:

- Number of SYN requests from a specific source IP
- TCP 3-Way Handshake flags (SYN, SYN-ACK, ACK)

Gathering a set of requests in 3-Second intervals, we can detect what IP has
an abnormal number of requests. Also, we know that TCP is a connectionoriented protocol. It uses various flags to indicate that a connection is being
started or ended, or that the data carries a high priority. Many attacks are
based on altering the TCP flags. With the flags of the request, if there is no
ACK after the second handshake, I can simply understand that this attack is
probably a SYN attack. Also, the threshold for the number of SYN requests
from a single IP is 25, based on other works in this area. However, having
more data, we can have an adaptive threshold which could be more accurate
but requires a lot of data and time and effort.

# Implementation

I used Scapy and Python 2.7 to implement the project. Scapy is a Python
program that enables the user to send, sniff and dissect and forge network packets. This capability allows construction of tools that can probe, scan or attack
networks. In other words, Scapy is a powerful interactive packet manipulation
program. It is able to forge or decode packets of a wide number of protocols,
send them on the wire, capture them, match requests and replies, and much
more. Scapy can easily handle most classical tasks like scanning, tracerouting,
probing, unit tests, attacks or network discovery. It can replace hping, arpspoof,
arp-sk, arping, p0f and even some parts of Nmap, tcpdump, and tshark).

In order to test the detection algorithm, I used Kali Metasploit framework.
The Metasploit Project is a computer security project that provides information
about security vulnerabilities and aids in penetration testing and IDS signature
development. In figure below, you can see a sample of running SYN Flood
attack on the victim machine.

In the output, we log the system behaviour every 3 seconds. If an attack is
detected, the system outputs the time of the attack as well as it’s source. Below,
you can see a part of a sample output.
