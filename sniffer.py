import argparse
from scapy.all import sniff

class Sniffer:
    def __init__(self, args):
        self.args = args  # Store arguments for later use
     
    # Special __call__ method — lets us use self like a function in sniff().
    def __call__(self, packet):
        if self.args.verbose:
            packet.show()
        # shows detailed packet info
        else:
            print(packet.summary())
         
    def run_forever(self):
        sniff(iface=self.args.interface, prn=self, store=0)
        #For every packet captured, it calls self(packet) which is your __call__() function.
     
parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", default=False, action="store_true", help="be more talkative")
parser.add_argument("-i", "--interface", type=str, required=True, help="network interface name")
# divide the arguments provided by the user
args = parser.parse_args()

#instance of Sniffer class
sniffer = Sniffer(args)
# Start sniffer
sniffer.run_forever()
