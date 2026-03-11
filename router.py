from scapy.all import *

def send_packets(packet):
    sendp(packet, iface="enp0s3")

def main():
    scapy.sniff(iface="enp0s8", prn=send_packets)


if __name__ == "__main__":
    main()
