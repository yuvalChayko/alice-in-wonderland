from scapy.all import *

MAC = "08:00:27:aa:71:bc"

def send_packets(packet):
    new_packet = packet
    if IP in packet and packet.dst in Net("10.100.102.0/24"):
        new_packet[Ether].src = MAC
        new_packet.ttl = packet.ttl - 1
        sendp(new_packet, iface="enp0s3")

def main():
    sniff(iface="enp0s8", prn=send_packets)


if __name__ == "__main__":
    main()
