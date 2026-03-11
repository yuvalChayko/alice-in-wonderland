from scapy.all import *

MAC = "08:00:27:aa:71:bc"
TABLE = {"10.100.102.2": "10:20:30:40:50:60", "10.100.102.3": "20:30:40:50:60:70"}


def send_packets(packet):
    new_packet = packet
    if IP in packet and packet.dst in Net("10.100.102.0/24") and packet.dst in TABLE.keys():
        new_packet[Ether].src = MAC
        new_packet[Ether].dst = TABLE[new_packet.dst]
        new_packet.ttl = packet.ttl - 1
        sendp(new_packet, iface="enp0s3")

def main():
    sniff(iface="enp0s8", prn=send_packets)


if __name__ == "__main__":
    main()
