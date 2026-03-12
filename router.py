from scapy.all import *

MAC3 = "08:00:27:aa:71:bc"
MAC8 = "08:00:27:a2:86:70"
FAKE_MAC3 = "08:00:27:aa:71:ab"
FAKE_MAC8 = "08:00:27:a2:86:80"


def send_packets(packet):
    new_packet = packet
    if IP in packet and packet.dst in Net("10.100.102.0/24") and new_packet.sniffed_on == "enp0s8":
        new_packet[Ether].src = MAC3
        new_packet[Ether].dst = FAKE_MAC3
        new_packet.ttl = packet.ttl - 1
        sendp(new_packet, iface="enp0s3")
    
    elif IP in packet and packet.dst in Net("92.168.137.0/24") and new_packet.sniffed_on == "enp0s3":
        new_packet[Ether].src = MAC8
        new_packet[Ether].dst = FAKE_MAC8
        new_packet.ttl = packet.ttl - 1
        sendp(new_packet, iface="enp0s8")

def main():
    sniff(iface=["enp0s8", "enp0s3"], filter="inbound", prn=send_packets)


if __name__ == "__main__":
    main()
