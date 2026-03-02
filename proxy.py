from scapy.all import *

IFACE3 = "enp0s3"
IFACE8 = "enp0s8"
REAL_IP = "192.168.137.1"
REAL_MAC = "0a:00:27:00:00:37"
FAKE_IP = "192.168.10.30"
FAKE_MAC = "10:20:30:40:50:60"


def send_packets(packet):
    new_packet = packet
    if IP in packet and new_packet[IP].src == REAL_IP:
        new_packet[IP].src = FAKE_IP
        new_packet[Ether].src = FAKE_MAC
        sendp(new_packet, iface=IFACE3)
    elif IP in packet and new_packet[IP].dst == FAKE_IP:
        new_packet[IP].dst = REAL_IP
        new_packet[Ether].dst = REAL_MAC
        sendp(new_packet, iface=IFACE8)


def main():
    sniff(iface=[IFACE3, IFACE8], filter="inbound", prn=send_packets)


if __name__ == "__main__":
    main()
