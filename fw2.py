from scapy.all import *


class session:
    port = 40000
    def __init__(self, src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.new_port = session.port
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        session.port += 1


IFACE3 = "enp0s3"
IFACE8 = "enp0s8"
REAL_IP = "192.168.137.1"
REAL_MAC = "0a:00:27:00:00:37"
FAKE_IP = "192.168.10.30"
FAKE_MAC = "10:20:30:40:50:60"
sessions = []


def firewall(packet):
    rules = [not (UDP in packet and packet.dport == 12345), not (UDP in packet and packet.dport == 12346)]
    flag = True
    for rule in rules:
        if rule:
            flag = False
            break
    return flag


def send_packets(packet):
    new_packet = packet
    if firewall(packet):
        if IP in packet and new_packet.sniffed_on == IFACE8:
            new_packet[IP].src = FAKE_IP
            new_packet[Ether].src = FAKE_MAC
            if ICMP in packet:
                exists = [s for s in range(len(sessions)) if packet[IP].src == sessions[s].src_ip
                and packet[IP].dst == sessions[s].dst_ip and packet[ICMP].seq == sessions[s].src_port]
                if exists:
                    sessions[exists[0]].src_port += 1
                else:
                    sessions.append(session(packet[IP].src, packet[IP].dst,
                    packet[ICMP].seq, None, packet[Ether].src, packet[Ether].dst))
            else:
                exists = [s for s in range(len(sessions)) if packet[IP].src == sessions[s].src_ip
                and packet[IP].dst == sessions[s].dst_ip and packet.sport == sessions[s].src_port
                and packet.dport == sessions[s].dst_port]
                if not exists:
                    sessions.append(session(packet[IP].src, packet[IP].dst
                    packet.sport, packet.dport, packet[Ether].src, packet[Ether].dst))
                    new_packet.sport = sessions[-1].new_port

            sendp(new_packet, iface=IFACE3)

        elif IP in packet and new_packet[IP].dst == FAKE_IP:
            new_packet[IP].dst = REAL_IP
            new_packet[Ether].dst = REAL_MAC
            if ICMP in packet:
                exists = [s for s in range(len(sessions)) if packet[IP].src == sessions[s].dst_ip
                and packet[ICMP].seq == sessions[s].src_port]
                if exists:
                    sendp(new_packet, iface=IFACE8)
            else:
                exists = [s for s in range(len(sessions)) if packet[IP].src == sessions[s].dst_ip
                and packet.sport == sessions[s].dst_port and packet.dport == sessions[s].new_port]
                if exists:
                    new_packet.dport = exists[0].src_port
                    sendp(new_packet, iface=IFACE8)


def main():
    sniff(iface=[IFACE3, IFACE8], filter="inbound and (udp or tcp or icmp)", prn=send_packets)


if __name__ == "__main__":
    main()
