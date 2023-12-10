import argparse
import json
from scapy.all import rdpcap
from collections import Counter

def load_known_ports(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def count_ports(pcap_file, target_ip, known_ports, target_flag):
    packets = rdpcap(pcap_file)
    src_ports = []
    dst_ports = []
    dst_ips = []

    for packet in packets:
        if packet.haslayer('IP'):
            if target_ip and packet['IP'].dst == target_ip:
                collect_ports(packet, src_ports, dst_ports)
            elif not target_ip and target_flag:
                collect_ports(packet, src_ports, dst_ports)
                dst_ips.append(packet['IP'].dst)

    print_top_ports(src_ports, "SRC", known_ports)
    print("──────────────────────────────────────────")
    print_top_ports(dst_ports, "DST", known_ports)
    if not target_ip and target_flag:
        print("──────────────────────────────────────────")
        print_top_ips(dst_ips, "Top 5 DST IP Adresy")

def collect_ports(packet, src_ports, dst_ports):
    if packet.haslayer('TCP'):
        src_ports.append(packet['TCP'].sport)
        dst_ports.append(packet['TCP'].dport)
    elif packet.haslayer('UDP'):
        src_ports.append(packet['UDP'].sport)
        dst_ports.append(packet['UDP'].dport)

def print_top_ports(ports, port_type, known_ports):
    count = Counter(ports)
    for port, number in count.most_common(10):
        service = known_ports.get(str(port))
        service_info = f", Proto: {service} (kanskje)" if service else ""
        print(f"{port_type} Port: {port}, Liczba pakietów: {number}{service_info}")

def print_top_ips(ips, title):
    count = Counter(ips)
    print(title)
    for ip, number in count.most_common(5):
        print(f"Adres IP: {ip}, Liczba pakietów: {number}")

def main():
    parser = argparse.ArgumentParser(description='Zlicza pakiety według portów źródłowych i docelowych w pliku pcap, opcjonalnie listując najczęstsze adresy IP docelowe.')
    parser.add_argument('pcap_file', type=str, help='Ścieżka do pliku pcap')
    parser.add_argument('--target_ip', type=str, help='Docelowy adres IP lub podsieć do filtrowania')
    parser.add_argument('--target', action='store_true', help='Flaga do listowania top docelowych adresów IP bez filtrowania')
    parser.add_argument('--ports_db', type=str, default='TLports.json', help='Ścieżka do pliku JSON z bazą znanych portów')

    args = parser.parse_args()
    known_ports = load_known_ports(args.ports_db)
    count_ports(args.pcap_file, args.target_ip, known_ports, args.target)

if __name__ == '__main__':
    main()
