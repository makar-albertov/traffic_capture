import time
from typing import Set
import scapy.interfaces
from scapy.all import *
import threading
import argparse
import csv
from multiprocessing import Queue, Process

def print_interfaces():
    print(scapy.interfaces.show_interfaces())


#calculate aver len
def aver_len(p_count, total_len):
    return round(total_len / p_count, 2)


def sniffer(path='capture.csv', capture_time = 5, interf = 'eth0'):
    header = ['time', 'number', 'count_packets', 'aver_packet_len', 'min_packet_len', 'max_packet_len', 'count_unicast',
              'count_multicast', 'count_segmented', 'count_ports_src', 'count_ports_dest','count_tcp',
              'count_udp', 'count_other_protocols', 'count_icmp', 'count_encrypted', 'count_with_opts',
              'count_syn', 'count_fin']
    num = 0
    print(*header, sep='\t')
    while True:
        data_pcap = sniff(timeout=capture_time, iface=interf)
        buffer: list = list()
        p_count: int = 0
        count_tcp: int = 0
        count_udp: int = 0
        count_icmp: int = 0
        count_other_prot: int = 0
        total_length: int = 0
        aver_length: float = 0
        count_multicast: int = 0
        count_unicast: int = 0
        count_encrypt: int = 0
        count_ip_opts: int = 0
        count_fragment: int = 0
        count_syn: int = 0
        count_fin: int = 0
        src_port: Set[int] = set()
        dst_port: Set[int] = set()
        if len(data_pcap) != 0:
            p_len_min: int = len(data_pcap[0])
            p_len_max: int = len(data_pcap[0])
            for packet in data_pcap:
                p_count += 1
                total_length += len(packet)
                if len(packet) > p_len_max:
                    p_len_max = len(packet)
                if len(packet) < p_len_min:
                    p_len_min = len(packet)
                eth_src = packet.getlayer('Ether').src
                eth_dst = packet.getlayer('Ether').dst
                if eth_dst == "ff:ff:ff:ff:ff:ff":
                    count_multicast += 1
                else:
                    count_unicast += 1
                if packet.haslayer('IP'):
                    p_src_ip = packet.getlayer('IP').src
                    p_dst_ip = packet.getlayer('IP').dst
                    # check for options in packet
                    if packet['IP'].options:
                        count_ip_opts += 1
                    #check for fragmentation in packet
                    if packet['IP'].flags == 1:
                        count_fragment += 1
                    if packet.haslayer('TCP'):
                        src_port.add(packet['TCP'].sport)
                        dst_port.add(packet['TCP'].dport)
                        count_tcp += 1
                        if packet.haslayer('TLS') or packet.haslayer('SSL'):
                            count_encrypt += 1
                        elif packet['TCP'].flags == 0x01:
                            count_fin += 1
                        elif packet['TCP'].flags == 0x02:
                            count_syn += 1
                elif packet.haslayer('UDP'):
                    count_udp += 1
                    src_port.add(packet['UDP'].sport)
                    dst_port.add(packet['UDP'].dport)
                elif packet.haslayer('ICMP'):
                    count_icmp += 1
                else:
                    count_other_prot += 1
            aver_length = aver_len(p_count, total_length)
        elif len(data_pcap) == 0:
            p_len_min = 0
            p_len_max = 0
        buffer = [time.strftime("%d.%m.%Y, %H:%M:%S", time.localtime()), num, p_count, aver_length, p_len_max, p_len_min,
                count_unicast, count_multicast, count_fragment, len(src_port), len(dst_port), count_tcp, count_udp,
                count_other_prot, count_icmp, count_encrypt, count_ip_opts, count_syn, count_fin]
        print(*buffer, sep='\t')
        with open(path, "a", newline='') as file:
            is_empty = os.path.getsize(path) == 0
            writer = csv.writer(file, lineterminator='\n')
            if is_empty:
                writer.writerow(header)
            writer.writerow(buffer)
        num += 1



def main():
    parser = argparse.ArgumentParser(description='capture traffic from the interface. Parametres'
                                     'time, packet_number, packet_count, aver_length_of_packet, packet_len_max, '
                                     'packet_len_min, count_unicast, count_multicast, count_fragment, '
                                     'count_differ_src_port, count_differ_dst_port, count_tcp, count_udp, '
                                     'count_other_transport_protocols, count_icmp, count_encrypt, count_ip_opts,'
                                     ' count_syn, count_fin')
    subparser = parser.add_subparsers(dest='subparser_command')
    list_interfaces = subparser.add_parser('list_of_interfaces',
                                           description='Show interfaces')

    capture_traffic = subparser.add_parser('capture', description='capture traffic')
    capture_traffic.add_argument('interface', type=int, default=1, help='index of interface')
    capture_traffic.add_argument('-t', '--time',type=int, default=10, help='specify agregate interfal for traffic '
                                                                           'capture, sec')
    args = parser.parse_args()
    if args.subparser_command == 'list_of_interfaces':
        print_interfaces()
    elif args.subparser_command == 'capture':
        sniffer(interf=scapy.interfaces.dev_from_index(args.interface), capture_time=args.time)

if __name__ == '__main__':
    main()