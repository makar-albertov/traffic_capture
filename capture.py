import scapy.interfaces
from scapy.all import *
import argparse
import csv
import sys
import signal
import datetime

from headers import base_header


def print_interfaces():
    print(scapy.interfaces.show_interfaces())


def signal_sigint_handler(signal, frame):
    print('[*] Operation aborted')
    sys.exit()


def save_to_csv(path_out_csv='out.csv', buffer=None):
    if buffer is None:
        buffer = list()
    with open(path_out_csv, "a", newline='') as file:
        is_empty = os.path.getsize(path_out_csv) == 0
        writer = csv.writer(file, lineterminator='\n')
        if is_empty:
            writer.writerow(base_header)
        writer.writerow(buffer)


def parser(data_pcap, num: int = 0, pcap_time=None):
    p_len_min = 0
    p_len_max = 0
    buffer: list = list()
    aver_len = lambda x, y: round(x / y, 2) if y != 0 else 0
    if pcap_time is None:
        local_time = time.strftime("%d.%m.%Y, %H:%M:%S", time.localtime())
    else:
        local_time = datetime.datetime.fromtimestamp(int(pcap_time)).strftime("%d.%m.%Y, %H:%M:%S")
    p_count: int = 0
    count_tcp: int = 0
    count_udp: int = 0
    count_icmp: int = 0
    count_other_prot: int = 0
    total_length: int = 0
    count_multicast: int = 0
    count_unicast: int = 0
    count_encrypt: int = 0
    count_ip_opts: int = 0
    count_fragment: int = 0
    count_syn: int = 0
    count_fin: int = 0
    src_tcp_port: Set[int] = set()
    dst_tcp_port: Set[int] = set()
    src_udp_port: Set[int] = set()
    dst_udp_port: Set[int] = set()
    if len(data_pcap) != 0:
        p_len_min: int = len(data_pcap[0])
        p_len_max: int = len(data_pcap[0])
        for packet in data_pcap:
            p_count += 1
            total_length += len(packet)
            if len(packet) > p_len_max:
                p_len_max = len(packet)
            elif len(packet) < p_len_min:
                p_len_min = len(packet)
            eth_dst = packet.getlayer('Ether').dst
            if eth_dst.startswith("01:00:5e") or eth_dst.startswith("33:33"):
                count_multicast += 1
            elif eth_dst != 'ff:ff:ff:ff:ff:ff':
                count_unicast += 1
            if packet.haslayer('IP'):
                # check for options in packet
                if packet['IP'].options:
                    count_ip_opts += 1
                # check for fragmentation in packet
                if packet['IP'].flags:
                    count_fragment += 1
                if packet.haslayer('TCP'):
                    count_tcp += 1
                    src_tcp_port.add(packet['TCP'].sport)
                    dst_tcp_port.add(packet['TCP'].dport)
                    if packet.haslayer('TLS') or packet.haslayer('SSL'):
                        count_encrypt += 1
                    if packet['TCP'].flags == 0x01:
                        count_fin += 1
                    if packet['TCP'].flags == 0x02:
                        count_syn += 1
                elif packet.haslayer('UDP'):
                    count_udp += 1
                    src_udp_port.add(packet['UDP'].sport)
                    dst_udp_port.add(packet['UDP'].dport)
                elif packet.haslayer('ICMP'):
                    count_icmp += 1
                else:
                    count_other_prot += 1
    buffer = [local_time, num, p_count, aver_len(total_length, p_count), p_len_max, p_len_min,
              count_unicast, count_multicast, count_fragment, len(src_tcp_port), len(dst_tcp_port), len(src_udp_port),
              len(dst_udp_port), count_tcp, count_udp,
              count_other_prot, count_icmp, count_encrypt, count_ip_opts, count_syn, count_fin]
    print(*buffer, sep='\t')
    return buffer


def sniffer(path='capture.csv', capture_time=5, interf='eth0'):
    iteration = 0
    print('[*] Capture start')
    print(*base_header, sep='\t')
    while True:
        signal.signal(signal.SIGINT, signal_sigint_handler)
        data_pcap = sniff(timeout=capture_time, iface=interf)
        data = parser(data_pcap, num=iteration)
        save_to_csv(path_out_csv=path, buffer=data)
        iteration += 1


def parse_pcap(path_in_pcap='in.pcap', path_out_csv='out.csv', agregate_time=10):
    packets = rdpcap(path_in_pcap)
    start_time = packets[0].time
    interval_packets = list()
    iteration = 0
    for packet in packets:
        finish_time = start_time + agregate_time
        if packet.time < finish_time:
            interval_packets.append(packet)
        else:
            buffer_str = parser(data_pcap=interval_packets, num=iteration, pcap_time=start_time)
            save_to_csv(path_out_csv=path_out_csv, buffer=buffer_str)
            interval_packets.clear()
            iteration += 1
            start_time = packet.time
    buffer_str = parser(data_pcap=interval_packets, num=iteration, pcap_time=start_time)
    save_to_csv(path_out_csv=path_out_csv, buffer=buffer_str)
    interval_packets.clear()


def main():
    parser = argparse.ArgumentParser(description='capture traffic from the interface. Parametres'
                                                 'time, packet_number, packet_count, aver_length_of_packet, '
                                                 'packet_len_max, '
                                                 'packet_len_min, count_unicast, count_multicast, count_fragment, '
                                                 'count_differ_src_tcp_port, count_differ_dst_tcp_port,'
                                                 'count_differ_src_udp_port, count_differ_dst_udp_port,'
                                                 ' count_tcp, count_udp, '
                                                 'count_other_transport_protocols, count_icmp, count_encrypt, '
                                                 'count_ip_opts, count_syn, count_fin')
    subparser = parser.add_subparsers(dest='subparser_command')
    # subparser show interfaces list
    list_interfaces_subp = subparser.add_parser('list_of_interfaces',
                                                description='Show interfaces')
    # subparser capture traffic
    capture_traffic_subp = subparser.add_parser('capture', description='capture traffic')
    capture_traffic_subp.add_argument('interface', type=int, default=1, help='index of interface')
    capture_traffic_subp.add_argument('-t', '--time', type=int, default=10,
                                      help='specify agregate interfal for traffic '
                                           'capture (default 10), sec')
    # subparser analyse pcap file
    parse_pcap_subp = subparser.add_parser('parse_pcap', description='parse pcap file to csv')
    parse_pcap_subp.add_argument('-i', '--in_pcap', type=str, default='in.pcap', help='specify input pcap file name'
                                                                                      ', default \"in.pcap\"')
    parse_pcap_subp.add_argument('-o', '--out_csv', type=str, default='out.csv', help='specify output csv file name'
                                                                                      ', default \"out.csv\")')
    parse_pcap_subp.add_argument('-a', '--agregate', type=int, default=10, help='specify agregate interfal for traffic '
                                                                                'analyse (default 10), sec')

    args = parser.parse_args()
    if args.subparser_command == 'list_of_interfaces':
        print_interfaces()
    elif args.subparser_command == 'capture':
        sniffer(interf=scapy.interfaces.dev_from_index(args.interface), capture_time=args.time)
    elif args.subparser_command == 'parse_pcap':
        parse_pcap(path_in_pcap=args.in_pcap, path_out_csv=args.out_csv, agregate_time=args.agregate)


if __name__ == '__main__':
    main()
