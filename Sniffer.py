My first task is about building a network sniffer in Python that captures and analyzes network traffic. 

import platform
import socket
import pyshark
import struct

def sniff_packets(interface, save_to_file=False, verbose=False):
    if platform.system() == 'Windows':
        print("Packet sniffing using PyShark (WinPcap/Npcap) on Windows.")
        capture = pyshark.LiveCapture(interface=interface)
        if save_to_file:
            file_path = "captured_packets.txt"
            with open(file_path, 'w') as file:
                capture.sniff(timeout=None)
                for packet in capture:
                    file.write(str(packet) + '\n')
                if verbose:
                    print("Packets saved to file.")
        else:
            capture.sniff(timeout=None)
            for packet in capture:
                packet_callback(packet, verbose)
    elif platform.system() in ['Linux', 'Darwin']:  # Unix-like systems
        print("Packet sniffing using raw sockets on Unix-like system.")
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

        if save_to_file:
            file_path = "captured_packets.txt"
            with open(file_path, 'wb') as file:
                while True:
                    raw_data, _ = conn.recvfrom(65536)
                    file.write(raw_data)
                    if verbose:
                        print("Packet saved to file.")
        else:
            while True:
                raw_data, _ = conn.recvfrom(65536)  # Capture packets with a maximum length of 65536 bytes
                packet_callback(raw_data, verbose)

def packet_callback(pkt, verbose=False):
    dest_mac, src_mac, eth_proto = pkt[:6], pkt[6:12], pkt[12:14]
    if verbose:
        print(f'Ethernet Frame: Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {socket.htons(struct.unpack("!H", eth_proto)[0])}')

    if eth_proto == b'\x08\x00':  # IPv4
        ip_header = pkt[14:34]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 0xF) * 4
        ttl = iph[5]
        protocol = iph[6]
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])
        if verbose:
            print(f'IP Packet: Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}')

if __name__ == '__main__':
    interface = input("Enter the interface name (e.g., eth0, wlan0): ")
    save_to_file = input("Do you want to save packets to a file? (y/n): ").lower() == 'y'
    verbose = input("Do you want to enable verbose mode? (y/n): ").lower() == 'y'
    sniff_packets(interface, save_to_file, verbose)
