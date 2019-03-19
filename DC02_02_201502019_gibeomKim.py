import socket
import struct

def parsing_ethernet_header(data):
    ethernet_header = struct.unpack("!6c6c2s", data)
    ether_src = convert_ethernet_address(ethernet_header[0:6])
    ether_dest = convert_ethernet_address(ethernet_header[6:12])
    ip_header = "0x"+ethernet_header[12].hex()

    print("======ehternet header======")
    print("src_mac_address:", ether_src)
    print("dest_mac_address:", ether_dest)
    print("ip_version",ip_header)

def convert_ethernet_address(data):
    ethernet_addr = list()
    for i in data:
        ethernet_addr.append(i.hex())
    ethernet_addr = ":".join(ethernet_addr)
    return ethernet_addr

def parsing_ip_header(data):
    ip_header = struct.unpack("!1B1BH2sh1B1B2s4B4B", data)
    ip_version = (ip_header[0] & 0xF0) >> 4
    ip_length = ip_header[0] & 0x0F
    differentiated_service_codepoint = (ip_header[1] & 0xFC) >> 2
    explicit_congestion_notification = ip_header[1] & 0x03
    total_length = ip_header[2]
    identification = "0x"+ip_header[3].hex()
    flags = hex(ip_header[4])
    reserved_bit = (ip_header[4] & 0x8000) >> 15
    not_fragment = (ip_header[4] & 0x4000) >> 14
    fragment = (ip_header[4] & 0x2000) >> 13
    fragment_offsets = (ip_header[4] & 0x1FFF)
    time_to_live = ip_header[5]
    protocol = ip_header[6]
    header_checksum = "0x" + ip_header[7].hex()
    source_ip_address = convert_ip_address(ip_header[8:12])
    dest_ip_address = convert_ip_address(ip_header[12:16])

    print("======ip_header======")
    print("ip_version:", ip_version)
    print("ip_length:", ip_length)
    print("differentiated_service_codepoint:", differentiated_service_codepoint)
    print("explicit_congestion_notification:", explicit_congestion_notification)
    print("total_lenght:", total_length)
    print("identification:", identification)
    print("flags:", flags)
    print(">>>reserved_bit:", reserved_bit)
    print(">>>not_fragments:", not_fragment)
    print(">>>fragment:", fragment)
    print(">>>fragments_offset:", fragment_offsets)
    print("time_to_live:",time_to_live)
    print("protocol:", protocol)
    print("header_checksum:", header_checksum)
    print("source_ip_address:", source_ip_address)
    print("dest_ip_address:", dest_ip_address)
    return protocol

def convert_ip_address(data):
    ip_addr = list()
    for i in data:
        ip_addr.append(str(i))
    ip_addr = ".".join(ip_addr)
    return ip_addr

def parsing_tcp_header(data):
    tcp_header = struct.unpack("!HHIIHH2sH", data)
    src_port = tcp_header[0]
    dst_port = tcp_header[1]
    seq_num = tcp_header[2]
    ack_num = tcp_header[3]
    header_len = (tcp_header[4] & 0xF000) >> 12
    flags = tcp_header[4] & 0x0FFF
    reserved = (tcp_header[4] & 0x0E00) >> 9
    nonce = (tcp_header[4] & 0x0100) >> 8
    cwr = (tcp_header[4] & 0x0080) >> 7
    ece = (tcp_header[4] & 0x0040) >> 6
    urgent = (tcp_header[4] & 0x0020) >> 5
    ack = (tcp_header[4] & 0x0010) >> 4
    push = (tcp_header[4] & 0x0008) >> 3
    reset = (tcp_header[4] & 0x0004) >> 2
    syn = (tcp_header[4] & 0x0002) >> 1
    fin = tcp_header[4] & 0x0001
    window_size_value = tcp_header[5]
    checksum = "0x" + tcp_header[6].hex()
    urgent_pointer = tcp_header[7]

    print("======tcp_header======")
    print("src_port:", src_port)
    print("dst_port:", dst_port)
    print("seq_num:", seq_num)
    print("ack_num:", ack_num)
    print("header_len:", header_len)
    print("flags:", flags)
    print(">>>reserved:", reserved)
    print(">>>nonce:", nonce)
    print(">>>cwr:", cwr)
    print(">>>ece:", ece)
    print(">>>urgent:", urgent)
    print(">>>ack:", ack)
    print(">>>push:", push)
    print(">>>reset:", reset)
    print(">>>syn:", syn)
    print(">>>fin:", fin)
    print("window_size_value:", window_size_value)
    print("checksum:", checksum)
    print("urgent_pointer:", urgent_pointer)

def parsing_udp_header(data):
    udp_header = struct.unpack("!HHH2s", data)
    src_port = udp_header[0]
    dst_port = udp_header[1]
    leng = udp_header[2]
    header_checksum = "0x" + udp_header[3].hex()

    print("======udp_header======")
    print("src_port:", src_port)
    print("dst_port:", dst_port)
    print("leng:",leng)
    print("header_checksum:", header_checksum)

recv_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x800))
print("<<<<<<Packet Caputure Start>>>>>>")

while True:
    data = recv_socket.recvfrom(20000)
    parsing_ethernet_header(data[0][0:14])
    protocol = parsing_ip_header(data[0][14:34])
    if protocol == 0x06:
        parsing_tcp_header(data[0][34:54])
    elif protocol == 0x11:
        parsing_udp_header(data[0][34:42])
