# -*- coding:utf-8 -*-
import socket
import time
import struct
from struct import pack
import traceback
import random

import pcap

import q


def checksum(tcp_header):
    s = 0
    for i in range(0, len(tcp_header), 2):
        w = (tcp_header[i] << 8) + (tcp_header[i + 1])
        s = s + w
    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff
    return s


def pPacket(source_address, source_port, remote_address, remote_port):

    get_ipheader = lambda iph_checksum: pack("!BBHHHBBH4s4s", 69, 0, 40, 0, 0, 64, 6, iph_checksum, source_address, remote_address)
    ip_header = get_ipheader(0)
    iph_checksum = checksum(ip_header)
    ip_header = get_ipheader(iph_checksum)

    get_tcpheader = lambda tcph_checksum: pack("!HHLLBBHHH", source_port, remote_port, 1000000001, 0, 80, 2, 53270, tcph_checksum, 0)
    tcp_header = get_tcpheader(0)
    psh = pack("!4s4sBBH", source_address, remote_address, 0, 6, 20)
    tcph_checksum = checksum(psh + tcp_header)
    tcp_header = get_tcpheader(tcph_checksum)

    return ip_header + tcp_header


def main():

    pp_socket = pcap.pcap(name="en0")

    """
        网关自带防攻击和过滤数据包的能力，要避免被网关影响判断

        我的 mac "18:65:90:cc:45:b9"
        网关 mac "00:ff:ea:6e:8f:0b"
        目标 mac "00:50:56:26:82:d1"
    """

    source_address = socket.inet_aton("192.168.8.111")      # 伪造任意IP，如果不是自己的 IP，网关把响应数据发到这个 IP (有猫腻)
    remote_address = socket.inet_aton("192.168.1.112")      # 目标的 IP，网关会自动解析 (有猫腻)
    packet = pPacket(source_address, 60002, remote_address, 12345)  # 我的端口 - 目标端口

    local_mac = "18:65:90:cc:45:b9"
    # local_mac = "00:ff:ea:6e:8f:0b"
    # local_mac = "00:50:56:26:82:d1"
    # local_mac = "00:00:00:00:00:00"     # 理论上任意一个 mac 都可以，但会被网关过滤 (有猫腻)

    # gateway_mac = "18:65:90:cc:45:b9"
    # gateway_mac = "00:ff:ea:6e:8f:0b"
    # gateway_mac = "00:50:56:26:82:d1"
    gateway_mac = "00:00:00:00:00:00"   # 只要不是自己的 mac 就可以，网关会自动处理 (有猫腻)

    ether = b"%s%s%s" % (bytes.fromhex(gateway_mac.replace(":", "")), bytes.fromhex(local_mac.replace(":", "")), bytes.fromhex("0800"))
    packet = ether + packet

    # 这里发送的是 完全的，原始的 packet，直接把任意的内容丢出去到网关
    pcap.pcap.sendpacket(pp_socket, packet)


if __name__ == "__main__":
    main()
