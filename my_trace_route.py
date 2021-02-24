# -*- coding:utf-8 -*-
"""
    Use ICMP/TCP/UDP to trace the route to target
"""
import q
import time
import random
from struct import pack, unpack
from socket import inet_aton, inet_ntoa
import pcap
import socket


def checksum(tcp_header):
    s = 0
    for i in range(0, len(tcp_header), 2):
        w = (tcp_header[i] << 8) + (tcp_header[i + 1])
        s = s + w
    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff
    return s


def packet_ether_header(dst_mac, src_mac, ether_type=0x0800):

    ether_header = b"%s%s%s" % (bytes.fromhex(dst_mac.replace(":", "")), bytes.fromhex(src_mac.replace(":", "")), bytes.fromhex("{0:04x}".format(ether_type)))

    return ether_header


def pack_ip(src_ip, dst_ip, id, ttl, ptype, ip_dlen):

    get_ipheader = lambda iph_checksum: pack("!BBHHHBBH4s4s", 69, 0, 20 + ip_dlen, id, 0, ttl, ptype, iph_checksum, src_ip, dst_ip)
    ip_header = get_ipheader(0)
    iph_checksum = checksum(ip_header)
    ip_header = get_ipheader(iph_checksum)

    return ip_header


def pack_tcp(src_ip, dst_ip, src_port, dst_port, seq, ack, flags=0b000010):
    get_tcpheader = lambda tcph_checksum: pack("!HHLLBBHHH", src_port, dst_port, seq, ack, 80, flags, 53270, tcph_checksum, 0)
    tcp_header = get_tcpheader(0)
    psh = pack("!4s4sBBH", src_ip, dst_ip, 0, 6, 20)
    tcph_checksum = checksum(psh + tcp_header)
    tcp_header = get_tcpheader(tcph_checksum)

    return tcp_header


def pack_udp(src_ip, dst_ip, src_port, dst_port):
    get_udpheader = lambda udph_checksum: pack("!HHHH", src_port, dst_port, 32, udph_checksum)
    udp_header = get_udpheader(0)
    psh = pack("!4s4sBBH", src_ip, dst_ip, 0, 17, 8 + 32)
    udp_data = (dst_port).to_bytes(2, byteorder="big") * (32 // 2)

    udph_checksum = checksum(psh + udp_header + udp_data)
    udp_header = get_udpheader(udph_checksum)

    return udp_header + udp_data


def pack_icmp(src_ip, dst_ip, id, seq):
    get_icmpheader = lambda icmph_checksum: pack("!BBHHH", 8, 0, icmph_checksum, id, seq)
    icmp_header = get_icmpheader(0)
    icmp_data = bytes.fromhex("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")   # MacOS PING

    icmph_checksum = checksum(icmp_header + icmp_data)
    icmp_header = get_icmpheader(icmph_checksum)

    return icmp_header + icmp_data


def sender(settings):

    pp_socket = pcap.pcap(name=settings["interface"], promisc=False)

    src_ip = socket.inet_aton(settings["src_ip"])
    dst_ip = socket.inet_aton(settings["dst_ip"])

    local_mac = settings["local_mac"]
    gateway_mac = settings["gateway_mac"]

    isend = 1
    while isend <= MAX_ROUTE:

        # packet = packet_ether_header(
        #     gateway_mac,
        #     local_mac
        # ) + pack_ip(
        #     src_ip,
        #     dst_ip,
        #     settings["checkid"] + isend,
        #     ttl=isend,
        #     ptype=6,
        #     ip_dlen=20,
        # ) + pack_tcp(
        #     src_ip,
        #     dst_ip,
        #     settings["checkid"] + isend,
        #     settings["checkid"] + isend,
        #     settings["checkid"] + isend,
        #     0,
        #     0b000010            # 除了 SYN 都没有返回（可能被网关抛弃了）
        # )
        # pcap.pcap.sendpacket(pp_socket, packet)

        # packet = packet_ether_header(
        #     gateway_mac,
        #     local_mac
        # ) + pack_ip(
        #     src_ip,
        #     dst_ip,
        #     settings["checkid"] + isend,
        #     ttl=isend,
        #     ptype=17,
        #     ip_dlen=32,
        # ) + pack_udp(
        #     src_ip,
        #     dst_ip,
        #     settings["checkid"] + isend,
        #     settings["checkid"] + isend,
        # )
        # pcap.pcap.sendpacket(pp_socket, packet)

        packet = packet_ether_header(
            gateway_mac,
            local_mac
        ) + pack_ip(
            src_ip,
            dst_ip,
            settings["checkid"] + isend,
            ttl=isend,
            ptype=1,
            ip_dlen=56,
        ) + pack_icmp(
            src_ip,
            dst_ip,
            settings["checkid"] + isend,
            settings["checkid"] + isend,
        )
        pcap.pcap.sendpacket(pp_socket, packet)

        yield False

        isend += 1

    yield True


def receiver(settings):

    wrap_checker = checker(settings)

    def do(packet):
        """
            ICMP 包返回的信息，前面 8 个字节是 ICMP 头，紧跟在后面的是之前收到的数据
                - 完整的 IP 数据，但因为 TTL 每经过一次中转会 -1，所以最终收到的 TTL 都是 1
                    - 既然 TTL 会变，checksum 自然每次也会被重新计算出不一样的值
        """

        raw_packet = packet
        ether_len = 14

        ihl = raw_packet[ether_len] << 2 & 0b111100
        src_ip = inet_ntoa(raw_packet[ether_len + 12: ether_len + 16])
        dst_ip = inet_ntoa(raw_packet[ether_len + 16: ether_len + 20])
        ip_dlen = raw_packet[ether_len + 2] << 8 | raw_packet[ether_len + 3]

        icmp_packet = raw_packet[ether_len + ihl: ether_len + ip_dlen]
        ip_hdata = unpack("!BBHHHBBH4s4s", icmp_packet[8:28])
        raw_src_ip = inet_ntoa(ip_hdata[8])
        raw_dst_ip = inet_ntoa(ip_hdata[9])

        ttl = wrap_checker(icmp_packet)
        if ttl:
            # 在此处理 预期的返回
            print("%s (%s -> %s): %s -> %s" % (ttl, raw_src_ip, raw_dst_ip, src_ip, dst_ip))

    return do


def checker(settings):

    def do(icmp_packet):

        if icmp_packet[0] == 0x0b:    # Type=11，TTL 超时
            ip_hdata = unpack("!BBHHHBBH4s4s", icmp_packet[8:28])
            id = ip_hdata[3]
            ttl = ip_hdata[5]

            # 校验 IP 包
            if ttl == 1:
                if settings["checkid"] <= id <= settings["checkid"] + MAX_ROUTE:

                    ip_hlen = icmp_packet[8] << 2 & 0b111100

                    # 有些网关有长度限制，只返回 src_port+dst_port+seq，ip_dlen 的值不可信
                    # id_dlen = ip_hdata[2]

                    # 校验 ICMP 包
                    if ip_hdata[6] == 1:    # ICMP
                        icmp_header = icmp_packet[8 + ip_hlen: 8 + ip_hlen + 8]
                        if id == int.from_bytes(icmp_header[4:6], "big") == int.from_bytes(icmp_header[6:8], "big"):
                            return "tcp", id - settings["checkid"]

                    # 校验 TCP 包
                    if ip_hdata[6] == 6:    # TCP
                        tcp_header = icmp_packet[8 + ip_hlen: 8 + ip_hlen + 4]
                        if id == int.from_bytes(tcp_header[0:2], "big") == int.from_bytes(tcp_header[2:4], "big"):
                            return "tcp", id - settings["checkid"]

                    # 校验 UDP 包
                    if ip_hdata[6] == 17:    # UDP
                        udp_header = icmp_packet[8 + ip_hlen: 8 + ip_hlen + 4]
                        if id == int.from_bytes(udp_header[0:2], "big") == int.from_bytes(udp_header[2:4], "big"):
                            return "udp", id - settings["checkid"]

    return do


MAX_ROUTE = 64      # 最长链路
SEND_PERIOD = 128   # 发送探测包周期 毫秒
CLEANUP_TIMEOUT = 3000  # 最后的超时时间 毫秒


def main():

    settings = {
        "interface": "en0",
        "src_ip": "192.168.8.86",
        # "dst_ip": "14.215.177.39",
        "dst_ip": "163.177.151.110",
        "local_mac": "18:65:90:cc:45:b9",
        "gateway_mac": "00:00:00:00:00:00",
    }
    settings["checkid"] = random.randint(10000, 40000)

    sniffer = pcap.pcap(name=settings["interface"], promisc=False, immediate=True, timeout_ms=50)
    ts = time.time()
    iter_sender = sender(settings)
    wrap_receiver = receiver(settings)
    start_cleanup = False
    # ether_len = 14

    while True:

        _, packet = next(sniffer, (None, None))

        if packet[12] == 8:         # IP

            if packet[23] == 1:     # ICMP
                wrap_receiver(packet)

            if packet[23] == 6:     # TCP
                if False:           # 如果顺利连接上，判断 tcp 的 seq 即可知道 ttl 数量 （忽略，关闭的端口很可能不会返回任何信息）
                    pass

                    # ihl = packet[ether_len] << 2 & 0b111100

                    # src_port = packet[ether_len + ihl: ether_len + ihl + 2]
                    # dst_port = packet[ether_len + ihl + 2: ether_len + ihl + 4]

                    # if src_port == dst_port:
                    #     ack = int.from_bytes(packet[ether_len + ihl + 8:ether_len + ihl + 12], "big")

                    #     if int.from_bytes(src_port) == int.from_bytes(dst_port) == ack - 1:
                    #         print("All is done!")
                    #         pass

                    #     q.d()

        if start_cleanup:
            if time.time() - ts >= CLEANUP_TIMEOUT * 0.001:
                print("time up.")
                break
            else:
                pass
        elif time.time() - ts >= SEND_PERIOD * 0.001:
            ts = time.time()

            done = next(iter_sender, None)
            if done:
                start_cleanup = True


if __name__ == "__main__":
    main()
