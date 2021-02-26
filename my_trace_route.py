# -*- coding:utf-8 -*-
"""
    Use ICMP/TCP/UDP to trace the route to target
"""
import time
import random
from struct import pack, unpack
from socket import inet_aton, inet_ntoa
import pcap


def checksum(tcp_header):
    s = 0
    for i in range(0, len(tcp_header), 2):
        w = (tcp_header[i] << 8) + (tcp_header[i + 1])
        s = s + w
    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff
    return s


def packet_ether_header(dst_mac, src_mac, ether_type=0x0800):

    ether_header = b"%s%s%s" % (
        bytes.fromhex(dst_mac.replace(":", "")),
        bytes.fromhex(src_mac.replace(":", "")),
        bytes.fromhex("{0:04x}".format(ether_type))
    )

    return ether_header


def pack_ip(src_ip, dst_ip, id, ttl, ptype, ip_dlen):

    get_ipheader = lambda iph_checksum: pack(
        "!BBHHHBBH4s4s",
        69, 0, 20 + ip_dlen, id, 0, ttl, ptype, iph_checksum, src_ip, dst_ip
    )
    ip_header = get_ipheader(0)
    iph_checksum = checksum(ip_header)
    ip_header = get_ipheader(iph_checksum)

    return ip_header


def pack_tcp(src_ip, dst_ip, src_port, dst_port, seq, ack, flags=0b000010):
    get_tcpheader = lambda tcph_checksum: pack(
        "!HHLLBBHHH",
        src_port, dst_port, seq, ack, 80, flags, 53270, tcph_checksum, 0
    )
    tcp_header = get_tcpheader(0)
    psh = pack("!4s4sBBH", src_ip, dst_ip, 0, 6, 20)
    tcph_checksum = checksum(psh + tcp_header)
    tcp_header = get_tcpheader(tcph_checksum)

    return tcp_header


def pack_udp(src_ip, dst_ip, src_port, dst_port):
    get_udpheader = lambda udph_checksum: pack("!HHHH", src_port, dst_port, 32, udph_checksum)
    udp_header = get_udpheader(0)
    psh = pack("!4s4sBBH", src_ip, dst_ip, 0, 17, 32)
    udp_data = (dst_port).to_bytes(2, "big") * ((32 - 8) // 2)

    udph_checksum = checksum(psh + udp_header + udp_data)
    udp_header = get_udpheader(udph_checksum)

    return udp_header + udp_data


def pack_icmp(src_ip, dst_ip, id, seq):
    get_icmpheader = lambda icmph_checksum: pack("!BBHHH", 8, 0, icmph_checksum, id, seq)
    icmp_header = get_icmpheader(0)
    icmp_data = bytes.fromhex(
        "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"
    )   # data of MacOS PING

    icmph_checksum = checksum(icmp_header + icmp_data)
    icmp_header = get_icmpheader(icmph_checksum)

    return icmp_header + icmp_data


def sender(settings):

    pp_socket = pcap.pcap(name=settings["interface"], promisc=False)

    src_ip = inet_aton(settings["src_ip"])
    dst_ip = inet_aton(settings["dst_ip"])

    local_mac = settings["local_mac"]
    gateway_mac = settings["gateway_mac"]

    get_ip_header = lambda ptype, ip_dlen: (
        packet_ether_header(
            gateway_mac,
            local_mac
        ) + pack_ip(
            src_ip,
            dst_ip,
            settings["checkid"] + isend,
            ttl=isend,
            ptype=ptype,
            ip_dlen=ip_dlen,
        )
    )

    isend = 1
    while isend <= MAX_ROUTE:

        if not settings["end_tcp"]:
            packet = get_ip_header(6, 20) + pack_tcp(
                src_ip,
                dst_ip,
                settings["checkid"] + isend,
                settings["dst_port"] or (settings["checkid"] + isend),
                settings["checkid"] + isend,
                0,
                0b000010,            # UAPRSF 除了 SYN 都没有返回（可能被网关抛弃了）
            )
            pcap.pcap.sendpacket(pp_socket, packet)

        if not settings["end_udp"]:
            packet = get_ip_header(17, 32) + pack_udp(
                src_ip,
                dst_ip,
                settings["checkid"] + isend,
                settings["dst_port"] or (settings["checkid"] + isend),
            )
            pcap.pcap.sendpacket(pp_socket, packet)

        if not settings["end_icmp"]:
            packet = get_ip_header(1, 56) + pack_icmp(
                src_ip,
                dst_ip,
                settings["checkid"] + isend,
                settings["checkid"] + isend,
            )
            pcap.pcap.sendpacket(pp_socket, packet)

        yield False

        isend += 1
        if settings["end_tcp"] and settings["end_udp"] and settings["end_icmp"]:
            break

    yield True


def receiver(settings):

    def do(icmp_packet, src_ip, dst_ip):
        """
            ICMP 包返回的信息，前面 8 个字节是 ICMP 头，紧跟在后面的是之前收到的数据
                - 完整的 IP 数据，但因为 TTL 每经过一次中转会 -1，所以最终收到的 TTL 都是 1
                    - 既然 TTL 会变，checksum 自然每次也会被重新计算出不一样的值
        """

        ip_hdata = unpack("!BBHHHBBH4s4s", icmp_packet[8:28])
        ip_id = ip_hdata[3]
        ttl = ip_hdata[5]
        res_type, req_id = None, None

        # 校验 IP 包
        if ttl == 1:
            if settings["checkid"] <= ip_id <= settings["checkid"] + MAX_ROUTE:

                ip_hlen = icmp_packet[8] << 2 & 0b111100

                # 有些网关有长度限制，只返回 src_port+dst_port+seq，ip_dlen 的值不可信
                # id_dlen = ip_hdata[2]

                # 校验 ICMP 包
                if ip_hdata[6] == 1:    # ICMP
                    icmp_header = icmp_packet[8 + ip_hlen: 8 + ip_hlen + 8]
                    if ip_id.to_bytes(2, "big") == icmp_header[4:6] == icmp_header[6:8]:
                        res_type, req_id = "icmp", ip_id - settings["checkid"]

                # 校验 TCP 包
                if ip_hdata[6] == 6:    # TCP
                    tcp_header = icmp_packet[8 + ip_hlen: 8 + ip_hlen + 4]

                    src_port = int.from_bytes(tcp_header[0:2], "big")
                    dst_port = int.from_bytes(tcp_header[2:4], "big")

                    # if ip_id.to_bytes(2, "big") == tcp_header[0:2] == tcp_header[2:4]:
                    if ip_id == src_port and (src_port == dst_port or settings["dst_port"] == dst_port):
                        res_type, req_id = "tcp", ip_id - settings["checkid"]

                # 校验 UDP 包
                if ip_hdata[6] == 17:    # UDP
                    udp_header = icmp_packet[8 + ip_hlen: 8 + ip_hlen + 4]

                    src_port = int.from_bytes(udp_header[0:2], "big")
                    dst_port = int.from_bytes(udp_header[2:4], "big")

                    if ip_id == src_port and (src_port == dst_port or settings["dst_port"] == dst_port):
                        res_type, req_id = "udp", ip_id - settings["checkid"]

        # 获得预期的返回，在此处理
        if res_type:

            settings["res"][res_type][req_id] = src_ip
            settings["res"]["max_ttl"] = max(req_id, settings["res"]["max_ttl"])

            ip_hdata = unpack("!BBHHHBBH4s4s", icmp_packet[8:28])
            raw_src_ip = inet_ntoa(ip_hdata[8])
            raw_dst_ip = inet_ntoa(ip_hdata[9])
            print("%s.%s (%s -> %s): %s -> %s" % (
                res_type, req_id, raw_src_ip, raw_dst_ip, src_ip, dst_ip
            ))

    return do


MAX_ROUTE = 64      # 最长链路
SEND_PERIOD = 128   # 发送探测包周期 毫秒
CLEANUP_TIMEOUT = 1000  # 最后的超时时间 毫秒


def main(settings):

    settings["checkid"] = random.randint(10000, 40000)

    settings["end_tcp"] = 0
    settings["end_udp"] = 0
    settings["end_icmp"] = 0
    settings["res"] = {
        "max_ttl": 0,
        "tcp": {},
        "udp": {},
        "icmp": {},
    }

    sniffer = pcap.pcap(name=settings["interface"], promisc=False, immediate=True, timeout_ms=50)
    ts = time.time()
    iter_sender = sender(settings)
    wrap_receiver = receiver(settings)
    start_cleanup = False
    ETHER_LEN = 14

    while True:

        _, packet = next(sniffer, (None, None))

        if packet[12] == 8:         # IP

            ihl = packet[ETHER_LEN] << 2 & 0b111100
            src_ip = inet_ntoa(packet[ETHER_LEN + 12: ETHER_LEN + 16])
            dst_ip = inet_ntoa(packet[ETHER_LEN + 16: ETHER_LEN + 20])
            ip_dlen = packet[ETHER_LEN + 2] << 8 | packet[ETHER_LEN + 3]

            if packet[23] == 1:     # ICMP

                icmp_packet = packet[ETHER_LEN + ihl: ETHER_LEN + ip_dlen]

                # 所有 TTL 超时的数据包（TCP/UDP/ICMP）都会通过 ICMP 超时包(TYPE=11)返回
                if icmp_packet[0] == 11:
                    wrap_receiver(icmp_packet, src_ip, dst_ip)

                # 正常返回的 ICMP 回应包(TYPE=0)，代表已经成功到达
                elif icmp_packet[0] == 0:
                    if icmp_packet[4:6] == icmp_packet[6:8]:
                        req_id = int.from_bytes(icmp_packet[4:6], "big") - settings["checkid"]
                        if 0 <= req_id <= MAX_ROUTE:

                            if settings["end_icmp"] and req_id >= settings["end_icmp"]:
                                pass
                            else:
                                settings["end_icmp"] = req_id

                                settings["res"]["icmp"][req_id] = src_ip
                                settings["res"]["max_ttl"] = max(req_id, settings["res"]["max_ttl"])
                                print("End on icmp.%s : %s -> %s" % (req_id, src_ip, dst_ip))

                # UDP 端口不通 Destination unreachable (TYPE=3)
                elif icmp_packet[0] == 3:
                    # Port unreachable (CODE=3)
                    if icmp_packet[1] == 3:

                        ip_id = icmp_packet[12] << 8 | icmp_packet[13]
                        ip_hlen = icmp_packet[8] << 2 & 0b111100
                        udp_header = icmp_packet[8 + ip_hlen: 8 + ip_hlen + 4]

                        src_port = int.from_bytes(udp_header[0:2], "big")
                        dst_port = int.from_bytes(udp_header[2:4], "big")

                        if ip_id == src_port and (src_port == dst_port or settings["dst_port"] == dst_port):
                            req_id = ip_id - settings["checkid"]
                            if settings["end_udp"] and req_id >= settings["end_udp"]:
                                pass
                            else:
                                settings["end_udp"] = req_id

                                settings["res"]["udp"][req_id] = src_ip
                                settings["res"]["max_ttl"] = max(req_id, settings["res"]["max_ttl"])
                                print("End on udp.%s : %s -> %s" % (req_id, src_ip, dst_ip))

            elif packet[23] == 6:     # TCP
                # 如果顺利到 TCP 层（端口不通被 RST，或端口通 SYN+ACK ），判断 TCP 的 ACK 即可知道 TTL 数
                # *但是关闭的端口很可能不会响应任何信息
                dst_port = int.from_bytes(packet[ETHER_LEN + ihl: ETHER_LEN + ihl + 2], "big")
                src_port = int.from_bytes(packet[ETHER_LEN + ihl + 2: ETHER_LEN + ihl + 4], "big")

                ack = int.from_bytes(packet[ETHER_LEN + ihl + 8:ETHER_LEN + ihl + 12], "big")

                # 要排除发出去的请求
                if ack - 1 == src_port and (dst_port == src_port or settings["dst_port"] == dst_port):
                    req_id = ack - 1 - settings["checkid"]

                    if settings["end_tcp"] and req_id >= settings["end_tcp"]:
                        pass
                    else:
                        settings["end_tcp"] = req_id

                        settings["res"]["tcp"][req_id] = src_ip
                        settings["res"]["max_ttl"] = max(req_id, settings["res"]["max_ttl"])
                        print("End on tcp.%s : %s -> %s" % (req_id, src_ip, dst_ip))

            elif packet[23] == 17:     # UDP
                # 端口不通的在 ICMP 里处理
                # 端口若通，如果 UDP 的数据包无法通过对方校验，通常不会获得响应，所以处理意义不大
                pass

        if start_cleanup:
            if time.time() - ts >= CLEANUP_TIMEOUT * 0.001:
                print("%4s%20s\t\t%20s\t\t%20s" % ("", "ICMP", "TCP", "UDP"))
                for i in range(1, settings["res"]["max_ttl"] + 1):
                    print("%4s%20s\t\t%20s\t\t%20s" % (
                        i,
                        settings["res"]["icmp"].get(i, "*") if (
                            i <= settings["end_icmp"] or settings["end_icmp"] == 0
                        ) else "",
                        settings["res"]["tcp"].get(i, "*") if (
                            i <= settings["end_tcp"] or settings["end_tcp"] == 0
                        ) else "",
                        settings["res"]["udp"].get(i, "*") if (
                            i <= settings["end_udp"] or settings["end_udp"] == 0
                        ) else "",
                    ))

                break

        elif time.time() - ts >= SEND_PERIOD * 0.001:
            ts = time.time()

            done = next(iter_sender, None)
            if done:
                start_cleanup = True


def get_local_addr(ifname):
    """
        通过 python 直接获得 osx 的本地 MAC 比较困难，此处依赖 ifconfig 获取
    """
    import os, re
    mac, ip = None, None
    res_text = os.popen("""ifconfig|grep "^%s:" -A7""" % ifname).read()
    for line in res_text.splitlines():

        re_mac = re.match(r"""^[\W]+ether[\W]+(([0-9a-f]{2}:){5}[0-9a-f]{2})[\W]*$""", line, re.I)
        if re_mac:
            mac = re_mac.groups()[0]

        re_ip = re.match(r"""^[\W]+inet[\W]+(([0-9]{1,3}\.){3}[0-9]{1,3})[\W]+netmask.*$""", line, re.I)
        if re_ip:
            ip = re_ip.groups()[0]

    return mac, ip


def get_host_by_name(name):
    """
        只解析第一个 IP，也可以像 downloader 那样解析多个
    """
    from socket import gethostbyname
    return gethostbyname(name)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("请输入目标 IP 地址")
        exit(1)

    ifname = pcap.lookupdev()    # 自动取第1个活跃的网卡 en0
    local_mac, local_ip = get_local_addr(ifname)
    dst_ip = get_host_by_name(sys.argv[1])
    if dst_ip:
        print("解析 %s 的 IP 地址: %s 成功" % (sys.argv[1], dst_ip))
    else:
        print("解析 %s 的 IP 地址失败" % sys.argv[1])
        exit(1)

    if local_mac and local_ip:
        print("获取本地网卡: %s 的 MAC: %s 和 IP: %s 成功" % (ifname, local_mac, local_ip))
    else:
        print("获取本地网卡 %s 的 MAC 和 IP 失败" % ifname)
        exit(1)

    settings = {
        "interface": ifname,
        "src_ip": local_ip,
        "local_mac": local_mac,
        "dst_ip": dst_ip,
        "dst_port": int(sys.argv[2]) if len(sys.argv) > 2 else 0,   # 指定 port 通常只对 TCP 有意义
        # "gateway_mac": "04:d4:c4:57:b2:70",     # 有线需要正确的网关 MAC
        "gateway_mac": "00:00:00:00:00:00",   # 无线 WIFI 可以填任意的网关 MAC
    }

    main(settings)
