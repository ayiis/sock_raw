# -*- coding:utf-8 -*-
import socket
import struct
import pcap
import traceback
from aytool.common.print_table import PrettyTable
"""
             ┌──────────────────────────────────┬──────────────────────────────────┬──────────┐
             │                  Destination Mac │                       Source Mac │Ether type│
             └──────────────────────────────────┴──────────────────────────────────┴──────────┘
┌──────┬──────┬──────────┬─────────────────────┐  ┌────────────────────────┬──────────────────┐
│  Ver │   HL │      TOS │        Total length │  │            Source Port │ Destination Port │
├──────┴──────┴──────────┼──────┬──────────────┤  ├────────────────────────┴──────────────────┤
│         Identification │ Flags│FragmentOffset│  │                           Sequence Number │
├─────────────┬──────────┼──────┴──────────────┤  ├───────────────────────────────────────────┤
│         TTL │ Protocol │     Header Checksum │  │                    Acknowledgement Number │
├─────────────┴──────────┴─────────────────────┤  ├──────┬────────┬────────┬──────────────────┤
│                                    Source IP │  │   HL │Reserved│ UAPRSF │      Window Size │
├──────────────────────────────────────────────┤  ├──────┴────────┴────────┼──────────────────┤
│                               Destination IP │  │               Checksum │   Urgent Pointer │
├──────────────────────────────────────────────┤  ├────────────────────────┴──────────────────┤
│                                      Options │  │                                   Options │
└──────────────────────────────────────────────┘  └───────────────────────────────────────────┘
┌─────────┬───────────────────────────────────────────────────────────────────────────────────┐
│ Data Len│                                                                           TCP Data│
└─────────┴───────────────────────────────────────────────────────────────────────────────────┘
"""

_eth_addr = lambda a: "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % ((a[0]), (a[1]), (a[2]), (a[3]), (a[4]), (a[5]))


def better_print(packet):
    eth_hlen = 14

    # IP 头部长度通常是 20 + 可选项
    ip_hlen = packet[eth_hlen] << 2 & 0b111100

    ip_hdata_raw = packet[eth_hlen: ip_hlen + eth_hlen]
    ip_hdata = struct.unpack("!BBHHHBBH4s4s", ip_hdata_raw[:20])

    ip_ver = ip_hdata[0] >> 4           # ??
    ip_hlen = ip_hdata[0] << 2 & 0b111100
    ip_dlen = ip_hdata[2]

    # TCP 头部长度通常是 20 + 可选项
    tcp_hlen = packet[eth_hlen + ip_hlen + 2 + 2 + 4 + 4] >> 4 << 2

    tcp_hdata_raw = packet[eth_hlen + ip_hlen: eth_hlen + ip_hlen + tcp_hlen]
    tcp_hdata = struct.unpack("!HHLLBBHHH", tcp_hdata_raw[:20])

    tcp_dlen = ip_dlen - ip_hlen - tcp_hlen
    tcp_data = packet[eth_hlen + ip_hlen + tcp_hlen: eth_hlen + ip_dlen]

    # ETH
    pt = PrettyTable()
    pt.add_line((32, 32, 8), [_eth_addr(packet[6:12]), _eth_addr(packet[0:6]), "0x" + packet[12:14].hex()])

    # if not(tcp_hdata[0] == 10002 or tcp_hdata[1] == 10002):
    #     return None

    # 右对齐输出
    print("\n".join(["%s%s" % (x, y) for x, y in zip(["             "] * 3, pt.get_table())]))

    # IP
    pt1 = PrettyTable()
    pt1.add_line((4, 4, 8, 16), [ip_ver, ip_hlen, packet[15:16].hex(), ip_dlen])
    pt1.add_line((16, 4, 12), ["0x" + packet[18:20].hex(), format(packet[20] >> 5, "03b"), (packet[20] & 0b0001111) << 4 + packet[21]])
    pt1.add_line((8, 8, 16), [ip_hdata[5], ip_hdata[6], hex(ip_hdata[7])])
    pt1.add_line((32, ), [socket.inet_ntoa(ip_hdata[8])])
    pt1.add_line((32, ), [socket.inet_ntoa(ip_hdata[9])])
    pt1.add_line((32, ), [("0x" + ip_hdata_raw[20:].hex()) if ip_hlen > 20 else ""])

    # TCP
    pt2 = PrettyTable()
    pt2.add_line((16, 16), [tcp_hdata[0], tcp_hdata[1]])
    pt2.add_line((32, ), [tcp_hdata[2]])
    pt2.add_line((32, ), [tcp_hdata[3]])
    pt2.add_line((4, 6, 6, 16), [tcp_hlen, format(tcp_hdata_raw[2 + 2 + 4 + 4] & 0b1111, "04b") + format(tcp_hdata_raw[2 + 2 + 4 + 4 + 1], "08b")[:2], format(tcp_hdata_raw[2 + 2 + 4 + 4 + 1], "08b")[2:], tcp_hdata[6]])
    pt2.add_line((16, 16), [hex(tcp_hdata[7]), tcp_hdata[8]])
    pt2.add_line((32, ), [("0x" + tcp_hdata_raw[20:].hex()) if tcp_hlen > 20 else ""])

    # 并列输出
    print("\n".join(["%s  %s" % (x, y) for x, y in zip(pt1.get_table(), pt2.get_table())]))

    # DATA
    pt3 = PrettyTable()
    pt3.add_line((7, 81), [tcp_dlen, tcp_data if tcp_dlen > 0 else ""])
    pt3.print_table()


def main():

    sniffer = pcap.pcap(name=None, promisc=True, immediate=True, timeout_ms=50)

    while True:
        try:
            ts, packet = next(sniffer, (None, None))
            if packet[12:14] == b"\x08\x00" and packet[23:24] == b"\x06":    # IP & TCP
                better_print(packet)

        except Exception:
            print(traceback.format_exc())


#                           #
#            TEST           #
#                           #
#        Python 3.7         #
#        Mac                #

if __name__ == "__main__":
    main()
