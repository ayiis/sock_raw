# -*- coding:utf-8 -*-
import time
import zlib
from socket import inet_aton, inet_ntoa
from pcap import pcap
"""

    * 对于 IP 协议，无法通过抓包知道哪些包是出去的，哪些包是进来的，必须指定 ip 或 mac 才能知道

        对于 TCP 协议，通过分析 TCP 的握手过程，判断 SYN 的发起者为 请求方

            - 利用 TCP Connection keep-alive 重复发起的请求，不在此判断范围（因为不需要重新握手）

                同时，对于这种情况，相当于中途开始抓包，因为前序的 TCP 包未知，导致不一定能完整捕获，因此直接忽略

    1. 抓包 TCP
    2. 将 TCP packet 组合，构成 HTTP 包

"""
"""
    常有的问题：

        TCP （通常是连续PSH的） packet 顺序不对，后发的 packet 先至 （ TCP Out-Of-Order: 网卡能自动处理）

            - 如何区别于 TCP Hijack

"""


class CONFIG:
    decode_gzip = True
    packet_expire_timeout = 120         # 一直没有发送完毕且没有更新的数据包，超时时间 (针对不活跃的连接，需要考虑 TCP keep-alive)
    skip_large_body = 1024 * 1024 * 2   # 忽略大于 2MB 的请求和返回


gzip_decode = lambda g: zlib.decompress(g, zlib.MAX_WBITS | 32)


"""
                TCPHandler <!--
"""


class TCPHandler(object):

    def __init__(self):
        self.conns = {
            # (src_addr, dst_addr): {}
        }
        self.expire_dict = {
            # (src_addr, dst_addr): ts in seconds,
        }
        self.expire_timeout_check_period = CONFIG.packet_expire_timeout / 10   # 多久检查一次
        self.expire_last_check_ts = time.time()
        self.default_read_status = {
            "i": 0,
            "progress": 0,
            "head_line": b"",
            "headers": {},
            "body": b"",

            "b_header": b"",
            "b_body": b"",
        }

    def reverse_conn_id(self, conn_id):
        return (conn_id[1], conn_id[0])

    def touch_conn_expire(self, conn_id):
        ts = time.time()
        self.expire_dict.update({
            conn_id: ts,
            self.reverse_conn_id(conn_id): ts,
        })

    def clear_conn(self, conn_id):

        if conn_id in self.expire_dict:
            del self.expire_dict[conn_id]
            del self.expire_dict[self.reverse_conn_id(conn_id)]

        if conn_id in self.conns:
            del self.conns[conn_id]
            del self.conns[self.reverse_conn_id(conn_id)]

    def finish_conn(self, conn_id):

        req_conn_id = self.reverse_conn_id(conn_id)

        self.conns[conn_id].update({
            "tcp_data_list": [],
            "seq_list": [],
        })
        self.conns[req_conn_id].update({
            "tcp_data_list": [],
            "seq_list": [],
        })
        self.conns[conn_id]["read_status"].update(self.default_read_status)
        self.conns[req_conn_id]["read_status"].update(self.default_read_status)
        self.touch_conn_expire(conn_id)

    def timmer(self):
        """
            利用嗅探到的数据包来触发定时任务，理论上只要网卡不故障，触发会非常频繁，需要适当降低检查频率
        """
        if time.time() - self.expire_last_check_ts < self.expire_timeout_check_period:
            return None
        else:
            self.expire_last_check_ts = time.time()
            remove_keys = set()
            for conn_id in self.expire_dict:
                if self.expire_last_check_ts - self.expire_dict[conn_id] < CONFIG.packet_expire_timeout:
                    continue
                else:
                    remove_keys.add(conn_id)

            # print("** timmer: %s keys in expire_dict **" % (len(self.expire_dict)))

            for conn_id in remove_keys:
                # 直接删除不活跃的连接
                # print("remove conns:", conn_id)
                self.clear_conn(conn_id)

    def http_iter(self, conn_id):
        conn_data = self.conns[conn_id]

        conn_data["read_status"] = read_status = {
            "i_next_seq": conn_data["next_seq"],     # 下一个处理的 seq
        }
        read_status.update(self.default_read_status)

        def do():

            while read_status["i"] < len(conn_data["tcp_data_list"]):
                """
                    读取 请求头部
                        请求方法 请求路径 HTTP版本\r\n
                        请求头\r\n\r\n
                """

                if read_status["i"] < len(conn_data["tcp_data_list"]):
                    if read_status["i_next_seq"] == conn_data["seq_list"][read_status["i"]]:
                        read_status["i_next_seq"] += len(conn_data["tcp_data_list"][read_status["i"]])
                        b_next = conn_data["tcp_data_list"][read_status["i"]]
                        read_status["i"] += 1
                    else:
                        print("WARNING, maybe TCP Hijack:", conn_id, conn_data["seq"], conn_data["next_seq"])
                        read_status["i"] += 1
                        continue
                else:
                    break

                if read_status["progress"] == 0:
                    read_status["b_header"] += b_next
                    b_next = b""

                    hlen = read_status["b_header"].find(b"\r\n\r\n")
                    # 找到了请求头的结束标志
                    if hlen != -1:
                        read_status["b_body"] = read_status["b_header"][hlen + 4:]
                        read_status["b_header"] = read_status["b_header"][:hlen]
                        read_status["head_line"], *headers = read_status["b_header"].split(b"\r\n")

                        read_status["headers"] = dict([(lambda h: (h[0].lower().strip(), h[1].strip()))(line.split(b":")) for line in headers])
                        read_status["progress"] = 1

                if read_status["progress"] == 1:

                    read_status["b_body"] += b_next
                    b_next = b""

                    if b"transfer-encoding" in read_status["headers"]:
                        if read_status["headers"][b"transfer-encoding"].lower() == b"chunked":

                            while True:
                                clen = read_status["b_body"].find(b"\r\n")
                                if clen == -1:
                                    break

                                chunk_data_len = int(read_status["b_body"][:clen], 16)
                                if chunk_data_len == 0:

                                    # RFC2616: 0\r\n\r\n to end the http packet
                                    if read_status["b_body"] == b"0\r\n\r\n":
                                        yield read_status
                                    else:
                                        print("invalid ending:", conn_id)
                                        yield {}

                                # 本次 TCP 数据包未达到一个完整的 chunk
                                if len(read_status["b_body"]) < clen + 2 + chunk_data_len:
                                    break

                                read_status["body"] += read_status["b_body"][clen + 2: clen + 2 + chunk_data_len]
                                read_status["b_body"] = read_status["b_body"][clen + 2 + chunk_data_len + 2:]

                        else:
                            print("unknow transfer-encoding:", conn_id, read_status["headers"][b"transfer-encoding"])
                            yield {}

                    elif b"content-length" in read_status["headers"]:
                        if len(read_status["b_body"]) < int(read_status["headers"][b"content-length"]):
                            pass
                        else:
                            if len(read_status["b_body"]) == int(read_status["headers"][b"content-length"]):
                                read_status["body"] = read_status["b_body"]
                                read_status["progress"] = 2
                                yield read_status
                            else:
                                print("WARNING: b_body length exceed:", conn_id)
                                yield {}

                    else:
                        read_status["progress"] = 2
                        if read_status["b_body"] == b"":
                            yield read_status
                        else:
                            print("WARNING: b_body without content-length:", conn_id)
                            yield {}

        return do

    def http_req_analyzer(self, conn_id):
        """
            分析一个 HTTP 的 请求 是否已经发送完毕
        """
        http_req_iter_for_conn = self.conns[conn_id]["iter"]

        conn_done_req = next(http_req_iter_for_conn(), None)
        if conn_done_req is not None:
            if not conn_done_req:
                pass
            else:
                conn_done_req["method"], conn_done_req["path"], conn_done_req["version"] = conn_done_req["head_line"].split(b" ")

    def http_res_analyzer(self, conn_id):
        """
            分析一个 HTTP 的 返回 是否已经发送完毕
        """
        http_res_iter_for_conn = self.conns[conn_id]["iter"]

        conn_done_res = next(http_res_iter_for_conn(), None)
        if conn_done_res is not None:
            if not conn_done_res:
                pass
            else:
                # status_text -> "HTTP/1.1 301 Moved Permanently"
                conn_done_res["version"], conn_done_res["status"], *conn_done_res["status_text"] = conn_done_res["head_line"].split(b" ")
                conn_done_res["status_text"] = b" ".join(conn_done_res["status_text"])
                if CONFIG.decode_gzip:
                    if conn_done_res["headers"].get(b"content-encoding", "").lower() == b"gzip":
                        conn_done_res["body"] = gzip_decode(conn_done_res["body"])

                """
                    此处完成捕获请求和返回，自由处理
                """
                print("======" * 12, "%s:%s -> %s:%s" % (*conn_id[1], *conn_id[0]))

                conn_done_req = self.conns[self.reverse_conn_id(conn_id)]["read_status"]
                print(conn_done_req["b_header"].decode("utf8"))
                print()
                print(conn_done_req["body"][:1024])
                print()

                conn_done_res["body"] = conn_done_res["body"][:1024]
                print(conn_done_res["b_header"].decode("utf8"))
                print()
                print(conn_done_res["body"][:1024])
                print()

                # 重置 conn_id
                # 需要考虑 TCP keep-alive 重复利用当前 TCP 连接再次发送请求的情况
                self.finish_conn(conn_id)

    def insert_packet_by_seq(self, conn_data, seq, tcp_data):

        for i in range(len(conn_data["seq_list"]) - 1, -1, -1):
            if conn_data["seq_list"][i] < seq:
                conn_data["tcp_data_list"].insert(i + 1, tcp_data)
                conn_data["seq_list"].insert(i + 1, seq)
                break
        else:
            conn_data["tcp_data_list"].insert(0, tcp_data)
            conn_data["seq_list"].insert(0, seq)

    def skip_packet(self, conn_data, tcp_data, tcp_dlen, conn_id, seq, ack):

        if conn_data["seq"] == seq:
            # print("TCP Retransmission:", conn_id, conn_data["seq"], conn_data["next_seq"], seq)
            pass

        elif conn_data["next_seq"] - 1 == seq and tcp_data == b"\x00":
            # https://tools.ietf.org/html/rfc1122#page-101
            # 4.2.3.6  TCP Keep-Alives
            # 争议内容：一种迂回但相对稳健的 TCP Keep-Alives 实现方法
            """
                An implementation SHOULD send a keep-alive segment with no
                data; however, it MAY be configurable to send a keep-alive
                segment containing one garbage octet, for compatibility with
                erroneous TCP implementations.

                ...

                Unfortunately, some misbehaved TCP implementations fail
                to respond to a segment with SEG.SEQ = SND.NXT-1 unless
                the segment contains data.  Alternatively, an
                implementation could determine whether a peer responded
                correctly to keep-alive packets with no garbage data
                octet.
            """
            # print("TCP keep-alive:", conn_id, conn_data["seq"], conn_data["next_seq"], seq)
            pass

        elif conn_data["next_seq"] < seq:
            # TCP Out-Of-Order
            # print("TCP Out-Of-Order 1:", conn_id, conn_data["seq"], conn_data["next_seq"], seq)
            self.insert_packet_by_seq(conn_data, seq, tcp_data)

        elif conn_data["seq"] < seq:
            # Previous segment(s) not captured (common at capture start)
            # However, this script capture SYN/ACK from tcp connection start, thus it only happens in a TCP Out-Of-Order
            if seq in conn_data["seq_list"]:
                # print("TCP Retransmission:", conn_id, conn_data["seq"], conn_data["next_seq"], seq)
                pass
            else:
                # print("TCP Out-Of-Order 2:", conn_id, conn_data["seq"], conn_data["next_seq"], seq)
                self.insert_packet_by_seq(conn_data, seq, tcp_data)

        elif seq < conn_data["seq"]:
            if seq in conn_data["seq_list"]:
                # print("TCP Retransmission:", conn_id, conn_data["seq"], conn_data["next_seq"], seq)
                pass
            else:
                print("WARNING, maybe TCP Hijack:", conn_id, conn_data["seq"], conn_data["next_seq"], seq)

        else:
            print("Not gona happened:", conn_id, conn_data["seq"], conn_data["next_seq"], seq)
            pass

    def handshake(self, src_addr, dst_addr, seq, ack, tcp_flags):

        conn_id = (src_addr, dst_addr)

        if tcp_flags == 0b10000:    # ACK, ignore all
            pass

        elif tcp_flags == 0b10 or tcp_flags == 0b10010:   # SYN / ACK+SYN
            self.conns[conn_id] = {
                "is_req": tcp_flags == 0b10,
                "seq": seq,
                "next_seq": seq + 1,
                "ack": ack,
                "ts": time.time(),
                "tcp_data_list": [],
                "seq_list": [],
            }
            self.conns[conn_id]["iter"] = self.http_iter(conn_id)
            self.touch_conn_expire(conn_id)

        elif tcp_flags & 0b101:     # FIN / RST
            self.close_tcp(conn_id)

        else:
            pass

    def close_tcp(self, conn_id):
        """
            触发了 Fin 或者 RST
            *不做任何处理，以简单方式避免被 TCP 劫持影响
        """
        # self.clear_conn(conn_id)
        pass

    def check_seq_list(self, conn_data):

        if conn_data["seq"] != conn_data["seq_list"][-1]:
            return False

        for i in range(1, len(conn_data["seq_list"])):
            prev = i - 1
            seq = conn_data["seq_list"][i]
            if seq != conn_data["seq_list"][prev] + len(conn_data["tcp_data_list"][prev]):
                return False

        return True

    def handle_packet(self, tcp_data, tcp_dlen, src_addr, dst_addr, seq, ack):
        conn_id = (src_addr, dst_addr)
        if conn_id not in self.conns:
            # print("Warning: no conn_id in self.conns:", conn_id, tcp_dlen)
            return None

        conn_data = self.conns[conn_id]

        if conn_data["next_seq"] == seq:
            next_seq = conn_data["next_seq"] + tcp_dlen
            conn_data["seq"] = seq
            conn_data["next_seq"] = next_seq

            while conn_data["next_seq"] in conn_data["seq_list"]:
                conn_data["seq"] = conn_data["next_seq"]
                conn_data["next_seq"] += len(conn_data["tcp_data_list"][conn_data["seq_list"].index(conn_data["next_seq"])])

            self.insert_packet_by_seq(conn_data, seq, tcp_data)
            self.touch_conn_expire(conn_id)
        else:
            self.skip_packet(conn_data, tcp_data, tcp_dlen, conn_id, seq, ack)

        # 数据包不完整
        if not self.check_seq_list(conn_data):
            return None

        if self.conns[conn_id]["is_req"]:
            self.http_req_analyzer(conn_id)
        else:
            self.http_res_analyzer(conn_id)


"""
                --> TCPHandler
"""

TCPHandler = TCPHandler()


def http_filter_wrap(settings):

    connvert_2_bytes = lambda pair: [(inet_aton(ip), (port).to_bytes(2, byteorder="big")) for ip, port in pair] if pair else None
    address_pairs = connvert_2_bytes(settings["address_pair"])

    # drop_port = lambda ports, pair: next((True for port in ports if (port).to_bytes(2, byteorder="big") in pair), False)

    address_pairs = set(address_pairs) if address_pairs else None

    ether_len = 14 if settings["ether"] else 4

    def do(raw_packet):

        ihl = raw_packet[ether_len] << 2 & 0b111100
        src_ip = raw_packet[ether_len + 12: ether_len + 16]
        dst_ip = raw_packet[ether_len + 16: ether_len + 20]

        src_port = raw_packet[ether_len + ihl: ether_len + ihl + 2]
        dst_port = raw_packet[ether_len + ihl + 2: ether_len + ihl + 4]

        # if drop_port([80, 443, 50000], (src_port, dst_port)):
        #     return None

        # DEBUG
        # print("%s:%s --> %s:%s" % (src_ip, src_port, dst_ip, dst_port))

        # # 匹配到接收数据的地址 -> 请求
        # if (dst_ip, dst_port) in address_pairs:
        #     packet_type = 0

        # # 匹配到发送数据的地址 -> 返回
        # elif (src_ip, src_port) in address_pairs:
        #     packet_type = 1

        # else:
        #     return None

        if address_pairs and not set([(src_ip, src_port), (dst_ip, dst_port)]) & address_pairs:
            return None

        """
            此处可以不做任何处理，直接使用原始的 bytes，节约计算资源
        """
        src_ip = inet_ntoa(src_ip)
        src_port = int.from_bytes(src_port, "big")
        dst_ip = inet_ntoa(dst_ip)
        dst_port = int.from_bytes(dst_port, "big")

        ip_dlen = raw_packet[ether_len + 2] << 8 | raw_packet[ether_len + 3]
        tcp_hl = raw_packet[ether_len + ihl + 12] >> 4 << 2
        tcp_dlen = ip_dlen - ihl - tcp_hl

        seq = int.from_bytes(raw_packet[ether_len + ihl + 4:ether_len + ihl + 8], "big")
        ack = int.from_bytes(raw_packet[ether_len + ihl + 8:ether_len + ihl + 12], "big")

        # 没有 TCP 数据，忽略
        if tcp_dlen == 0:
            tcp_flags = raw_packet[ether_len + ihl + 13]
            TCPHandler.handshake((src_ip, src_port), (dst_ip, dst_port), seq, ack, tcp_flags)
        else:
            tcp_data = raw_packet[ether_len + ihl + tcp_hl: ether_len + ip_dlen]
            TCPHandler.handle_packet(tcp_data, tcp_dlen, (src_ip, src_port), (dst_ip, dst_port), seq, ack)

    return do


def main(http_filter, settings):

    sniffer = pcap(name=settings["interface"], promisc=True, immediate=True, timeout_ms=50)

    if settings["ether"]:
        while True:
            _, packet = next(sniffer, (None, None))
            if packet[12] == 8 and packet[13] == 0 and packet[23] == 6:    # IP & TCP
                http_filter(packet)

            TCPHandler.timmer()
    else:
        while True:
            _, packet = next(sniffer, (None, None))
            if packet[0] == 2 and packet[13] == 6:    # IP & TCP
                http_filter(packet)

            TCPHandler.timmer()


#                           #
#            TEST           #
#                           #
#        Python 3.7         #
#        MacOS              #

if __name__ == "__main__":

    if True:

        settings = {
            "interface": None,      # 自动获取
            "ether": True,          # 完整 ether
            "address_pair": None,   # 匹配所有地址
        }

    elif True:

        settings = {
            "interface": "en0",     # wifi 或 有线
            "ether": True,
            "address_pair": [("149.129.120.100", 80), ],      # 只匹配目标IP和端口，支持多个，不过滤则设置为 None
        }

    else:
        """
            https://stackoverflow.com/questions/39327734/capturing-packets-on-loopback
            Error on lo0 -> Device doesn't provide Ethernet headers
                local: lo0
                wifi: en0
        """
        settings = {
            "interface": "lo0",     # 本地回环
            "ether": False,         # MacOS 下，默认无 ether 的长度是 4
            # "address_pair": None,
            "address_pair": [("127.0.0.1", 60002), ],      # 只匹配目标IP和端口，支持多个，不过滤则设置为 None
        }

    http_filter = http_filter_wrap(settings)
    main(http_filter, settings)
