import platform
import os, re

socks = None

def get_gateway_addr(ifname):
    """
        依赖 route 和 netstat 命令
    """
    gateway_mac = '00:00:00:00:00:00'
    gateway_ip = '0.0.0.0'

    os_name = platform.system()
    if os_name == 'Darwin':
        route_ip_res_text = os.popen("""route -n get default""").read()
        gateway_ip = next((x for x in route_ip_res_text.splitlines() if "gateway: " in x), "").split("gateway: ")[1]

        route_mac_res_text = os.popen("""netstat -nr -f inet""").read()
        for line in route_mac_res_text.splitlines():
            items = [x for x in line.split(" ") if x]
            if len(items) > 3 and items[0] == gateway_ip and items[3] == ifname:
                gateway_mac = items[1]
                break
        else:
            raise Exception("获取网关MAC、IP失败")

    elif os_name == 'Linux':
        pass

    return gateway_mac, gateway_ip


def get_default_ifconf():
    """
        通过第三方的包获取 本地机器和网关的信息
    """
    import netifaces
    gws = netifaces.gateways()
    local_gateway = gws['default'][netifaces.AF_INET][1]
    local_mac = netifaces.ifaddresses(local_gateway)[netifaces.AF_LINK][0]['addr']
    local_ip = netifaces.ifaddresses(local_gateway)[netifaces.AF_INET][0]['addr']
    gateway_mac, gateway_ip = get_gateway_addr(local_gateway)

    return local_gateway, local_mac, local_ip, gateway_mac, gateway_ip

def get_gateway_conf():
    pass


local_gateway, local_mac, local_ip, gateway_mac, gateway_ip = get_default_ifconf()


class SockRaw(object):

    sock_type = "RAW"

    def __init__(self):
        pass

    def build_sock(self):
        return socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    def build_raw_sock(self):
        return socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    def raw_send_packet(self, sock, packet):
        sock.sendto(packet, (local_gateway, 0))

    def sniff_next(self, sniffer):
        packet = sniffer.recvfrom(65565)
        return packet[0]


class SockRawPcap(SockRaw):

    sock_type = "PCAP"

    def __init__(self):
        pass

    def build_sock(self):
        return pcap.pcap(name=local_gateway, promisc=False)

    def build_raw_sock(self):
        return pcap.pcap(name=None, promisc=True, immediate=True, timeout_ms=50)

    def raw_send_packet(self, sock, packet):
        pcap.pcap.sendpacket(sock, packet)

    def sniff_next(self, sniffer):
        _, packet = next(sniffer, (None, None))
        return packet


try:
    # 适用于 OSX
    import pcap
    socks = SockRawPcap()
except:
    # 适用于 Linux
    import socket
    socks = SockRaw()
