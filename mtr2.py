import pcap
import time
import datetime
import os
import q


# packet = b"\x58\xc7\xac\xc2\x2e\x01\x18\x65\x90\xcc\x45\xb9\x08\x00\x45\x00\x00\x34\x9f\x5b\x00\x00\x01\x11\x5d\x53\x0a\xc0\xa4\x65\x95\x81\x78\x64\x9f\x5a\x82\x9b\x00\x20\x20\xad\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

# settings = {'interface': 'en0', 'src_ip': '10.192.164.101', 'local_mac': '18:65:90:cc:45:b9', 'dst_ip': '149.129.120.100', 'dst_port': 0, 'gateway_mac': '18:65:90:cc:45:b9'}

# pp_socket = pcap.pcap(name=settings["interface"], promisc=False)

# time.sleep(1)

# for i in range(3):
#     pcap.pcap.sendpacket(pp_socket, packet)

# print("done")


def main():

    sniffer = pcap.pcap(name="en0", promisc=False, immediate=True, timeout_ms=50)

    last_tt = ""
    last_ts = 0
    while True:

        _, packet = next(sniffer)

        if packet is None:
            print(".")

        now_ts = datetime.datetime.now()

        tt = now_ts.strftime("%H:%M:%S.%f")[:11] + "0"
        if last_tt != tt:
            if last_ts:
                print(tt, round(now_ts.timestamp() - last_ts.timestamp(), 2))
            last_ts = now_ts


if __name__ == "__main__":
    main()
