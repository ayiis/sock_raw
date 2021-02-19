# python


### [basic-sniffer.py](https://github.com/ayiis/python/blob/master/basic-sniffer.py)

Use this to capture a TCP packet!

![basic-sniffer](https://raw.githubusercontent.com/ayiis/ayiis.github.io/master/img/basic-sniffer.png)


### [better_tcp_sniffer.py](https://github.com/ayiis/python/blob/master/better_tcp_sniffer.py)

this table is construct like the definition size of packet, without extra infomation, for senior.

```code
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
```

![better_tcp_sniffer](https://raw.githubusercontent.com/ayiis/ayiis.github.io/master/img/better_tcp_sniffer.jpg)


### [pcap_usage.py](https://github.com/ayiis/python/blob/master/pcap_usage.py)

use pcap to send a raw socket packet. It's a very low level usage that only for senior.

you should DROP all `RST` signal between the connection and handle it yourself.


### [synflood.py](https://github.com/ayiis/python/blob/master/synflood.py)

I cut a part of code to make it out of work, sorry about that.

But you know where to find it :P

Add to your iptables like follow

```bash
    iptables -A INPUT -p tcp -s 192.168.152.134 -j DROP
    iptables -A OUTPUT -p tcp -d 192.168.152.134 --tcp-flags RST RST -j DROP
```

Just to tell your kenel:

```bash
    Do not send RST packet to target.134 -- that is what SYN FLOOD is
    Drop every tcp packet from target.134 -- is it evil? yes
```


### [tcpevil.py](https://github.com/ayiis/python/blob/master/tcpevil.py)

Yes it is so evil to inject a tcp packet.

![tcpevil](https://raw.githubusercontent.com/ayiis/ayiis.github.io/master/img/tcpevil.png)


### [http_sniffer.py](https://github.com/ayiis/python/blob/master/http_sniffer.py)

Here's a good sniffer for HTTP request and response! You got to love it!

![http_sniffer](https://raw.githubusercontent.com/ayiis/ayiis.github.io/master/img/http_sniffer.jpg)


### NOTE

    SOCK_RAW for MacOS: Check `https://github.com/pynetwork/pypcap` to get the `libpcap`
    MacOS's ping: https://opensource.apple.com/source/network_cmds/network_cmds-433/ping.tproj/ping.c.auto.html

