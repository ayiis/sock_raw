# python


### 1. [basic-sinffer.py](https://github.com/ayiis/python/blob/master/basic-sniffer.py)

love it

![basic-sinffer](http://images2015.cnblogs.com/blog/392599/201604/392599-20160405174641984-1613090533.jpg)


### 2. [synflood.py](https://github.com/ayiis/python/blob/master/synflood.py)

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


### 3. [tcpevil.py](https://github.com/ayiis/python/blob/master/tcpevil.py)

Yes it is so evil to inject a tcp packet.

![tcpevil](https://raw.githubusercontent.com/ayiis/ayiis.github.io/master/img/tcpevil.png)
