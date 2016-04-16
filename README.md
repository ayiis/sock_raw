# python


### 1. basic-sinffer.py

love it

![basic-sinffer](http://images2015.cnblogs.com/blog/392599/201604/392599-20160405174641984-1613090533.jpg)


### 2. synflood.py

I cut a part of code to make it out of work, sorry about that.

But you know where to find it :P

Add to your iptables like follow
```bash
    iptables -A INPUT -p tcp -s 192.168.152.134 -j DROP
    iptables -A OUTPUT -p tcp -d 192.168.152.134 --tcp-flags RST RST -j DROP
```
Just to tell your kenel:
    Do not send RST packet to target.134 -- that is what SYN FLOOD is
    Drop every tcp packet from target.134 -- is it evil? yes
