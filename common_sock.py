# encoding:utf8
import socket, sys
from struct import *

# checksum functions needed for calculation checksum
def checksum(msg):
    if len(msg) % 2 == 1:
        msg += '\0'
    s = 0
    for i in range(0, len(msg), 2):
        w = (ord(msg[i]) << 8) + ord(msg[i+1])
        s = s + w
    s = (s >> 16) + (s & 0xffff)
    return (~s & 0xffff)


def getSockObj(obj):
    sockObj = {}

    sockObj['source_ip'] = obj.get('source_ip') or '127.0.0.1'
    sockObj['dest_ip'] = obj.get('dest_ip') or '127.0.0.1'

    sockObj['source_port'] = int(obj.get('source_port') ) or 11111
    sockObj['dest_port'] = int(obj.get('dest_port') ) or 22222

    sockObj['seq'] = int(obj.get('seq') ) or 0
    sockObj['ack'] = int(obj.get('ack') ) or 0

    #tcp flags
    sockObj['f_fin'] = int(bool(obj.get('f_fin') ) )
    sockObj['f_syn'] = int(bool(obj.get('f_syn') ) )
    sockObj['f_rst'] = int(bool(obj.get('f_rst') ) )
    sockObj['f_psh'] = int(bool(obj.get('f_psh') ) )
    sockObj['f_ack'] = int(bool(obj.get('f_ack') ) )
    sockObj['f_urg'] = int(bool(obj.get('f_urg') ) )

    sockObj['id'] = obj.get('id') or 0

    return sockObj


def sendRawSock(sockString, dest_ip, dest_port):
    #create a raw socket
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except socket.error , msg:
        print 'Socket could not be created. sendRawTCP(): Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        return False

    # s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.sendto(sockString, (dest_ip , dest_port ))


def sendRawTCP(tcpString, dest_ip, dest_port):
    #create a raw socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error , msg:
        print 'Socket could not be created. sendRawTCP(): Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        return False

    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.sendto(tcpString, (dest_ip , dest_port ))


def sendSockRaw(sockObj, tcp_data = ''):
    #create a raw socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error , msg:
        print 'Socket could not be created. sendSockRaw: Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        return False

    # tell kernel not to put in headers, since we are providing it
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # now start constructing the packet
    packet = ''

    print sockObj

    source_ip = sockObj['source_ip']
    dest_ip = sockObj['dest_ip']

    # ip header fields
    ihl = 5
    version = 4
    tos = 0
    tot_len = 20 + 20   # python seems to correctly fill the total length, dont know how ??
    id = sockObj['id']  #Id of this packet
    frag_off = 0x4000
    ttl = 64
    protocol = socket.IPPROTO_TCP
    check = 10  # python seems to correctly fill the checksum
    saddr = socket.inet_aton ( source_ip )  #Spoof the source ip address if you want to
    daddr = socket.inet_aton ( dest_ip )

    ihl_version = (version << 4) + ihl

    # the ! in the pack format string means network order
    ip_header = pack('!BBHHHBBH4s4s' , ihl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)

    # tcp header fields
    source_port = sockObj['source_port']   # source port
    dest_port = sockObj['dest_port']   # destination port
    seq = sockObj['seq']
    ack = sockObj['ack']
    doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
    #tcp flags
    f_fin = sockObj['f_fin']
    f_syn = sockObj['f_syn']
    f_rst = sockObj['f_rst']
    f_psh = sockObj['f_psh']
    f_ack = sockObj['f_ack']
    f_urg = sockObj['f_urg']
    window = 124 #socket.htons (115)    #   maximum allowed window size
    check = 0
    urg_ptr = 0

    offset_res = (doff << 4) + 0
    tcp_flags = f_fin + (f_syn << 1) + (f_rst << 2) + (f_psh <<3) + (f_ack << 4) + (f_urg << 5)

    # the ! in the pack format string means network order
    tcp_header = pack('!HHLLBBHHH' , source_port, dest_port, seq, ack, offset_res, tcp_flags,  window, check, urg_ptr)

    # pseudo header fields
    source_address = socket.inet_aton( source_ip )
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(tcp_data)

    psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);

    psh = psh + tcp_header + tcp_data

    tcp_checksum = checksum(psh)

    # make the tcp header again and fill the correct checksum
    tcp_header = pack('!HHLLBBHHH' , source_port, dest_port, seq, ack, offset_res, tcp_flags, window, tcp_checksum , urg_ptr)

    # final full packet - syn packets dont have any data
    packet = ip_header + tcp_header + tcp_data

    #Send the packet finally - the port specified has no effect
    s.sendto(packet, (dest_ip , dest_port ))    # put this in a loop if you want to flood the target


def reverseSock(recvObj):
    sendObj = {
        'source_ip': recvObj['dest_ip'],
        'dest_ip': recvObj['source_ip'],
        'source_port': recvObj['dest_port'],
        'dest_port': recvObj['source_port'],
        'seq': recvObj['ack'],
        'ack': recvObj['seq'],
    }
    return sendObj


def rstTCP(recvObj, rstType = 0):
    '''
        ack = seq+1 ==> Reject
        ack = seq ==> Disconnect
        [rstType] seems to be nothing to do here
    '''
    sendObj = reverseSock(recvObj)
    sendObj['ack'] += rstType

    sendObj['f_ack'] = 1
    sendObj['f_rst'] = 1

    sendObj = getSockObj(sendObj)
    return sendSockRaw(sendObj)
