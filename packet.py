__author__ = 'Home'
__email__ = 'ahatm0use@gmail.com'
import socket
import struct
import random
from optparse import OptionParser

ETH_P_IP = 0x0800

class layer():
    pass
def checksum(data):
    s=0
    n=len(data)%2
    for i in range(0,len(data)-n,2):
        s+=(data[i])+(data[i+1]<<8)
    if n:
        s+=(data[i+1])
    while (s>>16):
        s=(s&0xFFFF)+(s>>16)
    s=~s&0xFFFF
    return s
def eth_addr (a) :
    b = "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x" % (a[0] , a[1] , a[2], a[3], a[4], a[5])
    return b
class ETHER(object):
    def __init__(self):
        self.src=''
        self.dst=''
        self.type=ETH_P_IP
    #localhost mac-address and router mac-address
    #So important!! if you want to send a packet to Internet host(or not local Lan host),you must set the dst-mac correctly!
    #    send to the router,then let router forward the packet to another network(in the process,the dst-ip has not changed,but the mac-address changed)
    def pack(self,src_mac=b'\x9C\xB7\x0D\xE6\x3E\x7C',dst_mac=b'\xD4\xEE\x07\x0E\x47\x7E',type=ETH_P_IP):
        self.srcmac=src_mac
        self.dstmac=dst_mac
        self.type=type
        ethernet=struct.pack('!6s6sH',self.dstmac,self.srcmac,self.type)
        return ethernet
    def unpack(self,packet):
        _eth=layer()
        unpacked=struct.unpack("!6B6BH",packet)
        _eth.type=socket.ntohs(unpacked[12])
        _eth.src=eth_addr(unpacked[0:6])
        _eth.dst=eth_addr(unpacked[6:12])
        print('\n\n|+|----eth----')
        print('   Protocol: ',_eth.type)
        print('   Destination_MAC: ',_eth.dst)
        print('   Source_MAC: ',_eth.src)
        return _eth
class IP(object):
    def __init__(self):
        self.version=4
        self.ihl=5 #Internaet Header Length,(length of byte)
        self.tos=0 #Type of Service
        self.tl=44
        self.id=random.randint(0,65535)
        self.flags=0 #Don't fragment
        self.offset=0
        self.ttl=255
        self.checksum=0 # will be filled by kernel,but if you want to send a eth frame,you must count it by yourself
    def pack(self,source,destination,proto=socket.IPPROTO_TCP):
        self.source=socket.inet_aton(source)
        self.destination=socket.inet_aton(destination)
        self.protocal=proto
        ver_ihl=(self.version<<4)+self.ihl
        flags_offset=(self.flags<<13)+self.offset
        ip_header=struct.pack("!BBHHHBBH4s4s",
                              ver_ihl,
                              self.tos,
                              self.tl,
                              self.id,
                              flags_offset,
                              self.ttl,
                              self.protocal,
                              self.checksum,
                              self.source,
                              self.destination)
        #First pack to get the checksum
        self.checksum=checksum(ip_header)
        ip_header=struct.pack("!BBHHHBB",
                              ver_ihl,
                              self.tos,
                              self.tl,
                              self.id,
                              flags_offset,
                              self.ttl,
                              self.protocal)
        ip_header+=struct.pack('H',self.checksum)+struct.pack('!4s4s',self.source,self.destination)
        return ip_header
    def unpack(self,packet):
        _ip=layer()
        _ip.ihl=((packet[0])&0xF)*4
        iph=struct.unpack("!BBHHHBBH4s4s",packet[:_ip.ihl])
        _ip.ver=iph[0]>>4 #version
        _ip.tos=iph[1]
        _ip.tl=iph[2]
        _ip.ids=iph[3]
        _ip.flags=iph[4]>>13
        _ip.offset=iph[4]&0x1FFF
        _ip.ttl=iph[5]
        _ip.protocal=iph[6]
        _ip.checksum=hex(iph[7])
        _ip.src=socket.inet_ntoa(iph[8])
        _ip.dst=socket.inet_ntoa(iph[9])
        _ip.list=[
            _ip.ihl,
            _ip.ver,
            _ip.tos,
            _ip.tl,
            _ip.ids,
            _ip.flags,
            _ip.offset,
            _ip.ttl,
            _ip.protocal,
            _ip.src,
            _ip.dst
        ]
        print('|+|----IP----')
        print('   Version: ',_ip.ver)
        print('   Length: ',_ip.tl)
        print('   TTL: ',_ip.ttl)
        print('   Protocol: ',_ip.protocal)
        print('   Destination-IP: ',_ip.dst)
        print('   Source_IP',_ip.src)
        return _ip

class TCP(object):
    def __init__(self):
        self.seqn=10
        self.ackn=0
        self.offset=5 #Data offset 5*4=20 bytes
        self.reserved=0
        self.urg=0
        self.ack=0
        self.psh=0
        self.rst=0
        self.syn=1
        self.fin=0
        self.window=socket.htons(5840)
        self.checksum=0
        self.urgp=0
    def pack(self,srcp,dstp,source,destination,payload='TEST'):
        self.srcp=srcp
        self.dstp=dstp
        source_ip=socket.inet_aton(source)
        destination_ip=socket.inet_aton(destination)
        self.payload=payload.encode()
        data_offset=(self.offset<<4)+0
        flags=self.fin+(self.syn<<1)+(self.rst<<2)+(self.psh<<3)+(self.ack<<4)+(self.urg<<5)
        tcp_header=struct.pack("!HHLLBBHHH",
                               self.srcp,
                               self.dstp,
                               self.seqn,
                               self.ackn,
                               data_offset,
                               flags,
                               self.window,
                               self.checksum,
                               self.urgp)
        #pseudo header fields
        reserved =0
        protocal=socket.IPPROTO_TCP
        total_length=len(tcp_header)+len(self.payload)
        # Pseudo header
        psh=struct.pack("!4s4sBBH",
                        source_ip,
                        destination_ip,
                        reserved,
                        protocal,
                        total_length)
        psh=psh+tcp_header+self.payload
        tcp_checksum=checksum(psh)
        tcp_header=struct.pack("!HHLLBBH",
                        self.srcp,
                        self.dstp,
                        self.seqn,
                        self.ackn,
                        data_offset,
                        flags,
                        self.window)
        #这里计算校验和要注意字节序
        tcp_header+= struct.pack('H', tcp_checksum) + struct.pack('!H', self.urgp)+self.payload
        return tcp_header
    def unpack(self,packet):
        cflags={
            1:'F',
            0x2:'S',
            0x4:'R',
            0x8:'P',
            0x10:'A',
            0x20:'U'
        }
        _tcp=layer()
        _tcp.thl=(packet[12]>>4)*4 #4位首部长度，4位二进制最多表示15，15×4=60字节
        _tcp.options=packet[20:_tcp.thl]
        _tcp.payload=packet[_tcp.thl:]
        tcph=struct.unpack('!HHLLBBHHH',packet[:20])
        _tcp.srcp=tcph[0]
        _tcp.dstp=tcph[1]
        _tcp.seq=tcph[2]
        _tcp.ack=hex(tcph[3])
        _tcp.flags=''
        for t in cflags:
            if tcph[5] & t:
                _tcp.flags+=cflags[t]
        _tcp.window=tcph[6]
        _tcp.checksum=hex(tcph[7])
        _tcp.urg=tcph[8]
        _tcp.list=[
            _tcp.srcp,
            _tcp.dstp,
            _tcp.seq,
            _tcp.ack,
            _tcp.thl,
            _tcp.flags,
            _tcp.window,
            _tcp.checksum,
            _tcp.urg,
            _tcp.options,
            _tcp.payload
        ]
        print('|+|----TCP----')
        print('   Source_port: ',_tcp.srcp)
        print('   Destination_port: ',_tcp.dstp)
        print('   Sequence: ',_tcp.seq)
        print('   ACK: ',_tcp.ack)
        print('   Payload: ',_tcp.payload)
        return _tcp

class UDP(object):
    def __init__(self, src, dst, payload=''):
        self.src = src
        self.dst = dst
        self.payload = payload
        self.checksum = 0
        self.length = 8 # UDP Header length
    def pack(self, src, dst, proto=socket.IPPROTO_UDP):
        length = self.length + len(self.payload)
        pseudo_header = struct.pack('!4s4sBBH',
            socket.inet_aton(src), socket.inet_aton(dst), 0,
            proto, length)
        self.checksum = checksum(pseudo_header)
        packet = struct.pack('!HHHH',
            self.src, self.dst, length, 0)
        return packet

def Byte2Hex(str):
    return ''.join( ["%02X " % x for x in str] ).strip()

def SendEthPacket(src_host,dst_host,src_port=1234,dst_port=80):
    print("|+|Local Machine: %s"% (src_host))
    print("|+|Remote Machine: %s"% (dst_host))
    data='TEST'
    print("|+|Data to inject: %s"%(data))
    tcpobj=TCP()
    ipobj=IP()
    ethobj=ETHER()
    #IP packet
    packet=ethobj.pack()+ipobj.pack(src_host,dst_host)+tcpobj.pack(src_port,dst_port,src_host,dst_host)
    print(Byte2Hex(packet))
    #pay attention to the protocal
    rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.htons(0x0800))    
    rawSocket.bind(("wlan0",0))
    rawSocket.send(packet)
    response,address = rawSocket.recvfrom(2048)
    print(Byte2Hex(response))
    response=response[14:]
    print('|+|RESPONSE:')
    ip=ipobj.unpack(response)
    response=response[ip.ihl:]
    tcp=tcpobj.unpack(response)
def SendIPacket(src_host,dst_host,src_port=1234,dst_port=80):
    print("|+|Local Machine: %s"% (src_host))
    print("|+|Remote Machine: %s"% (dst_host))
    data='TEST'
    print("|+|Data to inject: %s"%(data))
    tcpobj=TCP()
    ipobj=IP()
    #IP packet
    packet=ipobj.pack(src_host,dst_host)+tcpobj.pack(src_port,dst_port,src_host,dst_host)
    print(Byte2Hex(packet))
    rawSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW,socket.IPPROTO_TCP)
    #rawSocket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    rawSocket.sendto(packet,(dst_host,0))
    rawSocket.settimeout(20)
    response,address = rawSocket.recvfrom(2048)
    print(Byte2Hex(response))
    print('|+|RESPONSE:')
    ip=ipobj.unpack(response)
    response=response[ip.ihl:]
    tcp=tcpobj.unpack(response)
    
def SniffPackets():
    #ETH_P_IP   0x0800  只接收发往本机mac的ip类型的数据帧
    #ETH_P_ARP  0x0806  只接受发往本机mac的arp类型的数据帧
    #ETH_P_RARP 0x8035  只接受发往本机mac的rarp类型的数据帧
    #ETH_P_ALL  0x0003  接收发往本机mac的所有类型ip arp rarp的数据帧, 接收从本机发出的所有类型的数据帧.(混杂模式打开的情况下,会接收到非发往本地mac的数据帧)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    while True:
        packet,address=s.recvfrom(65535)
        ethobj=ETHER()
        tcpobj=TCP()
        ipobj=IP()
        ethheader=ethobj.unpack(packet[:14])
        # the packet is IP
        if ethheader.type==8:
            packet=packet[14:]
            ipheader=ipobj.unpack(packet)
            # the packet is TCP
            if ipheader.protocal==6:
                packet=packet[ipheader.ihl:]
                tcpacket=tcpobj.unpack(packet)
def main():
    parser=OptionParser()
    parser.add_option('-s','--src',dest='src',type='string',help='Source IP Address',metavar='IP')
    parser.add_option('-d','--dst',dest='dst',type='string',help='Destination IP Address',metavar='IP')
    parser.add_option('-f','--sniff',action="store_true", default=False,dest='dowhat')
    parser.add_option('-e','--ether',action="store_true", default=False,dest='iseth') 
    options,args=parser.parse_args()
    if options.dowhat:
        SniffPackets()
    else:
        if options.dst==None:
            parser.print_help()
            exit(0)
        else:
            dst_host=socket.gethostbyname(options.dst)
            dst_host='192.168.199.1'
        if options.src==None:
            src_host=socket.gethostbyname(socket.gethostname())
            src_host='192.168.199.190'
        else:
            src_host=options.src
        if options.iseth:
            SendEthPacket(src_host, dst_host)
        else:
            SendIPacket(src_host,dst_host)

if __name__=="__main__":
    main()
