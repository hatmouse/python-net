__author__ = 'Home'
import socket
import struct

HOST=socket.gethostbyname(socket.gethostname())
s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
s.bind((HOST,0))

#receive all packages
s.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)
class ip():
    def __init__(self,header):
        self.header=header
    def extract(self):
        unpacked=struct.unpack("!BBHHHBBH4s4s",self.header)
        ver=unpacked[0]>>4
        length=(unpacked[0]&0xF)*4
        ttl=unpacked[5]
        self.protocol=unpacked[6]
        source_addr=socket.inet_ntoa(unpacked[8])
        dest_addr=socket.inet_ntoa(unpacked[9])
        print('----IP----')
        print('Version: ',ver)
        print('Length: ',length)
        print('TTL: ',ttl)
        print('Protocol: ',self.protocol)
        print('S_Addr: ',source_addr)
        print('D_Addr',dest_addr)
class tcp():
    def __init__(self,header):
        self.header=header
    def extract(self):
        unpacked=struct.unpack('!HHLLBBHHH',self.header)
        source_port=unpacked[0]
        dest_port=unpacked[1]
        sequence=unpacked[2]
        ack=unpacked[3]
        length=unpacked[4]>>4
        print('----TCP----')
        print('Source_port: ',source_port)
        print('Dest_port: ',dest_port)
        print('Sequence: ',sequence)
        print('ACK: ',ack)
        print('Length: ',length)
while True:
    packet,address=s.recvfrom(65535)
    ipheader=ip(packet[:20])
    ipheader.extract()
    if ipheader.protocol==6:
        tcpheader=tcp(packet[20:40])
        tcpheader.extract()
        # data
        data=packet[40:]
        print('Data:',data)
    data=packet[20:]
    print('Data:',data)

s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
