__author__ = 'Home'
import socket
import struct

HOST=socket.gethostbyname(socket.gethostname())
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

def eth_addr (a) :
    b = "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x" % (a[0] , a[1] , a[2], a[3], a[4], a[5])
    return b
class eth():
    def __init__(self,header):
        self.header=header
    def extract(self):
        unpacked=struct.unpack("!6B6BH",self.header)
        print(unpacked)
        self.protocol=socket.ntohs(unpacked[12])
        Destination_MAC=eth_addr(unpacked[0:6])
        Source_MAC=eth_addr(unpacked[6:12])
        print('\n\n----eth----')
        print('Protocol: ',self.protocol)
        print('Destination_MAC: ',Destination_MAC)
        print('Source_MAC: ',Source_MAC)
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
        print('Destination-Address: ',source_addr)
        print('Source_Addrress',dest_addr)
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
        print('Destination_port: ',dest_port)
        print('Sequence: ',sequence)
        print('ACK: ',ack)
        print('Length: ',length)
while True:
    packet,address=s.recvfrom(65535)
    ethheader=eth(packet[:14])
    ethheader.extract()
    if ethheader.protocol==8:
        ipheader=ip(packet[14:34])
        ipheader.extract()
        if ipheader.protocol==6:
            tcpheader=tcp(packet[34:54])
            tcpheader.extract()
            # data
            data=packet[54:]
            print('Data:',data)
