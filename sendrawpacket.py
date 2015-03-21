import socket
import struct
import uuid

def add_eth():
	des_mac0='ffffffffffff'
	des_mac1=[int(mac[e:e+2],16) for e in range(0,11,2)]=[int(des_mac0[e:e+2],16) for e in range(0,11,2)]
	source_mac0=uuid.UUID(int=uuid.getnode()).hex[-12:]
	source_mac1=[int(source_mac0[e:e+2],16) for e in range(0,11,2)]
	des_mac_packed=struct.pack('!6B',des_mac1[0],des_mac1[1],des_mac1[2],des_mac1[3],des_mac1[4],des_mac1[5])
	source_mac_packed=struct.pack('!6B',source_mac1[0],source_mac1[1],source_mac1[2],source_mac1[3],source_mac1[4],source_mac1[5])
	protocal=0x800
	protocal_packed=struct.pack("!h", 0x800)
	return des_mac_packed+source_mac_packed+protocal_packed

def add_ip(proto, srcip, dstip, ident=54321):
    saddr = socket.inet_aton(srcip)
    daddr = socket.inet_aton(dstip)
    ihl_ver = (4 << 4) | 5
    return struct.pack('!BBHHHBBH4s4s' , ihl_ver, 0, 0, ident, 0, 255, proto, 0, saddr, daddr)

def add_tcp(srcport, dstport, payload, seq=123, ackseq=0,fin=False, syn=True, rst=False, psh=False, ack=False, urg=False,window=5840):
    offset_res = (5 << 4) | 0
    flags = (fin | (syn << 1) | (rst << 2) | (psh <<3) | (ack << 4) | (urg << 5))
    return struct.pack('!HHLLBBHHH', srcport, dstport, seq, ackseq, offset_res, flags, window, 0, 0)

srcip = dstip = '127.0.0.1'
srcport, dstport = 11001, 11000
payload = 'test'

eth=add_eth()
ip = add_ip(socket.IPPROTO_TCP, srcip, dstip)
tcp = add_tcp(srcport, dstport, payload)
packet = eth+ip + tcp + payload

rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
rawSocket.bind((interface, socket.htons(0x0806)))
rawSocket.send(packet)

# wait for response
rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
rawSocket.settimeout(0.5)
response = rawSocket.recvfrom(2048)
if target == socket.inet_ntoa(response[0][28:32]):
    print "Response from the folloiwing mac " + binascii.hexlify(response[0][6:12]).swapcase()
    break