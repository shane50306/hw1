import socket
from random import randint
import struct
from uuid import getnode as get_mac

class dhcp_client:
	
	def __init__(self):
		self.transID = b''
		self.macaddr = b''
		
		mac = bin(get_mac())[2:]
		if len(mac) < 48:
			mac = '0' + mac
		for i in range(0, 48, 8):
			self.macaddr += struct.pack('!B', int(mac[i:i+8], 2))
	
	def discover(self):
		
		for i in range(4):
			self.transID += struct.pack('!B', randint(0, 255))
			
		packet = b''
		packet += b'\x01'				#op
		packet += b'\x01'				#htype
		packet += b'\x06'				#hlen
		packet += b'\x00'				#hops
		packet += self.transID			#xid
		print(self.transID)
		packet += b'\x00\x00'			#secs
		packet += b'\x80\x00'			#flags
		packet += b'\x00\x00\x00\x00'	#ciaddr
		packet += b'\x00\x00\x00\x00'	#yiaddr
		packet += b'\x00\x00\x00\x00'	#siaddr
		packet += b'\x00\x00\x00\x00'	#giaddr
		packet += self.macaddr
		packet += b'\x00'*10			#chaddr
		packet += b'\x00'*64			#sname
		packet += b'\x00'*128			#file
		packet += b'\x63\x82\x53\x63'	#magic cookie
		packet += b'\x35\x01\x01'		#option: 53 dhcp discover
		packet += b'\x37\x03\x01\x03\x06'#option: 55 request subnet mask, router, dns
		packet += b'\xff' #option: end
		
		return packet
	
#	def get_offer(self):
		
#	def request(self):
		
#	def get_ack(self):

if __name__ == '__main__':
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	sock.bind(('', 68))
	
	client = dhcp_client()
	sock.sendto(client.discover(), ("<broadcast>", 67))