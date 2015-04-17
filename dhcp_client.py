import socket
from random import randint
import struct
from uuid import getnode as get_mac

class dhcp_client:
	
	def __init__(self):
		self.transID = b''
		self.macaddr = b''
		
		self.op = b''
		self.CIADDR = b''
		self.YIADDR = b''
		self.SIADDR = b''
		self.GIADDR = b''
		self.DHCP_Message_Type = b''
		self.Subnet_Mask = b''
		self.Router = b''
		self.Leas_Time = b''
		self.DHCP_Server = b''
		self.Dns_Server = []
		
		
		mac = bin(get_mac())[2:]
		if len(mac) < 48:
			mac = '0' + mac
		for i in range(0, 48, 8):
			self.macaddr += struct.pack('!B', int(mac[i:i+8], 2))
	
	def make_str(self, data):
		return str(data[0]) + '.' + str(data[1]) + '.' + str(data[2]) + '.' + str(data[3])
	
	def send_DHCPDiscover(self):
		
		for i in range(4):
			self.transID += struct.pack('!B', randint(0, 255))
			
		packet = b''
		packet += b'\x01'				#op
		packet += b'\x01'				#htype
		packet += b'\x06'				#hlen
		packet += b'\x00'				#hops
		packet += self.transID			#xid
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
	
	def unpack(self, data):
		if data[4:8] != self.transID:
			return
		
		self.op = data[0]
		self.CIADDR = data[12:16]
		self.YIADDR = data[16:20]
		self.SIADDR = data[20:24]
		self.GIADDR = data[24:28]
		
		a = 240
		while(data[a]):
			if data[a] == 53 :
				self.DHCP_Message_Type = data[a+2]
				a += 3
			elif data[a] == 1:
				self.Subnet_Mask = data[a+2 : a+6]
				a += 6
			elif data[a] == 3:
				self.Router = data[a+2 : a+6]
				a += 6
			elif data[a] == 51:
				self.Leas_Time = data[a+2 : a+6]
				a += 6
			elif data[a] == 54:
				self.DHCP_Server = data[a+2 : a+6]
				a += 6
			elif data[a] == 6:
				num_dns = int(data[a+1]/4)
				for i in range(0, num_dns*4, 4):
					self.Dns_Server.append(data[a+2+i : a+6+i])
				a += (2 + data[a+1])
			else:
				a += (2 + data[a+1])
		
		if self.DHCP_Message_Type == 2:		#dhcp offer
			print('#Get DHCPOffer packet!')
			print('DHCP Server: ' + self.make_str(self.DHCP_Server))
			print('Offer IP: ' + self.make_str(self.YIADDR))
			print('Subnet Mask: ' + self.make_str(self.Subnet_Mask))
			print('Lease times: ' + str(struct.unpack('!L', self.Leas_Time)[0]))
			print('Default Gateway: ' + self.make_str(self.Router))
			print('DNS Server: ', end = "")
			for i in self.Dns_Server:
				print(self.make_str(i)+ '  ', end = "")
			print('\n')
		
		

if __name__ == '__main__':
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	
	sock.bind(('192.168.0.101', 68))
	
	client = dhcp_client()
	sock.sendto(client.send_DHCPDiscover(), ("<broadcast>", 67))
	print('\n#Client has sned DHCPDiscover packet\n')
	
	sock.settimeout(3)
	try:
		while True:
			data = sock.recv(1024)
			client.unpack(data)
			break
	except socket.timeout as e:
		print(e)
	sock.close()
	exit()