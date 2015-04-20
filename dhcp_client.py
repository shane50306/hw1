import socket
from random import randint
import struct
from uuid import getnode as get_mac

bind_ip = '192.168.56.101' 	#'192.168.17.122'

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
		self.Dns_Server = set()
		
		
		mac = bin(get_mac())[2:]
		if len(mac) < 48:
			mac = '0' + mac
		for i in range(0, 48, 8):
			self.macaddr += struct.pack('!B', int(mac[i:i+8], 2))
			
		for i in range(4):
			self.transID += struct.pack('!B', randint(0, 255))
	
	def make_str(self, data):
		return str(data[0]) + '.' + str(data[1]) + '.' + str(data[2]) + '.' + str(data[3])
	
	def send_DHCPDiscover(self, request_ip):
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
		if request_ip != 0:
			packet += b'\x32\x04\xc0\xa8\x38'
			packet += struct.pack("!B", request_ip)#option: 50 request IP 
		packet += b'\xff' #option: end
		
		return packet
	
	def send_DHCPRequest(self):
		packet = b''
		packet += b'\x01'				#op
		packet += b'\x01'				#htype
		packet += b'\x06'				#hlen
		packet += b'\x00'				#hops
		packet += self.transID			#xid
		packet += b'\x00\x00'			#secs
		packet += b'\x80\x00'			#flags
		packet += self.YIADDR			#ciaddr
		packet += b'\x00\x00\x00\x00'	#yiaddr
		packet += b'\x00\x00\x00\x00'	#siaddr
		packet += b'\x00\x00\x00\x00'	#giaddr
		packet += self.macaddr
		packet += b'\x00'*10			#chaddr
		packet += b'\x00'*64			#sname
		packet += b'\x00'*128			#file
		packet += b'\x63\x82\x53\x63'	#magic cookie
		packet += b'\x35\x01\x03'		#option: 53 dhcp request
		packet += b'\x32\x04'			
		packet += self.YIADDR			#option: 50 request YIADDR
		packet += b'\x36\x04'
		packet += self.DHCP_Server		#option: 54 dhcp server
		packet += b'\xff' #option: end
		
		return packet

	def send_DHCPDecline(self):
		packet = b''
		packet += b'\x01'				#op
		packet += b'\x01'				#htype
		packet += b'\x06'				#hlen
		packet += b'\x00'				#hops
		packet += self.transID			#xid
		packet += b'\x00\x00'			#secs
		packet += b'\x80\x00'			#flags
		packet += self.YIADDR			#ciaddr
		packet += b'\x00\x00\x00\x00'	#yiaddr
		packet += b'\x00\x00\x00\x00'	#siaddr
		packet += b'\x00\x00\x00\x00'	#giaddr
		packet += self.macaddr
		packet += b'\x00'*10			#chaddr
		packet += b'\x00'*64			#sname
		packet += b'\x00'*128			#file
		packet += b'\x63\x82\x53\x63'	#magic cookie
		packet += b'\x35\x01\x04'		#option: 53 dhcp decline
		packet += b'\x36\x04'
		packet += self.DHCP_Server		#option: 54 dhcp server
		packet += b'\xff' #option: end
		
		return packet

	def send_DHCPRelease(self, release_ip):
		packet = b''
		packet += b'\x01'				#op
		packet += b'\x01'				#htype
		packet += b'\x06'				#hlen
		packet += b'\x00'				#hops
		packet += self.transID			#xid
		packet += b'\x00\x00'			#secs
		packet += b'\x80\x00'			#flags
		packet += b'\xc0\xa8\x38'
		packet += struct.pack("!B", release_ip)	#ciaddr	release ip
		packet += b'\x00\x00\x00\x00'	#yiaddr
		packet += b'\x00\x00\x00\x00'	#siaddr
		packet += b'\x00\x00\x00\x00'	#giaddr
		packet += self.macaddr
		packet += b'\x00'*10			#chaddr
		packet += b'\x00'*64			#sname
		packet += b'\x00'*128			#file
		packet += b'\x63\x82\x53\x63'	#magic cookie
		packet += b'\x35\x01\x07'		#option: 53 dhcp release
		packet += b'\x36\x04'
		packet += b'\xc0\xa8\x38\x01'	#option: 54 dhcp server
		packet += b'\xff' #option: end
		
		return packet

		
	def unpack(self, data):
		
		self.op = data[0]
		self.CIADDR = data[12:16]
		self.YIADDR = data[16:20]
		self.SIADDR = data[20:24]
		self.GIADDR = data[24:28]
		
		a = 240
		while True:
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
					self.Dns_Server.add(data[a+2+i : a+6+i])
				a += (2 + data[a+1])
			elif data[a] == 255:
				break
			else:
				a += (2 + data[a+1])
		
		if self.DHCP_Message_Type == 2:		#dhcp offer
			print('#Get DHCPOffer packet!')
			print('\tDHCP Server: ' + self.make_str(self.DHCP_Server))
			print('\tOffer IP: ' + self.make_str(self.YIADDR))
			print('\tSubnet Mask: ' + self.make_str(self.Subnet_Mask))
			print('\tLease times: ' + str(struct.unpack('!L', self.Leas_Time)[0]))
			print('\tDefault Gateway: ' + self.make_str(self.Router))
			print('\tDNS Server: ', end = "")
			for i in self.Dns_Server:
				print(self.make_str(i)+ '  ', end = "")
			print('\n')
			return "DHCPOffer"
		
		elif self.DHCP_Message_Type == 5:		#dhcp ack
			print('#Get DHCPAck packet!')
			print('\tDHCP Server: ' + self.make_str(self.DHCP_Server))
			print('\tOffer IP: ' + self.make_str(self.YIADDR))
			print('\tSubnet Mask: ' + self.make_str(self.Subnet_Mask))
			print('\tLease times: ' + str(struct.unpack('!L', self.Leas_Time)[0]))
			print('\tDefault Gateway: ' + self.make_str(self.Router))
			print('\tDNS Server: ', end = "")
			for i in self.Dns_Server:
				print(self.make_str(i)+ '  ', end = "")
			print('\n')
			return "DHCPAck"
		
		elif self.DHCP_Message_Type == 6:
			print('#Get DHCPNak packet!')
			return "DHCPNak"
		else:
			return "Unknown"
		
def normal_test():
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	
	sock.bind((bind_ip, 68))
	

	client = dhcp_client()
	sock.sendto(client.send_DHCPDiscover(0), ("<broadcast>", 67))
	print('\n#Client has sned DHCPDiscover packet\n')
	sock.settimeout(3)
	try:
		while True:
			data = sock.recv(65535)
			if data[4:8] == client.transID and client.unpack(data) == "DHCPOffer":
				break
	except socket.timeout as e:
		print(e)
		exit()

	
	sock.sendto(client.send_DHCPRequest(), ("<broadcast>", 67))
	print('\n#Client has sned DHCPRequest packet\n')
	sock.settimeout(3)
	try:
		while True:
			data = sock.recv(65535)
			if data[4:8] == client.transID and client.unpack(data) == "DHCPAck":
				break			
	except socket.timeout as e:
		print(e)
		exit()
		
def request_special_ip(request_ip):
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	
	sock.bind((bind_ip, 68))
	

	client = dhcp_client()
	sock.sendto(client.send_DHCPDiscover(request_ip), ("<broadcast>", 67))
	print('\n#Client has sned DHCPDiscover packet\n')
	sock.settimeout(3)
	try:
		while True:
			data = sock.recv(65535)
			if data[4:8] == client.transID and client.unpack(data) == "DHCPOffer":
				break
	except socket.timeout as e:
		print(e)
		exit()

	
	sock.sendto(client.send_DHCPRequest(), ("<broadcast>", 67))
	print('\n#Client has sned DHCPRequest packet\n')
	sock.settimeout(3)
	try:
		while True:
			data = sock.recv(65535)
			if data[4:8] == client.transID and client.unpack(data) == "DHCPAck":
				break			
	except socket.timeout as e:
		print(e)
		exit()

def request_decline():
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	
	sock.bind((bind_ip, 68))
	

	client = dhcp_client()
	sock.sendto(client.send_DHCPDiscover(0), ("<broadcast>", 67))
	print('\n#Client has sned DHCPDiscover packet\n')
	sock.settimeout(3)
	try:
		while True:
			data = sock.recv(65535)
			if data[4:8] == client.transID and client.unpack(data) == "DHCPOffer":
				break
	except socket.timeout as e:
		print(e)
		exit()

	sock.sendto(client.send_DHCPDecline(), ("<broadcast>", 67))
	print('\n#Client has sned DHCPDecline packet\n')
	sock.settimeout(3)
	try:
		while True:
			data = sock.recv(65535)
			if data[4:8] == client.transID and client.unpack(data) == "DHCPAck":
				break
	except socket.timeout as e:
		print(e)
		exit()

def release(release_ip):
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	
	sock.bind((bind_ip, 68))
	

	client = dhcp_client()
	sock.sendto(client.send_DHCPRelease(150), ("<broadcast>", 67))
	print('\n#Client has sned DHCPRelease packet\n')

		
if __name__ == '__main__':
	
	
	#normal_test()					#test normal request
	
	
	#request_special_ip(150)		#test request duplicate ip
	#request_special_ip(151)	
	
	
	#normal_test()					#test decline
	#request_decline()
	
	#release(150)					#release test
	#request_special_ip(150)
	
	