#back up: nak
import socket
from random import randint
import struct
from uuid import getnode as get_mac
import time

class dhcp_server:
	
	def __init__(self):
		
		self.macaddr = b''
		self.request_list = set()
		
		self.op = b''
		self.CIADDR = b''
		
		self.SIADDR = b''
		self.GIADDR = b''
		self.DHCP_Message_Type = b''
		self.Subnet_Mask = b'\x01\x04\xff\xff\xff\x00'	#255.255.255.0
		self.Router = b'\x03\x04\xc0\xa8\x38\x01'		#192.168.56.1
		self.Leas_Time = b'\x33\x04\x00\x09\x3a\x80'	#604800
		self.DHCP_Server = b'\x36\x04\xc0\xa8\x38\x01'	#192.168.56.1
		self.Dns_Server = b'\x06\x04\xc0\xa8\x38\x01'	#192.168.56.1
		
		self.Request_ip = b''
		self.transID = b''
		self.YIADDR = b''
		
		self.ip_pool = {}
		for i in range(100, 200):
			self.ip_pool[i] = []

	def to_init(self):
		self.Request_ip = b''
		self.transID = b''
		self.YIADDR = b''
	
	def make_str(self, data):
		return str(data[0]) + '.' + str(data[1]) + '.' + str(data[2]) + '.' + str(data[3])
	
	def get_ip(self):
		for i in range(100, 200):
			if self.ip_pool[i] == []:
				self.ip_pool[i] = [time.time() + 604800, self.macaddr]
				return i
			elif self.ip_pool[i][0] < time.time():
				self.ip_pool[i] = [time.time() + 604800, self.macaddr]
				return i
		return 0	#error
	
	def send_DHCPOffer(self):
		if self.YIADDR == b'':
			ip = self.get_ip()
			if ip == 0:
				return 0
			self.YIADDR = struct.pack("!B", ip)
		
		packet = b''
		packet += b'\x02'						#op
		packet += b'\x01'						#htype
		packet += b'\x06'						#hlen
		packet += b'\x00'						#hops
		packet += self.transID					#xid
		packet += b'\x00\x00'					#secs
		packet += b'\x80\x00'					#flags
		packet += b'\x00\x00\x00\x00'			#ciaddr
		packet += b'\xc0\xa8\x38'
		packet += self.YIADDR					#yiaddr
		packet += b'\x00\x00\x00\x00'			#siaddr
		packet += b'\x00\x00\x00\x00'			#giaddr
		packet += self.macaddr
		packet += b'\x00'*10					#chaddr
		packet += b'\x00'*64					#sname
		packet += b'\x00'*128					#file
		packet += b'\x63\x82\x53\x63'			#magic cookie
		packet += b'\x35\x01\x02'				#option: 53 dhcp offer
		if 1 in self.request_list:				#option: 1 subnet mask
			packet += self.Subnet_Mask
		if 3 in self.request_list:				#option: 3 default router
			packet += self.Router
		packet += self.Leas_Time				#option: 51 lease time
		packet += self.DHCP_Server				#option: 54 dhcp server
		if 6 in self.request_list:				#option: 6 dns server
			packet += self.Dns_Server
		packet += b'\xff' 						#option: end
		
		return packet
	
	def send_DHCPAck(self):
		packet = b''
		packet += b'\x02'						#op
		packet += b'\x01'						#htype
		packet += b'\x06'						#hlen
		packet += b'\x00'						#hops
		packet += self.transID					#xid
		packet += b'\x00\x00'					#secs
		packet += b'\x80\x00'					#flags
		packet += b'\x00\x00\x00\x00'			#ciaddr
		packet += b'\xc0\xa8\x38'
		packet += self.YIADDR					#yiaddr
		packet += b'\x00\x00\x00\x00'			#siaddr
		packet += b'\x00\x00\x00\x00'			#giaddr
		packet += self.macaddr
		packet += b'\x00'*10					#chaddr
		packet += b'\x00'*64					#sname
		packet += b'\x00'*128					#file
		packet += b'\x63\x82\x53\x63'			#magic cookie
		packet += b'\x35\x01\x05'				#option: 53 dhcp ack
		if 1 in self.request_list:				#option: 1 subnet mask
			packet += self.Subnet_Mask
		if 3 in self.request_list:				#option: 3 default router
			packet += self.Router
		packet += self.Leas_Time				#option: 51 lease time
		packet += self.DHCP_Server				#option: 54 dhcp server
		if 6 in self.request_list:				#option: 6 dns server
			packet += self.Dns_Server
		packet += b'\xff' 						#option: end
		
		return packet
	
	def send_DHCPNak(self):
		packet = b''
		packet += b'\x02'						#op
		packet += b'\x01'						#htype
		packet += b'\x06'						#hlen
		packet += b'\x00'						#hops
		packet += self.transID					#xid
		packet += b'\x00\x00'					#secs
		packet += b'\x80\x00'					#flags
		packet += b'\x00\x00\x00\x00'			#ciaddr
		packet += b'\x00'*4						#yiaddr
		packet += b'\x00\x00\x00\x00'			#siaddr
		packet += b'\x00\x00\x00\x00'			#giaddr
		packet += self.macaddr
		packet += b'\x00'*10					#chaddr
		packet += b'\x00'*64					#sname
		packet += b'\x00'*128					#file
		packet += b'\x63\x82\x53\x63'			#magic cookie
		packet += b'\x35\x01\x06'				#option: 53 dhcp nak
		packet += self.DHCP_Server				#option: 54 dhcp server
		packet += b'\xff' 						#option: end
		
		return packet
	
	def unpack(self, data):
		if self.transID == b'':
			self.transID = data[4:8]
		
		self.op = data[0]
		self.macaddr = data[28:34]
		self.CIADDR = data[12:16]
		
		a = 240
		while(data[a]):
			if data[a] == 53 :
				self.DHCP_Message_Type = data[a+2]
				a += 3
			elif data[a] == 55:
				num_request = data[a+1]
				for i in range(num_request):
					self.request_list.add(data[a+2+i])
				a += (data[a+1] + 2)
			elif data[a] == 255:
				break
			elif data[a] == 50:
				self.Request_ip = data[a+2:a+6]
				a += 6
			elif data[a] == 54:
				if data[a+2:a+6] != self.DHCP_Server[2:6]:
					return "Unknown"
				a += 6
			else:
				a += (2 + data[a+1])
		
		if self.DHCP_Message_Type == 1:		#dhcp discover
			print('#Get DHCPDiscover packet!')
			if self.Request_ip == b'':
				return "DHCPDiscover"
			elif self.Request_ip[3]<100 or self.Request_ip[3]>199:
				print("\nClient request an illegal IP")
				return "Request duplicate"
			elif self.Request_ip[0:3] != b'\xc0\xa8\x38' or self.ip_pool[self.Request_ip[3]] != [] :
				print("\nClient request an illegal IP")
				return "Request duplicate"
			else:
				self.YIADDR = struct.pack("!B", self.Request_ip[3])
				self.ip_pool[self.Request_ip[3]] = [time.time() + 604800, self.macaddr]
				return "DHCPDiscover"
			
		
		elif self.DHCP_Message_Type == 3:		#dhcp request
			print('\n#Get DHCPRequest packet!')
			if self.Request_ip[0:3] != b'\xc0\xa8\x38' and self.Request_ip[3] != self.YIADDR:
					return "Unknown"
			return "DHCPRequest"
		
		elif  self.DHCP_Message_Type == 4:		#dhcp decline
			print('\n#Get DHCPDecline packet!')
			self.ip_pool[server.CIADDR[3]] = []
			return "DHCPDecline"
		
		elif  self.DHCP_Message_Type == 7:		#dhcp release
			if self.macaddr == self.ip_pool[server.CIADDR[3]][1]:
				print('\n#Get DHCPRelease packet!')
				self.ip_pool[server.CIADDR[3]] = []
				self.to_init()
				return "DHCPRelease"
		
		else:
			return "Unknown"

if __name__ == '__main__':
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	
	sock.bind(('192.168.56.101', 67))
	
	server = dhcp_server()
	print("\nDHCP Server is ready!\n")
	while True:
		
		while True:
			data = sock.recv(65535)
			status = server.unpack(data)
			if status == "DHCPDiscover":
				break
			elif status == "Request duplicate":
				sock.sendto(server.send_DHCPNak(), ("<broadcast>", 68))
				server.to_init()
				print("\n#Server has sned DHCPNak packet\n")
				
			
		packet = server.send_DHCPOffer()
		if packet == 0:
			continue
		sock.sendto(packet, ("<broadcast>", 68))
		print('\n#Server has sned DHCPOffer packet\n')
		
		sock.settimeout(3)
		try:
			while True:
				data = sock.recv(65535)
				status = server.unpack(data)
				if data[4:8] == server.transID and  status == "DHCPRequest" :
					sock.sendto(server.send_DHCPAck(), ("<broadcast>", 68))
					print('\n#Server has sned DHCPAck packet\n')
					print("\nIP: 192.168.56.", end = "")
					print(struct.unpack("!B", server.YIADDR)[0], "is release, mac: ", server.macaddr, "\n")
					sock.settimeout(None)
					break
				elif data[4:8] == server.transID and status == "DHCPDecline" :
					sock.settimeout(None)
					break
		except socket.timeout as e:
			print(e, ", no DHCKRequest packet receive")
			server.ip_pool[struct.unpack("!B", server.YIADDR)[0]] = []
			server.to_init()
			sock.settimeout(None)
		
		server.to_init()