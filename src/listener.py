import select
import socket
from pascy.l2 import *
import sys

MY_ADDRESSES = {
	"net1": ["02:42:37:94:2b:e4", "1.1.1.1"],
	"net2": ["02:42:04:89:4c:a0", "2.2.2.1"]
	}

ROUTING_TABLE = {
	"net1": 
			{ "1.1.1.2": "02:42:01:01:01:02" 
			},
	"net2":
			{ "2.2.2.2": "02:42:02:02:02:02"
			}
	}

PACKETS_TO_SEND = []

def get_network_by_ip(ip):
	for network in ROUTING_TABLE:
		if ip in ROUTING_TABLE[network].keys():
			return network
	return ""

def parse_buffer(buffer, current_socket):
	# Ethernet part
	ethernet_layer = EthernetLayer()
	ethernet_layer.deserialize(buffer[:14])
	# for field in ethernet_layer.fields:
	# 	print(ethernet_layer.fields[field])

	destination_mac = MacAddress.mac2str(ethernet_layer.fields["dst"].get())
	ethernet_type = ethernet_layer.fields["ether_type"].get()

	if destination_mac == MAC_BROADCAST and ethernet_type == 0x806:
		parse_ARP(buffer[14:], ethernet_layer, current_socket)

	# If the packet is for us
	elif destination_mac == MY_ADDRESSES["net1"][0] or destination_mac == MY_ADDRESSES["net2"][0]:
		if ethernet_type == 0x800:
			parse_IP(buffer[14:], ethernet_layer, current_socket)


def parse_IP(buffer, ethernet_layer, current_socket):
	pass


def parse_ARP(buffer, ethernet_layer, current_socket):
	#ARP part
	arp_layer = ArpLayer()
	arp_layer.deserialize(buffer[:28])
	
	# Debug printing
	for field in arp_layer.fields:
		print(arp_layer.fields[field])

	destination_ip = IPAddress.ip2str(arp_layer.fields["ip_dst"].get())

	if destination_ip == MY_ADDRESSES["net1"][1] or destination_ip == MY_ADDRESSES["net2"][1]:

		src_ip = IPAddress.ip2str(arp_layer.fields["ip_src"].get())
		
		if src_ip in ROUTING_TABLE["net1"].keys():
			# For regular Router behavior
			if ROUTING_TABLE["net1"][src_ip] != MacAddress.mac2str(arp_layer.fields["mac_src"].get()):
				ROUTING_TABLE["net1"][src_ip] = MacAddress.mac2str(arp_layer.fields["mac_src"].get())
		
		elif src_ip in ROUTING_TABLE["net2"].keys():
			# For regular Router behavior
			if ROUTING_TABLE["net2"][src_ip] != MacAddress.mac2str(arp_layer.fields["mac_src"].get()):
				ROUTING_TABLE["net2"][src_ip] = MacAddress.mac2str(arp_layer.fields["mac_src"].get())
		
		else:
			return

		if arp_layer.fields["opcode"].get() == ArpLayer.OP_WHO_HAS:
			# ethernet_layer.connect_layer(arp_layer)
			build_ARP_response(ethernet_layer, arp_layer, current_socket)


def build_ARP_response(ethernet_layer, arp_layer, current_socket):
	global PACKETS_TO_SEND

	network = get_network_by_ip(IPAddress.ip2str(arp_layer.fields["ip_src"].get()))

	# Switch the source and destination MAC addresses.
	ethernet_layer.fields["dst"].set(ethernet_layer.fields["src"].get())

	ethernet_layer.fields["src"].set(MacAddress.str2mac(MY_ADDRESSES[network][0]))

	arp_layer.fields["opcode"].set(ArpLayer.OP_IS_AT)

	arp_layer.fields["ip_dst"].set(arp_layer.fields["ip_src"].get())

	arp_layer.fields["mac_dst"].set(arp_layer.fields["mac_src"].get())

	arp_layer.fields["mac_src"].set(MacAddress.str2mac(MY_ADDRESSES[network][0]))

	arp_layer.fields["ip_src"].set(IPAddress.str2ip(MY_ADDRESSES[network][1]))

	ethernet_layer.connect_layer(arp_layer)

	PACKETS_TO_SEND.append((current_socket, ethernet_layer.build()))
	# print("RESPONSE*****************")
	# ethernet_layer.display()




def create_sockets():
	read_sockets = []
	read_sockets.append(socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(socket.PACKET_OTHERHOST)))
	read_sockets[0].bind(('net1', 0))
	read_sockets.append(socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(socket.PACKET_OTHERHOST)))
	read_sockets[1].bind(('net2', 0))
	return read_sockets

def find_socket_place(read_sockets, new_socket):
	for sock in read_sockets:
		if sock == new_socket:
			return read_sockets.index(sock)
	return -1

def main():
	global PACKETS_TO_SEND
	read_sockets = create_sockets()

	while True:
		#rlist - clients we want and can to read data from
		#wlist - clients we want and can to send data to them
		#xlist - clients that have a error
		rlist, wlist, xlist = select.select(read_sockets, read_sockets, [])

		for current_socket in rlist:

			try:
				data = current_socket.recv(1024)
				parse_buffer(data, current_socket)

			except socket.error:
				continue

		for packet in PACKETS_TO_SEND:
			(client_socket, pack) = packet
			if client_socket in wlist:
				client_socket.send(pack)
			PACKETS_TO_SEND.remove(packet)

	for sock in read_sockets:
		sock.close()


if __name__ == '__main__':
	main()