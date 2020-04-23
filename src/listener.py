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

def verify_addresses(ip_address, mac_address):
	
	if ip_address in ROUTING_TABLE["net1"].keys():
			# For regular Router behavior
			if ROUTING_TABLE["net1"][ip_address] != mac_address:
				ROUTING_TABLE["net1"][ip_address] = mac_address
			return True
		
	elif ip_address in ROUTING_TABLE["net2"].keys():
		# For regular Router behavior
		if ROUTING_TABLE["net2"][ip_address] != mac_address:
			ROUTING_TABLE["net2"][ip_address] = mac_address
		return True
	else:
		return False

def parse_buffer(buffer):
	# Ethernet part
	ethernet_layer = EthernetLayer()
	ethernet_layer.deserialize(buffer[:14])

	destination_mac = MacAddress.mac2str(ethernet_layer.fields["dst"].get())
	ethernet_type = ethernet_layer.fields["ether_type"].get()

	if destination_mac == MAC_BROADCAST and ethernet_type == 0x806:
		parse_ARP(buffer[14:], ethernet_layer)

	elif ethernet_type == 0x800:
		parse_IP(buffer, ethernet_layer)


def parse_IP(buffer, ethernet_layer):
	#IP part
	ip_layer = IPLayer()
	ip_layer.deserialize(buffer[14:34])

	# Calculate the checksum and verify it.
	if IPLayer.checksum(buffer[14:34]) == ip_layer.fields["checksum"].get():

		destination_ip = IPAddress.ip2str(ip_layer.fields["dst"].get())
		source_ip = IPAddress.ip2str(ip_layer.fields["src"].get())

		if not verify_addresses(source_ip, MacAddress.mac2str(ethernet_layer.fields["src"].get())):
			return

		if destination_ip == MY_ADDRESSES["net1"][1] or destination_ip == MY_ADDRESSES["net2"][1]:
			pass
			# The destination is ME!
			# if ip_layer.fields["protocol"].get()

		# If the packet need to be forward
		elif destination_ip in ROUTING_TABLE["net1"].keys() or destination_ip in ROUTING_TABLE["net2"].keys():


			network = get_network_by_ip(IPAddress.ip2str(destination_ip))

			ethernet_layer.fields["src"].set(MacAddress.str2mac(MY_ADDRESSES[network][0]))

			ethernet_layer.fields["dst"].set(MacAddress.str2mac(ROUTING_TABLE[network][destination_ip]))

			buffer = buffer[14:]

			buffer = ethernet_layer.build() + buffer

			PACKETS_TO_SEND.append((find_network_place(network) , buffer))

			print("Packet forward")
		else:
			return



def parse_ARP(buffer, ethernet_layer):
	#ARP part
	arp_layer = ArpLayer()
	arp_layer.deserialize(buffer[:28])

	destination_ip = IPAddress.ip2str(arp_layer.fields["ip_dst"].get())

	if destination_ip == MY_ADDRESSES["net1"][1] or destination_ip == MY_ADDRESSES["net2"][1]:

		src_ip = IPAddress.ip2str(arp_layer.fields["ip_src"].get())
		
		if not verify_addresses(src_ip, MacAddress.mac2str(arp_layer.fields["mac_src"].get())):
			return

		if arp_layer.fields["opcode"].get() == ArpLayer.OP_WHO_HAS:
			# ethernet_layer.connect_layer(arp_layer)
			build_ARP_response(ethernet_layer, arp_layer)


def build_ARP_response(ethernet_layer, arp_layer):
	global PACKETS_TO_SEND

	network = get_network_by_ip(IPAddress.ip2str(arp_layer.fields["ip_src"].get()))

	# Switch the source and destination MAC addresses.
	ethernet_layer.fields["dst"].set(ethernet_layer.fields["src"].get())

	ethernet_layer.fields["src"].set(MacAddress.str2mac(MY_ADDRESSES[network][0]))

	# Change the addresses in the ARP Layer and the opcode.
	arp_layer.fields["opcode"].set(ArpLayer.OP_IS_AT)

	arp_layer.fields["ip_dst"].set(arp_layer.fields["ip_src"].get())

	arp_layer.fields["mac_dst"].set(arp_layer.fields["mac_src"].get())

	arp_layer.fields["mac_src"].set(MacAddress.str2mac(MY_ADDRESSES[network][0]))

	arp_layer.fields["ip_src"].set(IPAddress.str2ip(MY_ADDRESSES[network][1]))

	ethernet_layer.connect_layer(arp_layer)

	PACKETS_TO_SEND.append((find_network_place(network) , ethernet_layer.build()))

	print("ARP response sent")



def create_sockets():

	read_sockets = []
	read_sockets.append(socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(socket.PACKET_OTHERHOST)))
	read_sockets[0].bind(('net1', 0))
	read_sockets.append(socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(socket.PACKET_OTHERHOST)))
	read_sockets[1].bind(('net2', 0))
	return read_sockets

def find_network_place(network):
	return list(ROUTING_TABLE.keys()).index(network)

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
				parse_buffer(data)

			except socket.error:
				continue

		for packet in PACKETS_TO_SEND:
			(client_index, pack) = packet
			if read_sockets[client_index] in wlist:
				read_sockets[client_index].send(pack)
			PACKETS_TO_SEND.remove(packet)

	for sock in read_sockets:
		sock.close()


if __name__ == '__main__':
	main()