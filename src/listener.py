import select
import socket

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

	read_sockets = create_sockets()

	while True:
		#rlist - clients we want and can to read data from
		#wlist - clients we want and can to send data to them
		#xlist - clients that have a error
		rlist, wlist, xlist = select.select(read_sockets, read_sockets, [])

		for current_socket in rlist:

			try:
				data = current_socket.recv(1024)
				print(data)

			except socket.error:
				continue

	for sock in read_sockets:
		sock.close()


if __name__ == '__main__':
	main()