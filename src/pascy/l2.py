from pascy.layer import Layer
from pascy.fields import *

MAC_BROADCAST = "FF:FF:FF:FF:FF:FF"
IP_BROADCAST = "0.0.0.0"

class ArpLayer(Layer):
    OP_WHO_HAS = 1
    OP_IS_AT = 2

    NAME = "ARP"

    @staticmethod
    def fields_info():
        # TODO: Implement this :)
        return [ UnsignedShort("hardware_type", 1), UnsignedShort("protocol_type", 0x800),
                UnsignedByte("hardware_size", 6), UnsignedByte("protocol_size", 4),
                UnsignedShort("opcode", ArpLayer.OP_IS_AT), 
                MacAddress("mac_src"), IPAddress("ip_src"),
                MacAddress("mac_dst", MAC_BROADCAST), 
                IPAddress("ip_dst", IP_BROADCAST)]


class IcmpLayer(Layer):
    PING_REQUEST = 8
    PING_REPLY = 0

    NAME = "ICMP"

    @staticmethod
    def fields_info():
        return [UnsignedByte('type', IcmpLayer.PING_REPLY), UnsignedByte('code', 0), UnsignedShort('checksum', 0),
                UnsignedInteger('headers', 0), UnsignedLong('payload_data', 0)]

class IPLayer(Layer):
    NAME = "IP"

    SHORT_MAX = 0xffff
    SHORT_SIZE = 16
    
    SUB_LAYERS = [
        [IcmpLayer, "protocol", 1]
    ]
    @staticmethod
    def fields_info():
        return [UnsignedByte('version_IHL', 0x45), UnsignedByte('service_type', 0), 
                UnsignedShort('total_length', 0), UnsignedShort('identification', 0),
                UnsignedShort('flags_frame_offset', 0x4000), UnsignedByte('TTL', 0),
                UnsignedByte('protocol', 6), UnsignedShort('checksum', 0),
                IPAddress('src'), IPAddress('dst', IP_BROADCAST)]

    @staticmethod
    def checksum(msg):
        s = 0
          # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            if i != 10:
                if (i+1) < len(msg):
                    a = msg[i]
                    b = msg[i+1]
                    s = s + (b+(a << 8))
                else:
                    raise "Something Wrong here"

        # minimize the number to 16 bit
        while s > IPLayer.SHORT_MAX:
            carry = s >> IPLayer.SHORT_SIZE
            s = s & IPLayer.SHORT_MAX
            s += carry
        
        return ~s & IPLayer.SHORT_MAX




class EthernetLayer(Layer):
    NAME = "Ethernet"

    SUB_LAYERS = [
        [ArpLayer, "ether_type", 0x806],
        [IPLayer, "ether_type", 0x800]
    ]

    @staticmethod
    def fields_info():
        return [MacAddress("dst", MAC_BROADCAST),
                MacAddress("src"),
                UnsignedShort("ether_type", 0)]

