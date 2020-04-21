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
                UnsignedShort("opcode", OP_WHO_HAS), 
                MacAddress("src"), IPAddress("src"),
                MacAddress("dst", MAC_BROADCAST), 
                IPAddress("dst", IP_BROADCAST)]

class EthernetLayer(Layer):
    NAME = "Ethernet"

    SUB_LAYERS = [
        [ArpLayer, "ether_type", 0x806],
    ]

    @staticmethod
    def fields_info():
        return [MacAddress("dst", MAC_BROADCAST),
                MacAddress("src"),
                UnsignedShort("ether_type", 0)]

class IPLayer(Layer):
    NAME = "IP"
