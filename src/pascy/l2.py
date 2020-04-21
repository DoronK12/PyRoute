from pascy.layer import Layer
from pascy.fields import *

MAC_BROADCAST = "FF:FF:FF:FF:FF:FF"


class ArpLayer(Layer):
    OP_WHO_HAS = 1
    OP_IS_AT = 2

    NAME = "ARP"

    @staticmethod
    def fields_info():
        # TODO: Implement this :)
        return [MacAddress("dst", MAC_BROADCAST), ]

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
