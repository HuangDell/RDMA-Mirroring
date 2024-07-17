from scapy.all import *
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether

class BTH(Packet):
    name = "BTH"
    fields_desc = [
        BitField("opcode", 0, 8),
        BitField("se", 0, 1),
        BitField("m", 0, 1),
        BitField("pad_count", 0, 2),
        BitField("transport_hdr_version", 0, 4),
        ShortField("partition_key", 0),
        BitField("reserved", 0, 8),
        BitField("dest_qp", 0, 24),
        XIntField("psn", 0),
    ]

class RoCEPayload(Packet):
    name = "RoCEPayload"
    fields_desc = [
        IntField("custom_payload", 0)  
    ]

eth = Ether(dst="12:34:56:78:90:12", src="00:11:22:33:44:55")
ip = IP(dst="192.168.1.2", src="192.168.1.1")
udp = UDP(dport=4791, sport=12345)  
bth = BTH(opcode=0x04, dest_qp=0x1)
roce_payload = RoCEPayload(custom_payload=0xdeadbeef)

packet = eth / ip / udp / bth / roce_payload
packet.show()

sendp(packet, iface="veth0")