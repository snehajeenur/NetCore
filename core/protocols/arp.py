import struct

class ARPPacket:
    def __init__(self, operation, src_mac, src_ip, dest_mac, dest_ip):
        self.operation = operation  # 1 for Request, 2 for Reply
        self.src_mac = src_mac
        self.src_ip = src_ip
        self.dest_mac = dest_mac
        self.dest_ip = dest_ip

    def pack(self):
        # ARP Header: Hardware Type(2), Protocol Type(2), HW Size(1), Proto Size(1), Opcode(2)...
        # Simplified for our simulation
        hw_type = 1       # Ethernet
        proto_type = 0x0800 # IPv4
        hw_size = 6
        proto_size = 4
        
        src_mac_bytes = bytes.fromhex(self.src_mac.replace(':', ''))
        src_ip_bytes = bytes.fromhex(self.src_ip.replace('.', ' ').replace(' ', '')) # Simplified
        # Let's use a better IP to bytes converter
        def ip_to_bytes(ip):
            return bytes(int(x) for x in ip.split('.'))

        header = struct.pack('!HHBBH', hw_type, proto_type, hw_size, proto_size, self.operation)
        
        return header + src_mac_bytes + ip_to_bytes(self.src_ip) + \
               bytes.fromhex(self.dest_mac.replace(':', '')) + ip_to_bytes(self.dest_ip)

    @staticmethod
    def unpack(raw_bytes):
        # Unpacking ARP is similar to Ethernet, slicing the bytes
        # For now, we focus on the logic of sending a request.
        pass
