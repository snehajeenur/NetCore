import struct

class UDPPacket:
    def __init__(self, src_port, dest_port, payload):
        self.src_port = src_port
        self.dest_port = dest_port
        self.payload = payload

    def pack(self):
        """Converts the UDP packet into raw bytes."""
        length = 8 + len(self.payload) # 8 bytes for UDP header
        checksum = 0 # Simplified: skipping checksum for simulation
        
        # ! = Network Byte Order
        # H = Unsigned Short (2 bytes)
        header = struct.pack('!HHHH', self.src_port, self.dest_port, length, checksum)
        return header + self.payload

    @staticmethod
    def unpack(raw_bytes):
        """Converts raw bytes back into a UDPPacket object."""
        header = raw_bytes[:8]
        payload = raw_bytes[8:]
        
        src_port, dest_port, length, checksum = struct.unpack('!HHHH', header)
        
        return UDPPacket(src_port, dest_port, payload)
