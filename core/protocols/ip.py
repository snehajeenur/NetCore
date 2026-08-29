import struct
import socket

class IPv4Packet:
    def __init__(self, src_ip, dest_ip, protocol, payload):
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.protocol = protocol # 1=ICMP, 6=TCP, 17=UDP
        self.payload = payload

    def pack(self):
        """Converts the IP packet into raw bytes."""
        # Header Fields:
        version_ihl = 0x45 # Version 4, Length 5 (20 bytes)
        tos = 0            # Type of Service
        total_length = 20 + len(self.payload)
        id = 54321         # Identification
        flags_offset = 0    # No fragmentation
        ttl = 64           # Time to Live
        checksum = 0       # Simplified: we will leave checksum as 0 for simulation
        
        # Convert IP strings to 4-byte binary format
        src_bytes = socket.inet_aton(self.src_ip)
        dest_bytes = socket.inet_aton(self.dest_ip)

        # ! = Network Byte Order
        # B = 1 byte, H = 2 bytes, 4s = 4 bytes
        header = struct.pack('!BBHHHBBH4s4s', 
                             version_ihl, tos, total_length, id, 
                             flags_offset, ttl, self.protocol, checksum, 
                             src_bytes, dest_bytes)
        
        return header + self.payload

    @staticmethod
    def unpack(raw_bytes):
        """Converts raw bytes back into an IPv4Packet object."""
        header = raw_bytes[:20] # IP header is always 20 bytes (without options)
        payload = raw_bytes[20:]
        
        # Unpack according to the same format used in pack()
        fields = struct.unpack('!BBHHHBBH4s4s', header)
        
        # Extract specific fields
        protocol = fields[6]
        src_ip = socket.inet_ntoa(fields[8])
        dest_ip = socket.inet_ntoa(fields[9])

        return IPv4Packet(src_ip, dest_ip, protocol, payload)
