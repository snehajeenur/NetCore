import struct

class EthernetFrame:
    # EtherType constants
    TYPE_IPV4 = 0x0800
    TYPE_ARP = 0x0806

    def __init__(self, dest_mac, src_mac, eth_type, payload):
        self.dest_mac = dest_mac
        self.src_mac = src_mac
        self.eth_type = eth_type
        self.payload = payload

    def pack(self):
        """Converts the frame into raw bytes for the wire."""
        # ! = Network Byte Order (Big Endian)
        # 6s = 6 bytes for MAC
        # 6s = 6 bytes for MAC
        # H = Unsigned Short (2 bytes) for Type
        
        # Convert MAC strings (AA:BB...) to actual bytes
        dest_bytes = bytes.fromhex(self.dest_mac.replace(':', ''))
        src_bytes = bytes.fromhex(self.src_mac.replace(':', ''))
        
        header = struct.pack('!6s6sH', dest_bytes, src_bytes, self.eth_type)
        return header + self.payload

    @staticmethod
    def unpack(raw_bytes):
        """Converts raw bytes from the wire back into an EthernetFrame object."""
        header = raw_bytes[:14] # Ethernet header is always 14 bytes
        payload = raw_bytes[14:]
        
        dest_bytes, src_bytes, eth_type = struct.unpack('!6s6sH', header)
        
        # Convert bytes back to readable MAC strings
        dest_mac = ':'.join(format(b, '02x') for b in dest_bytes) # This is a shortcut
        # Wait, the above shortcut is slightly wrong. Let's fix the formatting:
        dest_mac = ':'.join(f"{b:02x}" for b in dest_bytes) # WRONG
        
        # Correct way to format MAC bytes to string:
        def bytes_to_mac(b):
            return ':'.join(f"{x:02x}" for x in b)

        return EthernetFrame(
            dest_mac=bytes_to_mac(dest_bytes), 
            src_mac=bytes_to_mac(src_bytes), 
            eth_type=eth_type, 
            payload=payload
        )
