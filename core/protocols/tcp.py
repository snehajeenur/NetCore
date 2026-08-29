import struct

class TCPPacket:
    # TCP Flags
    FLAG_SYN = 0x02
    FLAG_ACK = 0x10
    FLAG_FIN = 0x01

    def __init__(self, src_port, dest_port, seq_num, ack_num, flags, payload=b""):
        self.src_port = src_port
        self.dest_port = dest_port
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.flags = flags
        self.payload = payload

    def pack(self):
        """Converts TCP packet to raw bytes."""
        # Header: SrcPort(H), DestPort(H), Seq(I), Ack(I), 
        # Offset/Flags(H), Window(H), Checksum(H), Urgent(H)
        # I = 4 bytes, H = 2 bytes
        
        offset_flags = (5 << 12) | self.flags # 5 is the header length in 32-bit words
        window = 65535
        checksum = 0
        urgent = 0
        
        header = struct.pack('!HHIIHHHH', 
                             self.src_port, self.dest_port, 
                             self.seq_num, self.ack_num, 
                             offset_flags, window, checksum, urgent)
        return header + self.payload

    @staticmethod
    def unpack(raw_bytes):
        """Converts raw bytes back to TCPPacket object."""
        header = raw_bytes[:20]
        payload = raw_bytes[20:]
        
        fields = struct.unpack('!HHIIHHHH', header)
        
        src_port = fields[0]
        dest_port = fields[1]
        seq_num = fields[2]
        ack_num = fields[3]
        flags = fields[4] & 0x00FF # Mask out the offset to get only the flags
        
        return TCPPacket(src_port, dest_port, seq_num, ack_num, flags, payload)
