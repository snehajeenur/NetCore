from core.protocols.ethernet import EthernetFrame
from core.protocols.ip import IPv4Packet
from core.protocols.udp import UDPPacket
from core.protocols.tcp import TCPPacket

class NetworkDevice:
    def __init__(self, name, mac_address, ip_address=None):
        self.name = name
        self.mac_address = mac_address
        self.ip_address = ip_address
        self.wire = None
        self.gateway_mac = None # The MAC address of the Router
        self.tcp_connections = {} # TCP State: {(remote_ip, remote_port): "STATE"}

    def connect_to_wire(self, wire):
        """Plugs the device into a virtual wire."""
        self.wire = wire
        wire.connect_device(self)

    def set_gateway(self, mac):
        """Sets the MAC address of the default gateway (router)."""
        self.gateway_mac = mac

    def send_raw_bytes(self, dest_mac, data):
        """The physical layer: sends bytes across the wire."""
        if self.wire:
            self.wire.transmit(self.mac_address, dest_mac, data)
        else:
            print(f"[{self.name}] ❌ Error: Not connected to any wire!")

    def send_ip_packet(self, dest_ip, ip_packet):
        """
        Layer 3 Logic: Decides if the packet should be sent 
        directly (local) or to the Gateway (remote).
        """
        # Check if dest_ip is in the same subnet (simplified check)
        if dest_ip.startswith(self.ip_address.rsplit('.', 1)[0]):
            print(f"[{self.name}] 🏠 Dest {dest_ip} is local. Sending directly.")
            # In a real system, we'd use ARP to find this MAC
            dest_mac = "DD:EE:FF:44:55:66" 
        else:
            print(f"[{self.name}] 🌍 Dest {dest_ip} is remote. Sending to Gateway.")
            dest_mac = self.gateway_mac

        if not dest_mac:
            print(f"[{self.name}] ❌ Error: No route to {dest_ip} (No gateway set).")
            return

        # Encapsulate IP Packet into Ethernet Frame
        frame = EthernetFrame(dest_mac, self.mac_address, EthernetFrame.TYPE_IPV4, ip_packet.pack())
        self.send_raw_bytes(dest_mac, frame.pack())

    def receive_bytes(self, data):
        """The receiving stack: L2 -> L3 -> L4"""
        # --- LAYER 2: Ethernet ---
        frame = EthernetFrame.unpack(data)
        
        # --- LAYER 3: IPv4 ---
        if frame.eth_type == EthernetFrame.TYPE_IPV4:
            ip_packet = IPv4Packet.unpack(frame.payload)
            
            # --- LAYER 4: Transport ---
            if ip_packet.protocol == 17: # UDP
                udp_packet = UDPPacket.unpack(ip_packet.payload)
                print(f"[{self.name}] 📩 UDP Port {udp_packet.dest_port}: {udp_packet.payload}")
            
            elif ip_packet.protocol == 6: # TCP
                tcp_packet = TCPPacket.unpack(ip_packet.payload)
                self.handle_tcp(ip_packet, tcp_packet)
            else:
                print(f"[{self.name}] 📩 Received IP packet with protocol {ip_packet.protocol}")

    def handle_tcp(self, ip_packet, tcp_packet):
        """TCP State Machine for the 3-Way Handshake"""
        remote_ip = ip_packet.src_ip
        remote_port = tcp_packet.src_port
        conn_key = (remote_ip, remote_port)
        
        print(f"[{self.name}] 📩 TCP Packet from {remote_ip}:{remote_port} | Flags: {hex(tcp_packet.flags)}")

        # Server receives SYN -> Respond with SYN-ACK
        if tcp_packet.flags == TCPPacket.FLAG_SYN:
            print(f"[{self.name}] 🤝 SYN received. Sending SYN-ACK...")
            self.tcp_connections[conn_key] = "SYN_RECEIVED"
            
            response = TCPPacket(
                src_port=tcp_packet.dest_port,
                dest_port=tcp_packet.src_port,
                seq_num=500, 
                ack_num=tcp_packet.seq_num + 1,
                flags=TCPPacket.FLAG_SYN | TCPPacket.FLAG_ACK
            )
            self.send_tcp_packet(remote_ip, response)

        # Server receives ACK -> Connection Established
        elif tcp_packet.flags == TCPPacket.FLAG_ACK and self.tcp_connections.get(conn_key) == "SYN_RECEIVED":
            print(f"[{self.name}] ✅ ACK received. Connection ESTABLISHED!")
            self.tcp_connections[conn_key] = "ESTABLISHED"

    def send_tcp_packet(self, dest_ip, tcp_packet):
        """Helper to wrap TCP in IP and Ethernet"""
        # For simulation, we use simple MAC mapping
        dest_mac = "DD:EE:FF:44:55:66" if dest_ip == "192.168.2.10" else "AA:BB:CC:11:22:33"
        
        ip_packet = IPv4Packet(self.ip_address, dest_ip, 6, tcp_packet.pack())
        eth_frame = EthernetFrame(dest_mac, self.mac_address, EthernetFrame.TYPE_IPV4, ip_packet.pack())
        self.send_raw_bytes(dest_mac, eth_frame.pack())
