from core.device import NetworkDevice
from core.protocols.ethernet import EthernetFrame
from core.protocols.ip import IPv4Packet

class Router(NetworkDevice):
    def __init__(self, name):
        # A router doesn't have one IP; it has an IP for every interface.
        # For this simulation, we'll keep it simple.
        super().__init__(name, mac_address="AA:00:00:00:00:01")
        self.routing_table = {} # { "subnet": "wire_object" }
        self.interfaces = {}     # { "wire_object": "ip_address" }

    def add_interface(self, wire, ip_address):
        """Plugs the router into a specific network wire."""
        self.interfaces[wire] = ip_address
        wire.connect_device(self)
        # Update MAC to be unique for this router instance
        # In a real router, every port has a different MAC.

    def connect_to_wire(self, wire):
        # We override this because we use add_interface instead
        pass

    def receive_bytes(self, data):
        # 1. Unpack Ethernet
        frame = EthernetFrame.unpack(data)
        
        # 2. Unpack IP
        if frame.eth_type == EthernetFrame.TYPE_IPV4:
            ip_packet = IPv4Packet.unpack(frame.payload)
            print(f"[{self.name}] 🚩 Routing Packet: {ip_packet.src_ip} -> {ip_packet.dest_ip}")
            
            # 3. ROUTING LOGIC
            # Check which wire leads to the destination IP
            target_wire = self.determine_route(ip_packet.dest_ip)
            
            if target_wire:
                print(f"[{self.name}] ➡️ Forwarding to {target_wire}...")
                self.forward_packet(target_wire, ip_packet)
            else:
                print(f"[{self.name}] ❌ Destination {ip_packet.dest_ip} unreachable.")

    def determine_route(self, dest_ip):
        """Simple routing table logic."""
        # If IP starts with 192.168.1, use wire_1. If 192.168.2, use wire_2.
        for wire, ip in self.interfaces.items():
            if dest_ip.startswith(ip.rsplit('.', 1)[0]):
                return wire
        return None

    def forward_packet(self, wire, ip_packet):
        """Re-encapsulates the IP packet into a new Ethernet frame for the new wire."""
        # In a real router, it would check the ARP table for the destination MAC.
        # For simulation, we assume the router knows the MACs.
        dest_mac = "DD:EE:FF:44:55:66" # Hardcoded for the demo
        
        new_frame = EthernetFrame(
            dest_mac=dest_mac,
            src_mac=self.mac_address,
            eth_type=EthernetFrame.TYPE_IPV4,
            payload=ip_packet.pack()
        )
        
        # Send the bytes across the chosen wire
        wire.transmit(self.mac_address, dest_mac, new_frame.pack())
