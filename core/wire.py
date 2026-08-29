import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

class VirtualWire:
    def __init__(self):
        self.connected_devices = {}
        self.monitor = None # Add a slot for the monitor

    def set_monitor(self, monitor):
        """Plugs in a network monitor to listen to traffic."""
        self.monitor = monitor

    def connect_device(self, device):
        self.connected_devices[device.mac_address] = device
        logging.info(f"Device {device.name} connected with MAC {device.mac_address}")

    def transmit(self, sender_mac, dest_mac, packet_bytes):
        # --- THE SPY LAYER ---
        # If a monitor is attached, send a copy of the packet to it
        if self.monitor:
            self.monitor.capture_packet(packet_bytes)
        
        # Normal delivery logic
        if dest_mac in self.connected_devices:
            self.connected_devices[dest_mac].receive_bytes(packet_bytes)
        else:
            logging.warning(f"Wire: Destination {dest_mac} not found. Packet dropped.")
