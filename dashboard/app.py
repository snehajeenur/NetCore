import sys
import os

# This ensures Python can find the 'core' folder regardless of where the script is run
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
from core.wire import VirtualWire
from core.device import NetworkDevice
from core.router import Router
from core.protocols.ip import IPv4Packet
from core.protocols.tcp import TCPPacket
from core.protocols.udp import UDPPacket
from core.monitor import NetworkMonitor

app = Flask(__name__)
app.config['SECRET_KEY'] = 'netcore_secret!'
# cors_allowed_origins="*" allows the browser to communicate with the socket server
socketio = SocketIO(app, cors_allowed_origins="*")

# The global monitor that tracks all traffic in the simulation
monitor = NetworkMonitor()

def setup_simulation():
    """Creates a fresh virtual network environment for each simulation run"""
    home_net = VirtualWire()
    office_net = VirtualWire()
    
    # Attach the monitor to both wires to capture all traffic
    home_net.set_monitor(monitor)
    office_net.set_monitor(monitor)

    # Setup Router
    router = Router("Main-Router")
    router.add_interface(home_net, "192.168.1.1")
    router.add_interface(office_net, "192.168.2.1")

    # Setup Devices
    pc_a = NetworkDevice("PC-A", "AA:BB:CC:11:22:33", "192.168.1.10")
    pc_b = NetworkDevice("PC-B", "DD:EE:FF:44:55:66", "192.168.2.10")

    pc_a.connect_to_wire(home_net)
    pc_b.connect_to_wire(office_net)
    pc_a.set_gateway(router.mac_address)
    
    return pc_a, pc_b

@app.route('/')
def index():
    """Serves the main dashboard page"""
    return render_template('index.html')

@app.route('/api/stats')
def get_stats():
    """Returns current summary of packets and alerts"""
    return jsonify(monitor.get_summary())

@app.route('/api/packets')
def get_packets():
    """Returns the full history of captured packets"""
    return jsonify(monitor.packet_log)

@app.route('/api/simulate/routing')
def simulate_routing():
    """Triggers a packet journey from one subnet to another"""
    pc_a, pc_b = setup_simulation()
    
    # Properly encapsulate: App Data -> UDP -> IP -> Ethernet
    msg = "Hello from Real-Time NetCore!".encode('utf-8')
    udp_packet = UDPPacket(src_port=5000, dest_port=80, payload=msg)
    ip_packet = IPv4Packet(src_ip="192.168.1.10", dest_ip="192.168.2.10", protocol=17, payload=udp_packet.pack())
    
    pc_a.send_ip_packet("192.168.2.10", ip_packet)
    return jsonify({"status": "success", "message": "Routing packet sent!"})

@app.route('/api/simulate/attack')
def simulate_attack():
    """Triggers a port scan simulation to fire security alerts"""
    pc_a, pc_b = setup_simulation()
    
    # Attack: Hit multiple ports rapidly
    target_ports = [80, 443, 22, 21, 3306]
    for port in target_ports:
        tcp_syn = TCPPacket(src_port=5000, dest_port=port, seq_num=100, ack_num=0, flags=TCPPacket.FLAG_SYN)
        ip_packet = IPv4Packet(src_ip="192.168.1.10", dest_ip="192.168.2.10", protocol=6, payload=tcp_syn.pack())
        pc_a.send_ip_packet("192.168.2.10", ip_packet)
        
    return jsonify({"status": "success", "message": "Port scan attack simulated!"})

@app.route('/api/clear')
def clear_logs():
    """Wipes all logs and reset security states"""
    monitor.packet_log = []
    monitor.alerts = []
    monitor.connection_attempts = {}
    return jsonify({"status": "success", "message": "Logs cleared!"})

# --- WebSocket Callbacks ---

def on_packet_captured(packet_info):
    """Pushed to browser whenever a packet is intercepted by the monitor"""
    socketio.emit('new_packet', packet_info)

def on_alert_triggered(alert_msg):
    """Pushed to browser whenever the security analysis finds a threat"""
    socketio.emit('new_alert', alert_msg)

# Inject these callbacks into the monitor object
monitor.on_capture_callback = on_packet_captured
monitor.on_alert_callback = on_alert_triggered

if __name__ == '__main__':
    # Use socketio.run instead of app.run to enable WebSocket support
    socketio.run(app, debug=True, port=5000)
