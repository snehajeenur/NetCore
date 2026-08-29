from core.wire import VirtualWire
from core.device import NetworkDevice
from core.router import Router
from core.protocols.ip import IPv4Packet
from core.protocols.tcp import TCPPacket
from core.monitor import NetworkMonitor

def setup_network():
    """Helper to create the same network for every test"""
    home_net = VirtualWire()
    office_net = VirtualWire()
    
    monitor = NetworkMonitor()
    home_net.set_monitor(monitor)
    office_net.set_monitor(monitor)

    router = Router("Main-Router")
    router.add_interface(home_net, "192.168.1.1")
    router.add_interface(office_net, "192.168.2.1")

    pc_a = NetworkDevice("PC-A", "AA:BB:CC:11:22:33", "192.168.1.10")
    pc_b = NetworkDevice("PC-B", "DD:EE:FF:44:55:66", "192.168.2.10")

    pc_a.connect_to_wire(home_net)
    pc_b.connect_to_wire(office_net)
    pc_a.set_gateway(router.mac_address)
    
    return home_net, office_net, monitor, router, pc_a, pc_b

def test_routing():
    print("\n--- 🌐 Scenario 1: Basic Subnet Routing ---")
    home_net, office_net, monitor, router, pc_a, pc_b = setup_network()
    
    msg = "Hello from Home Net!".encode('utf-8')
    ip_packet = IPv4Packet(src_ip="192.168.1.10", dest_ip="192.168.2.10", protocol=17, payload=msg)
    pc_a.send_ip_packet("192.168.2.10", ip_packet)

def test_security():
    print("\n--- 🚨 Scenario 2: Port Scan Detection ---")
    home_net, office_net, monitor, router, pc_a, pc_b = setup_network()
    
    target_ports = [80, 443, 22, 21, 3306]
    for port in target_ports:
        tcp_syn = TCPPacket(src_port=5000, dest_port=port, seq_num=100, ack_num=0, flags=TCPPacket.FLAG_SYN)
        ip_packet = IPv4Packet(src_ip="192.168.1.10", dest_ip="192.168.2.10", protocol=6, payload=tcp_syn.pack())
        pc_a.send_ip_packet("192.168.2.10", ip_packet)
    
    print("\n--- Monitor Report ---")
    print(monitor.get_summary())

def main():
    while True:
        print("\n=== NetCore Test Suite ===")
        print("1. Test Subnet Routing")
        print("2. Test Security (Port Scan)")
        print("3. Exit")
        choice = input("Select a test: ")

        if choice == "1":
            test_routing()
        elif choice == "2":
            test_security()
        elif choice == "3":
            break
        else:
            print("Invalid choice!")

if __name__ == "__main__":
    main()
