import time
from core.protocols.ethernet import EthernetFrame
from core.protocols.ip import IPv4Packet
from core.protocols.tcp import TCPPacket
from core.protocols.udp import UDPPacket

class NetworkMonitor:
    def __init__(self):
        self.packet_log = [] 
        self.alerts = []     
        self.connection_attempts = {} 

    def capture_packet(self, raw_bytes):
        """Intercepts raw bytes and parses them into a readable format."""
        try:
            # 1. Parse L2
            eth = EthernetFrame.unpack(raw_bytes)
            packet_info = {
                "timestamp": time.time(),
                "l2": {"src": eth.src_mac, "dst": eth.dest_mac, "type": hex(eth.eth_type)},
                "l3": None, "l4": None, "payload": None
            }

            # 2. Parse L3
            if eth.eth_type == EthernetFrame.TYPE_IPV4:
                ip = IPv4Packet.unpack(eth.payload)
                packet_info["l3"] = {"src": ip.src_ip, "dst": ip.dest_ip, "proto": ip.protocol}
                
                # 3. Parse L4
                if ip.protocol == 17: # UDP
                    udp = UDPPacket.unpack(ip.payload)
                    packet_info["l4"] = {"type": "UDP", "src_port": udp.src_port, "dst_port": udp.dest_port}
                    packet_info["payload"] = udp.payload.decode('utf-8', errors='ignore')
                
                elif ip.protocol == 6: # TCP
                    tcp = TCPPacket.unpack(ip.payload)
                    packet_info["l4"] = {"type": "TCP", "src_port": tcp.src_port, "dst_port": tcp.dest_port, "flags": hex(tcp.flags)}
                    packet_info["payload"] = tcp.payload.decode('utf-8', errors='ignore')
            
            self.packet_log.append(packet_info)
            
            # Push to real-time dashboard
            if hasattr(self, 'on_capture_callback'):
                self.on_capture_callback(packet_info)
            
            # RUN SECURITY ANALYSIS
            self.analyze_security(packet_info)
            
        except Exception as e:
            print(f"Monitor Error: {e}")

    # --- THIS MUST BE ALIGNED WITH THE OTHER 'def' STATEMENTS ---
    def analyze_security(self, packet):
        """Analyze packet behavior for security threats"""
        if not packet["l3"] or not packet["l4"]: return
        src_ip = packet["l3"]["src"]
        l4_info = packet["l4"]
        
        if l4_info["type"] == "TCP":
            dst_port = l4_info["dst_port"]
            if src_ip not in self.connection_attempts:
                self.connection_attempts[src_ip] = {"ports": set(), "start_time": time.time()}
            
            self.connection_attempts[src_ip]["ports"].add(dst_port)
            
            # DEBUG PRINT
            current_ports = len(self.connection_attempts[src_ip]["ports"])
            print(f"[DEBUG] IP {src_ip} has hit {current_ports} unique ports.")

            # Rule: More than 3 ports = Port Scan
            if current_ports > 3:
                alert_msg = f"🚨 ALERT: Port Scan detected from {src_ip}!"
                print(f"[DEBUG] !!! SECURITY ALERT TRIGGERED: {alert_msg} !!!")
                
                if alert_msg not in self.alerts:
                    self.alerts.append(alert_msg)
                    if hasattr(self, 'on_alert_callback'):
                        print(f"[DEBUG] Sending alert to dashboard via WebSocket...")
                        self.on_alert_callback(alert_msg)

    def get_summary(self):
        return {"total_packets": len(self.packet_log), "alerts": self.alerts}
