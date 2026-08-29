# NetCore
 🛡️ NetCore — TCP/IP Network Stack & Security Visualizer

NetCore is a from-scratch implementation of the TCP/IP network stack built in Python. It simulates a multi-subnet network environment and provides a real-time web dashboard to visualize packet encapsulation, routing, and security threats.

 Features

1. Custom TCP/IP Stack (L2-L4)
Built from the ground up using Python's `struct` library to handle binary data:
- Layer 2 (Ethernet): Implements MAC addressing and Ethernet frames.
-Layer 3 (IPv4):Implements IP addressing, TTL, and packet routing.
Layer 4 (Transport): Implements both UDP (connectionless) and TCP (connection-oriented with a 3-way handshake).

 2. Network Simulation Engine
Instead of using real hardware, NetCore creates a "Virtual Wire" environment:
-Subnetting: Supports multiple isolated networks.
-Routing: A functional Router that handles packet forwarding between subnets using a routing table.
-Default Gateway: Devices can detect if a destination is local or remote and route packets accordingly.

 3. Real-Time Security Monitor (IDS)
A built-in Intrusion Detection System (IDS) that performs behavioral analysis:
- Port Scan Detection: Identifies attackers who attempt to connect to multiple TCP ports in a short timeframe.
- Packet Inspection: Deconstructs raw binary packets into human-readable formats.
- Real-Time Alerts: Uses WebSockets to push security threats to the dashboard instantly.

 4. Interactive Dashboard
A modern web interface built with Flask, Socket.io, and Tailwind CSS that allows users to:
- Trigger network simulations (Routing & Attacks).
- Watch packets "pop" into a live inspector in real-time.
- Monitor active security alerts.

 Tech Stack
- Language: Python 3.x
- Backend: Flask, Flask-SocketIO
- Frontend: HTML5, Tailwind CSS, JavaScript (Socket.io client)
- Core Logic: `struct` (for binary packing), `socket` (for IP handling)

 Installation & Setup

1. Clone the repository:
   bash
   git clone (https://github.com/snehajeenur/NetCore.git)
   cd NetCore
