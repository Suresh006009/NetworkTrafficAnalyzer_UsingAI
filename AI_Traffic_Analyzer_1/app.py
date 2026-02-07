import threading
import time
import sqlite3
import collections
from datetime import datetime
from flask import Flask, render_template
from flask_socketio import SocketIO
from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP

# --- CONFIGURATION ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# --- IN-MEMORY DATA STORES ---
# We use separate locks for thread safety
data_lock = threading.Lock()
traffic_stats = {
    'total_packets': 0,
    'total_bytes': 0,
    'protocol_counts': collections.Counter(),
    'top_ips': collections.Counter(),
    'throughput': [] # Stores last 60 seconds of KB/s
}
packet_window = collections.deque(maxlen=100) # Sliding window for throughput calc

# --- DATABASE ---
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS alerts 
                 (id INTEGER PRIMARY KEY, timestamp TEXT, src_ip TEXT, 
                  type TEXT, message TEXT)''')
    conn.commit()
    conn.close()

def log_alert(src, alert_type, msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Save to DB
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("INSERT INTO alerts (timestamp, src_ip, type, message) VALUES (?, ?, ?, ?)",
              (timestamp, src, alert_type, msg))
    conn.commit()
    conn.close()
    # Emit to Frontend
    socketio.emit('new_alert', {'timestamp': timestamp, 'src': src, 'type': alert_type, 'msg': msg})

# --- ANALYZER ENGINE ---
class Analyzer:
    def __init__(self):
        self.blocked_ips = set()
        self.packet_rates = {} # IP -> [timestamps]

    def check_threats(self, src_ip, dst_port):
        now = time.time()
        
        # 1. DOS Detection (Rate Limiting)
        self.packet_rates.setdefault(src_ip, []).append(now)
        # Keep last 2 seconds only
        self.packet_rates[src_ip] = [t for t in self.packet_rates[src_ip] if now - t < 2]
        
        if len(self.packet_rates[src_ip]) > 100 and src_ip not in self.blocked_ips:
            log_alert(src_ip, "DoS Attack", f"High Rate: {len(self.packet_rates[src_ip])} pkts/2s")
            self.blocked_ips.add(src_ip)

analyzer = Analyzer()

# --- PACKET CAPTURE ---
def process_packet(packet):
    global traffic_stats
    
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        size = len(packet)
        
        # Determine Protocol
        proto = "OTHER"
        if TCP in packet: proto = "TCP"
        elif UDP in packet: proto = "UDP"
        elif ICMP in packet: proto = "ICMP"
        
        # Update Global Stats
        with data_lock:
            traffic_stats['total_packets'] += 1
            traffic_stats['total_bytes'] += size
            traffic_stats['protocol_counts'][proto] += 1
            traffic_stats['top_ips'][src] += size # Count by Bandwidth usage
            
            # Add to throughput window
            packet_window.append((time.time(), size))

        # Check Threats
        analyzer.check_threats(src, 0)
        
        # Stream Packet info (Lightweight)
        socketio.emit('packet', {
            'time': datetime.now().strftime("%H:%M:%S"),
            'src': src,
            'dst': dst,
            'proto': proto,
            'size': size
        })

def start_sniffing():
    print(" >> Sniffer Started...")
    sniff(prn=process_packet, store=False)

# --- BACKGROUND STATS EMITTER ---
# This function calculates "Per Second" stats and sends them to the UI
def stats_emitter():
    while True:
        time.sleep(1)
        now = time.time()
        
        with data_lock:
            # Calculate Throughput (Bytes in last 1 second)
            current_bytes = sum(size for t, size in packet_window if now - t <= 1)
            kbps = round(current_bytes / 1024, 2)
            
            # Get Top 5 IPs
            top_5 = traffic_stats['top_ips'].most_common(5)
            
            # Snapshot for UI
            stats_snapshot = {
                'kbps': kbps,
                'total_packets': traffic_stats['total_packets'],
                'protocols': dict(traffic_stats['protocol_counts']),
                'top_ips': top_5
            }
            
        socketio.emit('stats_update', stats_snapshot)

# --- ROUTES ---
@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    init_db()
    # 1. Start Sniffer Thread
    t1 = threading.Thread(target=start_sniffing, daemon=True)
    t1.start()
    # 2. Start Stats Thread
    t2 = threading.Thread(target=stats_emitter, daemon=True)
    t2.start()
    
    print(" >> Dashboard at http://127.0.0.1:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)