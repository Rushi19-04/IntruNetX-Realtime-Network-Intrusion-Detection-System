from flask import Flask, render_template, jsonify, request, send_file
import threading
import scapy.all as scapy
import time
import csv

from predict import FlowPredictor
from flow_tracker import FlowTracker

app = Flask(__name__)

INTERFACE = r"\Device\NPF_{75F3FBB0-8D13-4746-AAE2-38E7CAC2C686}"

captured_data = []
blocked_ips = {}  # Stores {ip: timestamp}
capture_thread = None
capture_running = False
lock = threading.Lock()

PROTOCOLS = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}

# Initialize ML predictor and flow tracker
predictor = FlowPredictor()
flow_tracker = FlowTracker()

def get_protocol_name(proto_number):
    return PROTOCOLS.get(proto_number, f"Other ({proto_number})")

def packet_callback(packet):
    if not capture_running or not packet.haslayer(scapy.IP):
        return

    ip_layer = packet[scapy.IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    protocol = get_protocol_name(ip_layer.proto)

    if src_ip in blocked_ips:
        return  # Ignore if source IP is blocked

    length = len(packet)
    src_port = dst_port = None

    if packet.haslayer(scapy.TCP):
        src_port = packet[scapy.TCP].sport
        dst_port = packet[scapy.TCP].dport
    elif packet.haslayer(scapy.UDP):
        src_port = packet[scapy.UDP].sport
        dst_port = packet[scapy.UDP].dport

    # Basic flow-level packet info
    flow_info = {
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'protocol': protocol,
        'src_port': src_port,
        'dst_port': dst_port,
        'length': length,
        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
    }

    # Update flow tracker and predict if enough data
    features = flow_tracker.update_flow(flow_info)
    prediction = "Waiting"
    if features:
        prediction = predictor.predict(features)

    with lock:
        flow_info['prediction'] = prediction
        captured_data.insert(0, flow_info)
        if len(captured_data) > 100:
            captured_data.pop()

def capture_packets():
    scapy.sniff(iface=INTERFACE, prn=packet_callback, store=0)

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/start_capture')
def start_capture():
    global capture_thread, capture_running
    if not capture_running:
        capture_running = True
        capture_thread = threading.Thread(target=capture_packets, daemon=True)
        capture_thread.start()
    return "Capture started"

@app.route('/stop_capture', methods=['GET'])
def stop_capture():
    global capture_running
    capture_running = False
    # Code to stop packet capture (stop the scapy sniffing or similar logic)
    return "Capture stopped"

@app.route('/captured_data')
def get_data():
    with lock:
        return jsonify(captured_data)

@app.route('/block_ip', methods=['POST'])
def block_ip():
    ip = request.json.get('ip')
    if ip and ip not in blocked_ips:
        blocked_ips[ip] = time.strftime("%Y-%m-%d %H:%M:%S")
    return jsonify({'status': 'blocked', 'ip': ip})

@app.route('/unblock_ip', methods=['POST'])
def unblock_ip():
    ip = request.json.get('ip')
    if ip in blocked_ips:
        del blocked_ips[ip]
    return jsonify({'status': 'unblocked', 'ip': ip})

@app.route('/blocked_ips')
def get_blocked_ips():
    with lock:
        return jsonify([
            {'src_ip': ip, 'timestamp': timestamp}
            for ip, timestamp in blocked_ips.items()
        ])

@app.route('/export_csv')
def export_csv():
    filename = 'captured_traffic.csv'
    with lock:
        with open(filename, mode='w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=[
                'timestamp', 'src_ip', 'dst_ip', 'protocol',
                'src_port', 'dst_port', 'length', 'prediction'
            ])
            writer.writeheader()
            for flow in captured_data:
                writer.writerow(flow)
    return send_file(filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
