import time
import numpy as np
from collections import defaultdict
from predict import expected_features

class FlowTracker:
    def __init__(self):
        self.flows = {}

    def get_flow_key(self, packet):
        return (
            packet['src_ip'], packet['dst_ip'],
            packet.get('src_port'), packet.get('dst_port'),
            packet['protocol']
        )

    def update_flow(self, packet):
        now = time.time()
        key = self.get_flow_key(packet)

        if key not in self.flows:
            self.flows[key] = {
                'timestamps': [],
                'lengths': [],
                'first_seen': now,
                'last_seen': now,
                'fwd_packets': 0,
                'bwd_packets': 0,
                'fwd_bytes': 0,
                'bwd_bytes': 0,
                'src_ip': packet['src_ip'],
                'dst_ip': packet['dst_ip'],
                'fwd_flags': defaultdict(int),
                'bwd_flags': defaultdict(int),
                'fwd_header_len': 0,
                'bwd_header_len': 0,
            }

        flow = self.flows[key]
        flow['timestamps'].append(now)
        flow['lengths'].append(packet['length'])
        flow['last_seen'] = now

        if packet['src_ip'] == flow['src_ip']:
            flow['fwd_packets'] += 1
            flow['fwd_bytes'] += packet['length']
            flow['fwd_header_len'] += 20  # approx TCP/IP header
        else:
            flow['bwd_packets'] += 1
            flow['bwd_bytes'] += packet['length']
            flow['bwd_header_len'] += 20

        # If the flow has enough data, extract features
        if flow['fwd_packets'] + flow['bwd_packets'] >= 5:
            return self.extract_features(flow, packet)
        return None

    def extract_features(self, flow, packet):
        duration = flow['last_seen'] - flow['first_seen']
        lengths = np.array(flow['lengths'])
        timestamps = np.array(flow['timestamps'])
        iats = np.diff(timestamps)

        features = {
            'Destination Port': packet.get('dst_port') or 0,
            'Flow Duration': duration,
            'Total Fwd Packets': flow['fwd_packets'],
            'Total Backward Packets': flow['bwd_packets'],
            'Total Length of Fwd Packets': flow['fwd_bytes'],
            'Total Length of Bwd Packets': flow['bwd_bytes'],
            'Fwd Packet Length Max': lengths.max(),
            'Fwd Packet Length Min': lengths.min(),
            'Fwd Packet Length Mean': lengths.mean(),
            'Fwd Packet Length Std': lengths.std(),
            'Bwd Packet Length Max': lengths.max(),
            'Bwd Packet Length Min': lengths.min(),
            'Bwd Packet Length Mean': lengths.mean(),
            'Bwd Packet Length Std': lengths.std(),
            'Flow Bytes/s': (flow['fwd_bytes'] + flow['bwd_bytes']) / duration if duration > 0 else 0,
            'Flow Packets/s': (flow['fwd_packets'] + flow['bwd_packets']) / duration if duration > 0 else 0,
            'Flow IAT Mean': iats.mean() if len(iats) else 0,
            'Flow IAT Std': iats.std() if len(iats) else 0,
            'Flow IAT Max': iats.max() if len(iats) else 0,
            'Flow IAT Min': iats.min() if len(iats) else 0,
            'Fwd IAT Total': duration if flow['fwd_packets'] > 0 else 0,
            'Fwd IAT Mean': duration / flow['fwd_packets'] if flow['fwd_packets'] else 0,
            'Fwd IAT Std': 0,
            'Fwd IAT Max': 0,
            'Fwd IAT Min': 0,
            'Bwd IAT Total': duration if flow['bwd_packets'] > 0 else 0,
            'Bwd IAT Mean': duration / flow['bwd_packets'] if flow['bwd_packets'] else 0,
            'Bwd IAT Std': 0,
            'Bwd IAT Max': 0,
            'Bwd IAT Min': 0,
            'Fwd PSH Flags': flow['fwd_flags'].get('PSH', 0),
            'Bwd PSH Flags': flow['bwd_flags'].get('PSH', 0),
            'Fwd URG Flags': flow['fwd_flags'].get('URG', 0),
            'Bwd URG Flags': flow['bwd_flags'].get('URG', 0),
            'Fwd Header Length': flow['fwd_header_len'],
            'Bwd Header Length': flow['bwd_header_len'],
            'Fwd Packets/s': flow['fwd_packets'] / duration if duration > 0 else 0,
            'Bwd Packets/s': flow['bwd_packets'] / duration if duration > 0 else 0,
            'Min Packet Length': lengths.min(),
            'Max Packet Length': lengths.max(),
            'Packet Length Mean': lengths.mean(),
            'Packet Length Std': lengths.std(),
            'Packet Length Variance': lengths.var(),
            'FIN Flag Count': 0,
            'SYN Flag Count': 0,
            'RST Flag Count': 0,
            'PSH Flag Count': 0,
            'ACK Flag Count': 0,
            'URG Flag Count': 0,
            'CWE Flag Count': 0,
            'ECE Flag Count': 0,
            'Down/Up Ratio': flow['bwd_packets'] / flow['fwd_packets'] if flow['fwd_packets'] else 0,
            'Average Packet Size': lengths.mean(),
            'Avg Fwd Segment Size': flow['fwd_bytes'] / flow['fwd_packets'] if flow['fwd_packets'] else 0,
            'Avg Bwd Segment Size': flow['bwd_bytes'] / flow['bwd_packets'] if flow['bwd_packets'] else 0,
            'Fwd Header Length.1': flow['fwd_header_len'],
            'Fwd Avg Bytes/Bulk': 0,
            'Fwd Avg Packets/Bulk': 0,
            'Fwd Avg Bulk Rate': 0,
            'Bwd Avg Bytes/Bulk': 0,
            'Bwd Avg Packets/Bulk': 0,
            'Bwd Avg Bulk Rate': 0,
            'Subflow Fwd Packets': flow['fwd_packets'],
            'Subflow Fwd Bytes': flow['fwd_bytes'],
            'Subflow Bwd Packets': flow['bwd_packets'],
            'Subflow Bwd Bytes': flow['bwd_bytes'],
            'Init_Win_bytes_forward': 0,
            'Init_Win_bytes_backward': 0,
            'act_data_pkt_fwd': flow['fwd_packets'],
            'min_seg_size_forward': 0,
            'Active Mean': 0,
            'Active Std': 0,
            'Active Max': 0,
            'Active Min': 0,
            'Idle Mean': 0,
            'Idle Std': 0,
            'Idle Max': 0,
            'Idle Min': 0
        }

        # Fill in missing features if any
        for field in expected_features:
            if field not in features:
                features[field] = 0

        return features
