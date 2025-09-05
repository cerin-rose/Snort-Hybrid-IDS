import pandas as pd
import numpy as np

def safe_flag_parse(x):
    try:
        return int(str(x), 0)
    except:
        return 0

def build_flows_from_packets(df):
    df['frame.time_epoch'] = pd.to_numeric(df['frame.time_epoch'], errors='coerce')
    df['frame.len'] = pd.to_numeric(df['frame.len'], errors='coerce')
    df = df.dropna(subset=['frame.time_epoch', 'frame.len'])

    df['flow_id'] = (df['ip.src'] + '-' + df['ip.dst'] + '-' +
                     df['ip.proto'].astype(str) + '-' +
                     df['tcp.srcport'].fillna(df['udp.srcport']).astype(str) + '-' +
                     df['tcp.dstport'].fillna(df['udp.dstport']).astype(str))

    flows = []

    for flow_id, group in df.groupby('flow_id'):
        group = group.sort_values('frame.time_epoch')
        duration = group['frame.time_epoch'].max() - group['frame.time_epoch'].min()
        pkt_lengths = group['frame.len'].values
        times = group['frame.time_epoch'].values
        iats = np.diff(times) if len(times) > 1 else [0]

        # Dummy forward/backward split for now (improvement possible if TCP flags are available)
        fwd_pkts = group.iloc[:len(group)//2]
        bwd_pkts = group.iloc[len(group)//2:]

        flow = {
            'Flow Duration': duration,
            'Total Fwd Packets': len(group),
            'Total Length of Fwd Packets': pkt_lengths.sum(),
            'Fwd Packet Length Max': pkt_lengths.max(),
            'Fwd Packet Length Min': pkt_lengths.min(),
            'Fwd Packet Length Mean': pkt_lengths.mean(),
            'Fwd Packet Length Std': pkt_lengths.std(),
            'Bwd Packet Length Max': bwd_pkts['frame.len'].max() if not bwd_pkts.empty else 0,
            'Bwd Packet Length Min': bwd_pkts['frame.len'].min() if not bwd_pkts.empty else 0,
            'Bwd Packet Length Mean': bwd_pkts['frame.len'].mean() if not bwd_pkts.empty else 0,
            'Bwd Packet Length Std': bwd_pkts['frame.len'].std() if not bwd_pkts.empty else 0,
            'Flow Bytes/s': pkt_lengths.sum() / duration if duration > 0 else 0,
            'Flow Packets/s': len(group) / duration if duration > 0 else 0,
            'Flow IAT Mean': np.mean(iats),
            'Flow IAT Std': np.std(iats),
            'Flow IAT Max': np.max(iats),
            'Flow IAT Min': np.min(iats),

            # Forward IATs (simplified)
            'Fwd IAT Total': np.sum(iats),
            'Fwd IAT Mean': np.mean(iats),
            'Fwd IAT Std': np.std(iats),
            'Fwd IAT Max': np.max(iats),
            'Fwd IAT Min': np.min(iats),

            # Backward IATs (dummy)
            'Bwd IAT Total': 0,
            'Bwd IAT Mean': 0,
            'Bwd IAT Std': 0,
            'Bwd IAT Max': 0,
            'Bwd IAT Min': 0,

            'Fwd Header Length': 0,
            'Bwd Header Length': 0,
            'Fwd Packets/s': len(fwd_pkts) / duration if duration > 0 else 0,
            'Bwd Packets/s': len(bwd_pkts) / duration if duration > 0 else 0,
            'Min Packet Length': pkt_lengths.min(),
            'Max Packet Length': pkt_lengths.max(),
            'Packet Length Mean': pkt_lengths.mean(),
            'Packet Length Std': pkt_lengths.std(),
            'Packet Length Variance': np.var(pkt_lengths),
            'FIN Flag Count': group['tcp.flags'].apply(lambda x: safe_flag_parse(x) & 0x01).sum() if 'tcp.flags' in group else 0,
            'PSH Flag Count': 0,
            'ACK Flag Count': group['tcp.flags.ack'].sum() if 'tcp.flags.ack' in group else 0,
            'Average Packet Size': pkt_lengths.mean(),
            'Subflow Fwd Bytes': fwd_pkts['frame.len'].sum() if not fwd_pkts.empty else 0,
            'Init_Win_bytes_forward': 0,
            'Init_Win_bytes_backward': 0,
            'act_data_pkt_fwd': 0,
            'min_seg_size_forward': 0,
            'Active Mean': 0,
            'Active Max': 0,
            'Active Min': 0,
            'Idle Mean': 0,
            'Idle Max': 0,
            'Idle Min': 0,
            'Destination Port': pd.to_numeric(group['tcp.dstport'].fillna(group['udp.dstport']).iloc[0], errors='coerce')
        }

        flows.append(flow)

    return pd.DataFrame(flows)
