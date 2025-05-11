import argparse
from scapy.all import sniff, TCP, IP, conf, Raw
from datetime import datetime

def format_ts(ts):
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S.%f")

def get_tcp_flags(pkt):
    flags = pkt[TCP].flags
    flag_names = []
    if flags & 0x02: flag_names.append("SYN")
    if flags & 0x10: flag_names.append("ACK")
    if flags & 0x01: flag_names.append("FIN")
    if flags & 0x04: flag_names.append("RST")
    if flags & 0x08: flag_names.append("PSH")
    if flags & 0x20: flag_names.append("URG")
    return '+'.join(flag_names) if flag_names else str(flags)

def packet_handler_tcp(pkt):
    enable_http = True
    enable_tls = True
    if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw):
        payload = pkt[Raw].load
        try:
            if payload.startswith(b"GET") or payload.startswith(b"POST"):
                if enable_http:
                    text = payload.decode(errors="ignore")
                    ts = format_ts(pkt.time)
                    src = f"{pkt[IP].src}:{pkt[TCP].sport}"
                    dst = f"{pkt[IP].dst}:{pkt[TCP].dport}"
                    method = text.split()[0]
                    uri = text.split()[1]
                    print(f"{ts} HTTP {src} -> {dst} {method} {uri}")
            elif payload[0] == 0x16 and payload[5] == 0x01:
                if enable_tls:
                    ts = format_ts(pkt.time)
                    src = f"{pkt[IP].src}:{pkt[TCP].sport}"
                    dst = f"{pkt[IP].dst}:{pkt[TCP].dport}"
                    print(f"{ts} TLS {src} -> {dst} Client Hello")
        except Exception:
            print("Error decoding payload")
            pass
        

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (e.g., eth0)")
    args = parser.parse_args()

    iface = args.interface or conf.iface
    print(f"[*] Sniffing on interface: {iface}")
    sniff(iface=iface, prn=packet_handler_tcp, filter="tcp", store=0)

if __name__ == "__main__":
    main()
