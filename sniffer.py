import argparse
from scapy.all import sniff, TCP, IP, conf
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

def packet_handler(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        ts = format_ts(pkt.time)
        src = f"{pkt[IP].src}:{pkt[TCP].sport}"
        dst = f"{pkt[IP].dst}:{pkt[TCP].dport}"
        flags = get_tcp_flags(pkt)
        print(f"{ts} TCP {src} -> {dst} Flags: {flags}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (e.g., eth0)")
    args = parser.parse_args()

    iface = args.interface or conf.iface
    print(f"[*] Sniffing on interface: {iface}")
    sniff(iface=iface, prn=packet_handler, filter="tcp", store=0)

if __name__ == "__main__":
    main()
