from scapy.all import sniff

def pkt(pkt):
    print(pkt.summary())

sniff(iface="wlan0", prn=pkt, count=10)
