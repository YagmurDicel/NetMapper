import scapy.all as scapy

def scan_network(ip_range):
    scapy.conf.L3socket6
    arp_request = scapy.ARP(pdst=ip_range)
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp_request

    result = scapy.srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

if __name__ == "__main__":
    ip_range = "192.168.1.1/24"
    devices = scan_network(ip_range)
    print("Ağdaki Cihazlar:")
    print("IP" + " "*18+"MAC")
    for device in devices:
        print(f"{device['ip']:16}    {device['mac']}")

print(f"Toplam {len(devices)} cihaz bulundu.")
for device in devices:
    print(f"IP: {device['ip']}, MAC: {device['mac']}")
