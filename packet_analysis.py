import netifaces
import pyshark
from scapy.all import sniff, wrpcap
 
 
def find_all_networks():
    interfaces = netifaces.interfaces()
    interfaces_list = []
 
    for interface in interfaces:
        interface_info = {
            'name': interface,
            'ip': netifaces.ifaddresses(interface).get(netifaces.AF_INET, [{'addr': 'No IP'}])[0]['addr'],
        }
        interfaces_list.append(interface_info)
 
    return interfaces_list
 
 
def packet_capturing(packet):
    global captured_packets
 
    captured_packets.append(packet)
 
    if len(captured_packets) >= 10:
        wrpcap("packets.pcap", captured_packets)
        print("Packets captured and saved successfully.")
 
 
def packet_analyzer():
    with open("packet_info.txt", "w") as file:
        capture = pyshark.FileCapture("packets.pcap")
 
        for packet in capture:
            if 'IP' in packet:
                ip_layer = packet['IP']
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                protocol = ip_layer.proto
 
                file.write(f"Source IP: {src_ip}\n")
                file.write(f"Destination IP: {dst_ip}\n")
                file.write(f"Protocol: {protocol}\n")
 
                if 'TCP' in packet:
                    tcp_layer = packet['TCP']
                    src_port = tcp_layer.srcport
                    dst_port = tcp_layer.dstport
                    flags = tcp_layer.flags
 
                    file.write(f"Source Port: {src_port}\n")
                    file.write(f"Destination Port: {dst_port}\n")
                    file.write(f"Flags: {flags}\n")
 
                elif 'UDP' in packet:
                    udp_layer = packet['UDP']
                    src_port = udp_layer.srcport
                    dst_port = udp_layer.dstport
 
                    file.write(f"Source Port: {src_port}\n")
                    file.write(f"Destination Port: {dst_port}\n")
 
                elif 'ICMP' in packet:
                    icmp_layer = packet['ICMP']
                    icmp_type = icmp_layer.type
                    icmp_code = icmp_layer.code
 
                    file.write(f"ICMP Type: {icmp_type}\n")
                    file.write(f"ICMP Code: {icmp_code}\n")
 
        print("Packet information written to packet_info.txt successfully.")
 
 
if __name__ == "__main__":
    networks = find_all_networks()
 
    if len(networks) > 0:
        print("Networks Found:")
        for network in networks:
            print(network)
 
        select_iface = input("Enter the interface: ")
        select_filtering = input("Enter the filter (tcp/udp): ")
 
        captured_packets = []
 
        try:
            sniff(iface=select_iface, filter=select_filtering, prn=packet_capturing, count=10)
            packet_analyzer()
        except Exception as e:
            print(f"An error occurred: {str(e)}")
    else:
        print("No Network Found.")
