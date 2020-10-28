from scapy.all import *
import pyshark

def dns_count():
    counter = 0
    for packet in PcapReader('sample.pcap'):
        if packet.haslayer(DNS):
            counter = counter + 1
    print("Total DNS packets: "+str(counter))

def print_dns_resp():
    from scapy.all import *
    counter = 0
    for packet in PcapReader('sample.pcap'):
        if packet.haslayer(DNSRR):
            if isinstance(packet.an, DNSRR):
                counter = counter +1
                print(counter, packet.an.rrname)

def dns_list():
    count = 0
    unique_list = []
    capture = pyshark.FileCapture('sample.pcap', display_filter='dns.flags.response == 1')
    for packet in capture:
        if packet.ip.src not in unique_list:
            unique_list.append(packet.ip.src)
           
    print(unique_list)

def print_domain():
    response_counter = 0
    for packet in PcapReader('sample.pcap'):
        if packet.haslayer(DNSRR):
            response_counter = response_counter + 1
     
    print("Total DNS Response packets: "+str(response_counter))   

def list_5():
    packets = rdpcap('sample.pcap')
    # iterate through every packet
    for packet in packets[0:5]:
        print(packet)
        print("\n")

def print_user():
    count = 0
    capture = pyshark.FileCapture('sample.pcap', display_filter='http contains user')
    for packet in capture:
        count = count + 1
    print(count)

def sites_visited():
    count = 0
    url_list = []
    capture = pyshark.FileCapture('sample.pcap', display_filter='ip.src==192.168.252.128 && http && http.request.method=="GET"')
    for packet in capture:
        host_name = packet.http.host
        host_name = ".".join(host_name.split('.')[-2:])
        if host_name not in url_list:
            url_list.append(host_name)
     
    print(url_list)

def print_pcap():
    # Read the packets from the pcap file
    packets = rdpcap('sample.pcap')

    for packet in packets:
        packet_amount = len(packets)
        
    print(len (packets)) 