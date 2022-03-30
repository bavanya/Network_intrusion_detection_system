import pyshark
from  get_connection_status import get_connection_status
from get_network_service_at_dst import get_network_service_at_dst

# Read pcap file.
input_file = 'sniff.pcap'
captured_packets = pyshark.FileCapture(input_file)

# Collected packets into captured_packets (it behaves like list, can access contents using index).

# Take the packets into a dictionary raw_connections {key:value} 
# where key is the tcp stream number of a packet and value is the list of packets belonging to the tcp stream. 
raw_connections = {}
for packet in captured_packets:
    try:
      if(packet.tcp.stream not in raw_connections.keys()):
        raw_connections[packet.tcp.stream] = [packet] 
      else:
        packets_of_same_stream = raw_connections[packet.tcp.stream]
        packets_of_same_stream.append(packet)
    except AttributeError:
        continue

#print("no of keys:" + str(len(raw_connections)))
#print(raw_connections.keys())

# Got raw_connections dictionary.     
protocol_type = 1 #code for tcp is taken as 1.
for key, packet_list in raw_connections.items():
    src_bytes = 0
    dst_bytes = 0
    wrong_frag = 0   
    duration = int(float(packet_list[-1].tcp.time_relative))
    if(hasattr(packet_list[0], 'ipv6')):
        src_ip = packet_list[0].ipv6.src
        dst_ip = packet_list[0].ipv6.dst
    else:
        src_ip = packet_list[0].ip.src
        dst_ip = packet_list[0].ip.dst

    for packet in packet_list:
        #print("length of packet is: " + packet.length.size)
        if(hasattr(packet, 'ipv6')):
            if(src_ip == packet.ipv6.src):
                src_bytes += int(packet.length.size)
            else:
                dst_bytes += int(packet.length.size)
        else:
            if(src_ip == packet.ip.src):
                src_bytes += int(packet.length.size)
            else:
                dst_bytes += int(packet.length.size)

        if(packet.tcp.checksum_status != '2'):
            wrong_frag += 1
        
    #print("src bytes of connection no: " + str(key) + " is: " + str(src_bytes))
    #print("dst bytes of connection no: " + str(key) + " is: " + str(dst_bytes))
    service = get_network_service_at_dst(packet_list[0])
    status_flag = get_connection_status(packet_list)
