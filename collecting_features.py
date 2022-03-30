import pyshark

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

for key, packet_list in raw_connections.items():
    src_bytes = 0
    dst_bytes = 0
    wrong_frag = 0   

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
        
    #print("src bytes of connection no: " + str(key) + " is: " + str(src_bytes))
    #print("dst bytes of connection no: " + str(key) + " is: " + str(dst_bytes))
     
