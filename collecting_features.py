import pyshark

# Read pcap file.
input_file = 'sniff.pcap'
captured_packets = pyshark.FileCapture(input_file)

# Take the packets into a dictionary raw_connections {key:value} 
# where key is the tcp stream number of a packet and value is the list of packets belonging to the tcp stream. 
raw_connections = {}
for packet in capture:
    try:
      if packet.tcp.stream not in raw_connections.keys():
        raw_connections[packet.tcp.stream] = [packet] 
      else:
        packets_of_same_stream = raw_connections[packet.tcp.stream]
        packets_of_same_stream.append(packet)
    except AttributeError:
        continue
