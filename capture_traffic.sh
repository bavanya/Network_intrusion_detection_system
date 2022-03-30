#Captures 400 packets related to only tcp connections and writes them to a pcap file.
sudo tcpdump tcp -c 400 -i wlo1 -w sniff.pcap
