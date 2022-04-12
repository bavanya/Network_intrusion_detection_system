echo "capturing traffic ..."

# Capture 400 packets related to only tcp connections and writes them to a pcap file.
sudo tcpdump -c 100000 -i wlan0mon -w data_related_files/sniff.pcap

echo "collecting packet info to file ..."
tcpdump -x -r data_related_files/sniff.pcap > packet_info.txt

echo "collected successfully!!"
echo "preparing data for inference ..."

# Generate inference dataset.
python3 collect_features.py

echo "data ready for inference"
