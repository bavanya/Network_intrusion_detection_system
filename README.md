# Network_intrusion_detection_system

## MVP plan:

Steps to perform intrusion detection at an end device on the network:
1. Capture traffic at the end device.
2. Run an intrusion detection system on the traffic captured in real-time.
3. If any abnormality is detected, alert the end user.

#### But how do we build an intrusion detection system?

We need pre existing benign and harmful network traffic data to build our system.

#### How do we accumulate such data?

We can do either of the two-
1. Simulate a network and generate mock data ourselves by running attacks in the simulated network.
2. Use open-sourced datasets:
  a. [KDDCup99 dataset](http://kdd.ics.uci.edu/databases/kddcup99/task.html)
  b. [AWID dataset](https://icsdweb.aegean.gr/awid/)

#### How do we capture incomming traffic at the end device?

Two possible ways-

1. We can use [tshark](https://www.wireshark.org/docs/man-pages/tshark.html) to extract specific headers of packets arriving at the end device and write them into a csv file or a database.
2. Use [tcpdump](https://www.tcpdump.org/) to capture the traffic and extract the required fields using [pyshark](https://github.com/KimiNewt/pyshark).

#### But this tshark should be running all the time the end device is on. How do we ensure this?

We can launch a screen session for this.

#### How to run the built intrusion detection system on the data captured into the file in real-time?

We write a single python script with the intrusion detection system performing inference on the last line of the csv file continuously.
