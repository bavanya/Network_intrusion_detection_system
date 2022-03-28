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
2. Use open-sourced datasets.

#### How do we capture incomming traffic at the end device?

We can use tshark to extract specific headers of packets arriving at the end device and write them into a csv file or a database.

#### But this tshark should be running all the time the end device is on. How do we ensure this?

We can launch a screen session for this.

#### How to run the built intrusion detection system on the data captured into the file in real-time?

We write a single python script with the intrusion detection system performing inference on the last line of the csv file continuously.
