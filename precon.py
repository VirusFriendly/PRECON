import pcap
from packet_sensor import grab_packets

# if default operation, load listen_sensor
# if reading from pcap, open pcap and pass to packet_sensor
# if research mode, start sniffer and pass to packet_sensor
sniffer = pcap.pcap()
sniffer.setfilter("udp and ip multicast")

print("running..")
grab_packets(sniffer)
