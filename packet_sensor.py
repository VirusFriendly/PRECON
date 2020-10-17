from protocols.parse import parse
from protocols.utils import list_to_host, list_to_num, WritePcap
from reporter import process_details
import dpkt
import time

def grab_packets(sniffer):
    ip_hdr = 14
    timestamp = 0
    ignorance = None

    for ts, pkt in sniffer:
        day = int(ts/86400)

        if day > timestamp:
            timestamp = day
            ignorance_filename = f"ai_log-{timestamp}.pcap"
            
            if ignorance is not None:
                ignorance.close()

            pcap_log = open(ignorance_filename, 'wb')
            ignorance = dpkt.pcap.Writer(pcap_log)

        if [pkt[12], pkt[13]] != [8, 0]:
            ignorance.writepkt(pkt, ts)
            continue

        ip_sz = (pkt[ip_hdr] - 0x40) * 4
        pkt_sz = list_to_num(pkt[ip_hdr + 2: ip_hdr + 4])

        if (
                len(pkt) != pkt_sz + 14 or 
                pkt[ip_hdr + 6] not in [0, 0x40] or 
                pkt[ip_hdr + 9] != 17
        ):
            ignorance.writepkt(pkt, ts)
            continue

        src_host = list_to_host(pkt[ip_hdr + 12:ip_hdr + 16])
        udp_hdr = ip_hdr + ip_sz

        svc_port = list_to_num(pkt[udp_hdr + 2: udp_hdr + 4])

        detail = dict()

        try:
            details = parse(pkt[udp_hdr:])
        except WritePcap:
            ignorance.writepkt(pkt, ts)

        if src_host != "0.0.0.0":
            if "Sources" not in details.keys():
                details["Sources"] = list()

            details["Sources"].append({"value": src_host})

        process_details(details)


