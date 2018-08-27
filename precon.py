import dpkt
from datetime import datetime

import pcap
import os
import select
import sys


def list_to_num(x):
    total = 0

    for digit in x:
        total = total * 256 + ord(digit)

    return total


def list_to_host(x):
    return '.'.join([str(ord(y)) for y in x])


def list_to_host6(x):
    assert len(x) == 16

    return ':'.join([''.join([hex(ord(x[i])).split('x')[-1], hex(ord(x[i+1])).split('x')[-1]]) for i in xrange(0, 16, 2)])


def url_to_protocol(url):
    port = 0
    hostname = url.split(':')[1:]

    if len(url.split(':')) > 2:
        port = ord(url.explit(':')[2].split('/')[0])

    if url[:4] == "http":
        proto = "tcp"

        if port == 0:  # deduce port number
            if url[4] == 's':
                port = 443
            else:
                port = 80
    else:
        print "Unknown Protocol: %s" % url
        raise WritePcap

    return hostname, port, proto


def register_list(ip, keyword, data):
    if keyword not in hosts[ip].keys():
        hosts[ip][keyword] = list()

    if len(data) > 0 and data not in hosts[ip][keyword]:
        hosts[ip][keyword].append(data)
        print "Found %s information on %s: %s" % (keyword, ip, data)


def register_dict(ip, keyword, key, value):
    if keyword not in hosts[ip].keys():
        hosts[ip][keyword] = dict()

    if key not in hosts[ip][keyword].keys():
        hosts[ip][keyword][key] = list()

    if len(value) > 0 and value not in hosts[ip][keyword][key]:
        print "Found %s information on %s: %s => %s" % (keyword, ip, key, value)
        hosts[ip][keyword][key].append(value)


def report_findings(ip, keyword):
    findings = ''

    if keyword in hosts[ip].keys():
        if isinstance(hosts[ip][keyword], list):
            findings = findings + keyword

            if len(hosts[ip][keyword]) > 1:
                findings = findings + '\n'

                for data in hosts[ip][keyword]:
                    findings = findings + "- %s" % data + '\n'
        elif isinstance(hosts[ip][keyword], dict):
            findings = findings + keyword + ":"

            if len(hosts[ip][keyword].keys()) > 1:
                findings = findings + '\n'

            for port in hosts[ip][keyword].keys():
                for value in hosts[ip][keyword][port]:
                    findings = findings + "- %s: %s" % (port, value) + '\n'

    return findings


def register_host(ip):
    if ip not in hosts.keys():
        print "Found new host %s" % ip
        hosts[ip] = dict()

    # insert time here
    now = datetime.now()
    day = now.strftime("%B%d")
    hour = now.strftime("%H")

    if day not in date_range:
        date_range.append(day)

    if "Time" not in hosts[ip].keys():
        hosts[ip]["Time"] = dict()

    if day not in hosts[ip]["Time"]:
        hosts[ip]["Time"][day] = list()

    if hour not in hosts[ip]["Time"][day]:
        hosts[ip]["Time"][day].append(hour)


def register_hostname(ip, hostname):
    register_list(ip, "Hostname", hostname)


def register_interface(ip, interface):
    register_list(ip, "Interfaces", interface)


def register_device(ip, device):
    register_list(ip, "Device", device)


def register_port(ip, port, proto, server):
    register_dict(ip, "Ports", str(port) + '/' + proto, server)


def register_svc(ip, svc, details):
    register_dict(ip, "Services", svc, details)


def register_tag(ip, system, account):
    register_dict(ip, "Tags", system, account)


def register_extras(ip, extra):
    register_list(ip, "Extras", extra)


def register_user_ageent(ip, user_agent):
    register_list(ip, "User-Agent", user_agent)


def report_timeline(ip):
    global date_range

    #if "Time" in hosts[ip].keys() and len(date_range) > 1:
    timeline = ''

    for hour in xrange(0, 24):
        if len(str(hour)) > 1:
            timeline = timeline + " " + str(hour)
        else:
            timeline = timeline + "  " + str(hour)

    timeline_padding = 0

    for day in date_range:
        if len(str(day)) > timeline_padding:
            timeline_padding = len(str(day))

    time = ' ' + ' ' * timeline_padding + timeline + '\n'

    for day in date_range:
        if day in hosts[ip]["Time"].keys():
            usage = ""
            time = time + " " + day + ' ' + "-" * (timeline_padding - len(str(day))) + ' '

            for hour in xrange(0, 24):
                time_str = str(hour)

                if len(time_str) == 1:
                    time_str = '0' + time_str

                if time_str in hosts[ip]["Time"][day]:
                    mark = 'X'
                else:
                    mark = ' '

                usage = usage + mark + '  '

        usage = usage + '\n'

    return time + usage


def report():
    findings = ''

    for host in hosts.keys():
        findings = findings + host + '\n'

        findings = findings + report_timeline(host)
        findings = findings + report_findings(host, "Hostname")

        keyword = "Interfaces"

        if keyword in hosts[host].keys():
            if host not in hosts[host][keyword]:
                hosts[host][keyword].append(host)

            findings = findings + report_findings(host, keyword)

        findings = findings + report_findings(host, "Ports")
        findings = findings + report_findings(host, "Services")
        findings = findings + report_findings(host, "Tags")
        findings = findings + report_findings(host, "Extras")
        findings = findings + report_findings(host, "User-Agent")

        findings = findings + '\n'

    return findings


def parse_bnet(ip, data):
    fields = data.split(',')

    if len(fields) != 10:
        raise WritePcap

    # uid = fields[3]
    account = fields[4] + '#' + fields[5]
    register_tag(ip, "BattleNet", account)

    # The following lines are for assisting in reverse engineering the protocol

    # fields[0] is unknown
    # fields[1] is some user/session dependant number between 968472 and 307445411
    # fields[2] is unknown
    # fields[3] is likely the UID
    # fields[4] is user name
    # fields[5] is unique username number
    # fields[6] is unknown
    # fields[7] is Region
    # fields[8] is unknown
    # fields[9] is a rather peculiar value whose MSB changes more than the LSB


def parse_mdns_name(data, offset):
    name = list()
    pos = offset
    length = ord(data[pos])

    while length != 0:
        if length < 0xc0:
            name.append(data[pos+1:pos+1+length])
            pos = pos+1+length

            if pos < len(data):
                length = ord(data[pos])
            else:
                length = 0
        else:
            x, _ = parse_mdns_name(data, ord(data[pos+1]))
            name.append(x)
            pos = pos+2
            length = 0

    return '.'.join(name), pos+1


def parse_mdns_text(data):
    texts = list()
    length = ord(data[0])
    pos = 0

    while pos < len(data):
        if length < 0xc0:
            texts.append(data[pos+1:pos+1+length])
            pos = pos+1+length

            if pos < len(data):
                length = ord(data[pos])
        else:
            print "Text field contains dns compression"
            raise WritePcap

    return texts


def parse_mdns(ip, data):
    if ord(data[2]) != 0x84:
        # Not an authortive response packet
        # print repr(data[0:5]),
        return

    questions = list_to_num(data[4:6])
    answer_rr = list_to_num(data[6:8])
    authority_rr = list_to_num(data[8:10])
    additional_rr = list_to_num(data[10:12])

    if questions > 0:
        print "Has %d questions" % questions
        raise WritePcap

    if authority_rr > 0:
        print "Has %d authorities" % authority_rr
        raise WritePcap

    offset = 12

    for _ in xrange(answer_rr):
        svc_type, offset = parse_mdns_name(data, offset)

        rtype = list_to_num(data[offset:offset+2])

        offset = offset + 2

        if rtype == 1:  # Host Address RR
            offset = offset + 8
            register_hostname(ip, svc_type)

            if list_to_host(data[offset:offset+4]) != ip:
                register_interface(ip, list_to_host(data[offset:offset+4]))
        elif rtype == 12:  # PTR RR
            offset = offset + 6

            length = list_to_num(data[offset:offset + 2])
            offset = offset + 2

            domain_name, _ = parse_mdns_name(data, offset)
            register_svc(ip, svc_type, domain_name)
            offset = offset + length

            if svc_type.split('.')[0] == "_googlecast":
                if "Extras" in hosts[ip].keys():
                    for extra in hosts[ip]["Extras"]:
                        if extra.split('=')[0] == "md":
                            register_device(ip, extra.split('=')[1])
                        elif extra.split('=')[0] == "fn":
                            register_hostname(ip, extra.split('=')[1])
            elif svc_type.split('.')[0] == "_ipp":
                if "Extras" in hosts[ip].keys():
                    for extra in hosts[ip]["Extras"]:
                        if extra.split('=')[0] == "ty":
                            register_device(ip, extra.split('=')[1])
                        elif extra.split('=')[0] == "product":
                            register_device(ip, extra.split('=')[1])
                        elif extra.split('=')[0] == "adminurl":
                            hostname, port, protocol = url_to_protocol(extra.split('=')[1])
                            register_port(ip, port, protocol, '')

                            if hostname != ip:
                                register_hostname(ip, hostname)

        elif rtype == 16:  # TXT RR
            offset = offset + 6

            length = list_to_num(data[offset:offset + 2])
            offset = offset + 2

            for txt in parse_mdns_text(data[offset:offset+length+1]):
                register_extras(ip, txt)

            offset = offset + length
        elif rtype == 33:  # Service RR
            offset = offset + 6

            length = list_to_num(data[offset:offset + 2])

            port = list_to_num(data[offset+6:offset+8])
            register_port(ip, port, svc_type.split('.')[-2][1:], svc_type.split('.')[-3][1:])

            offset = offset + length
        else:
            print "New rtype %d" % rtype
            raise WritePcap

    raise WritePcap


def parse_ssdp(ip, data):
    proto = "unk"
    port = None

    ssrp = data.splitlines()
    method = ssrp[0].split(' ')[0]

    if method not in ["NOTIFY", "M-SEARCH"]:
        print "SSRP: Unknown method: %s" % method
        raise WritePcap

    for line in ssrp[1:]:
        if ": " in line:
            field = line.split(': ')
        else:
            field = line.split(':')

        if field[0].upper() in ["HOST", "MAN", "CACHE-CONTROL", "NTS", "USN", "MX", "ST", 'OPT', '01-NLS', 'DATE', '']:
            continue

        if field[0].upper() == "LOCATION":
            if ": " in line:
                url = field[1]
            else:
                url = ':'.join(field[1:])

            if url[:4] == "http":
                proto = "tcp"

            if ip in line:
                if len(line.split(ip)) == 2 and line.split(ip)[1][0] == ':':
                    port = line.split(ip)[1].split('/')[0][1:]
                else:
                    print "SSRP IP split = %s" % line.split(ip)

            if port is None:
                if url[:4] == "http":
                    if url[4] == 's':
                        port = 443
                    else:
                        port = 80
                else:
                    print "SSRP Unknown Protocol: %s" % url
                    raise WritePcap

            register_port(ip, port, proto, "")

        elif field[0].upper() == "SERVER":
            if field[1][:17] == "Microsoft-Windows":
                win_ver = field[1][18:21]

                if win_ver == "5.0":
                    register_device(ip, "Windows 2000")
                elif win_ver == "5.1":
                    register_device(ip, "Windows XP")
                elif win_ver == "5.2":
                    register_device(ip, "Windows XP Professional x64")
                elif win_ver == "6.0":
                    register_device(ip, "Windows Vista")
                elif win_ver == "6.1":
                    register_device(ip, "Windows 7")
                elif win_ver == "6.2":
                    register_device(ip, "Windows 8")
                elif win_ver == "6.3":
                    register_device(ip, "Windows 8.1")
                elif field[1][18:22] == "10.0":
                    register_device(ip, "Windows 10")
                else:
                    print "Unknown windows version %s" % field[1]
                    raise WritePcap

            register_device(ip, field[1])
        elif field[0] == "NT":
            if "device:" in field[1]:
                register_device(ip, field[1].split("device:")[1].split(':')[0])
        elif field[0].upper() == "USER-AGENT":
            user_agent = field[1]

            if user_agent[:13] == "Google Chrome":
                register_device(ip, user_agent.split(' ')[2])
                user_agent = ' '.join(user_agent.split(' ')[:2])

            register_user_ageent(ip, user_agent)
        elif field[0].upper() == "X-SONOS-SESSIONSECONDS":
            pass
        elif field[0].upper()[:2] == "X-":
            register_extras(ip, field)
        elif field[0].upper() == "CONSOLENAME.XBOX.COM":
            register_device(ip, field[1])
        else:
            print "Unknown SSRP Field: %s:%s" % (field[0], field[1:])
            raise WritePcap


def parse_teredo(ip, data):
    if 0x70 < ord(data[0]) or ord(data[0]) < 0x60:
        print "Teredo is version %d" % ord(data[0])
        raise WritePcap

    if list_to_num(data[1:5]) != 0:
        print "Teredo has a flow label"
        raise WritePcap

    if ord(data[6]) != 59:
        print "Teredo has a next header"
        raise WritePcap

    if data[24:40] != '\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01':
        print "Teredo not a multicast packet: %s" % repr(data[24:40])
        raise WritePcap

    ipv6 = list_to_host6(data[8:24])  # Todo: support ipv6 in the future
    tun_server = list_to_host(data[12:16])
    tun_client_port = list_to_num([chr(0xff - ord(x)) for x in data[18:20]])
    tun_client = list_to_host([chr(0xff - ord(x)) for x in data[20:24]])

    if tun_client != ip and tun_client not in hosts.keys():
        print "Discovered external ip: %s" % tun_client
        register_host(tun_client)

    register_port(tun_client, tun_client_port, 'udp', '')

    if "endpoints" not in hosts[ip].keys():
        hosts[ip]["endpoints"] = list()

    if tun_server not in hosts[ip]["endpoints"]:
        print "Discovered new Teredo Server: %s" % tun_server
        hosts[ip]["endpoints"].append(tun_server)


class WritePcap(Exception):
    pass


ip_hdr = 14

hosts = dict()  # stores all the recon data. Currently no way to retrieve data
date_range = list()


# Setup Artificial Ignorance. Not sure what that is? Google Artificial Ignorance Marcus Ranum
ignorance_filename = 'ai_log.pcap'

if os.path.isfile(ignorance_filename):
    os.remove(ignorance_filename)

pcap_log = file(ignorance_filename, 'wb')
ignorance = dpkt.pcap.Writer(pcap_log)

sniffer = pcap.pcap()
sniffer.setfilter("udp and ip multicast")

print "ready.."

try:
    for ts, pkt in sniffer:
        r, w, e = select.select([sys.stdin], [], [], 0)  # detect if enter was pressed
        if len(r) > 0:
            sys.stdin.readline()  # clear the return
            print report()

            with open("report.txt", 'w') as report_file:
                report_file.write(report())

        if [ord(pkt[12]), ord(pkt[13])] != [8, 0]:
            # print "Not an IP packet"
            ignorance.writepkt(pkt, ts)
            continue

        ip_sz = (ord(pkt[ip_hdr]) - 0x40) * 4
        pkt_sz = list_to_num(pkt[ip_hdr + 2: ip_hdr + 4])

        if len(pkt) != pkt_sz + 14:
            # print "Size mismatch (reported %d, actual %d)" % (pkt_sz + 14, len(pkt))
            ignorance.writepkt(pkt, ts)
            continue

        if ord(pkt[ip_hdr + 6]) not in [0, 0x40]:
            # print "Fragmented %d" % ord(pkt[ip_hdr + 6])
            ignorance.writepkt(pkt, ts)
            continue

        if ord(pkt[ip_hdr + 9]) != 17:
            # print "Not a UDP packet"
            ignorance.writepkt(pkt, ts)
            continue

        src_host = list_to_host(pkt[ip_hdr + 12:ip_hdr + 16])

        register_host(src_host)

        udp_hdr = ip_hdr + ip_sz

        svc_port = list_to_num(pkt[udp_hdr + 2: udp_hdr + 4])

        try:
            if svc_port in [67, 68]:
                raise WritePcap
                # I'll get around to this soon
            elif svc_port == 1228:
                parse_bnet(src_host, pkt[udp_hdr + 8:])
            elif svc_port == 1900:
                parse_ssdp(src_host, pkt[udp_hdr + 8:])
            elif svc_port == 3544:
                # Teredo IPv6 over UDP tunneling
                parse_teredo(src_host, pkt[udp_hdr + 8:])
            elif svc_port == 3702:
                # WS-Discovery - Generally looking for WSD enabled (HP) printers
                raise WritePcap
            elif svc_port == 5353:
                parse_mdns(src_host, pkt[udp_hdr + 8:])
            elif svc_port == 5355:
                raise WritePcap
                # Link Local Name Resolution, but unlike mDNS responses are sent unicast
            elif svc_port == 7765:
                raise WritePcap
                # WonderShare MobileGo.
                # Used to manage android phone, not really interesting except to retrieve operating system and computer name
            else:  # Artificial Ignorance Catch
                # print "%s:%d" % (src_host, svc_port)
                raise WritePcap
        except WritePcap:
            # print "!",
            ignorance.writepkt(pkt, ts)
except KeyboardInterrupt:
    with open("report.txt", 'w') as report_file:
        report_file.write(report())
