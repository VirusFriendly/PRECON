import dpkt
import pcap
import os


def list_to_num(x):
    total = 0

    for digit in x:
        total = total * 256 + ord(digit)

    return total


def list_to_host(x):
    return '.'.join([str(ord(y)) for y in x])


def parse_bnet(ip, data):
    fields = data.split(',')

    if len(fields) != 10:
        raise WritePcap

    # uid = fields[3]
    account = fields[4] + '#' + fields[5]

    if 'tags' not in hosts[ip].keys():
        hosts[ip]['tags'] = list()

    if account not in hosts[ip]['tags']:
        print "Discovered Battle Net Account for %s, %s" % (ip, account)
        hosts[ip]['tags'].append(account)

    # The following lines are for assisting in reverse engineering the protocol

    if fields[0] != "72057594037927936":
        print "New value discovered for Battlenet Field #1, %s" % fields[0]
        raise WritePcap

    # fields[1] is some user/session dependant number between 968472 and 307445411

    if fields[2] != "144115193835963207":
        print "New value discovered for Battlenet Field #3, %s" % fields[2]
        raise WritePcap

    # fields[3] is likely the UID
    # fields[4] is user name
    # fields[5] is unique username number

    if fields[6] != "721408":
        print "New value discovered for Battlenet Field #7, %s" % fields[6]
        raise WritePcap

    if fields[7] != "us.actual.battle.net":
        print "New value discovered for Battlenet Field #8, %s" % fields[7]
        raise WritePcap

    if fields[8] not in ['0', '1']:
        # This field is often 0, but sometimes 1
        # Might be a busy state?
        print "New value discovered for Battlenet Field #9, %s" % fields[8]
        raise WritePcap

    # fields[9] is a rather peculiar value whose MSB changes more than the LSB


def parse_mdns_name(data, offset):
    name = list()
    length = 1
    pos = offset

    while length != 0:
        length = data[pos]
        name.append(data[pos+1:pos+1+length])

    return '.'.join(name), offset+1


def parse_mdns(ip, data):
    print '.',

    if ord(data[3]) != 0x84:
        # Not an authortive response packet
        raise WritePcap

    offset = 12

    while True:
        if ord(data[offset]) < 0xc0:
            name, offset = parse_mdns_name(data, 12)
            print name
        else:
            offset = offset + 2

        rtype = list_to_num(data[offset:offset+2])

        offset = offset + 2

        if rtype == 12:
            offset = offset + 6
        elif rtype == 16:
            offset = offset + 8
        elif rtype == 33:
            offset = offset + 8
        else:
            print "New rtype"
            raise WritePcap

        raise WritePcap  # Still working on this dissector

        length = ord(data[offset])

        while length != 0:
            if length < 0xc0:
                offset = offset + 1
                print data[offset:offset+length]
                offset = offset + length
            else:
                offset = offset + 2


def parse_ssdp(ip, data):
    url = ''
    proto = "unk"
    port = None
    server = ''
    device = list()
    user_agent = ''
    extras = list()

    newline = False

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

        elif field[0].upper() == "SERVER":
            if field[1][:17] == "Microsoft-Windows":
                win_ver = field[1][18:21]

                if win_ver == "5.0":
                    device.append("Windows 2000")
                elif win_ver == "5.1":
                    device.append("Windows XP")
                elif win_ver == "5.2":
                    device.append("Windows XP Professional x64")
                elif win_ver == "6.0":
                    device.append("Windows Vista")
                elif win_ver == "6.1":
                    device.append("Windows 7")
                elif win_ver == "6.2":
                    device.append("Windows 8")
                elif win_ver == "6.3":
                    device.append("Windows 8.1")
                elif field[1][18:22] == "10.0":
                    device.append("Windows 10")
                else:
                    print "Unknown windows version %s" % field[1]
                    raise WritePcap
            server = field[1]
        elif field[0] == "NT":
            if "device:" in field[1]:
                device.append(field[1].split("device:")[1].split(':')[0])
        elif field[0].upper() == "USER-AGENT":
            user_agent = field[1]

            if user_agent[:13] == "Google Chrome":
                device.append(user_agent.split(' ')[2])
                user_agent = ' '.join(user_agent.split(' ')[:2])
        elif field[0].upper()[:2] == "X-":
            extras.append(field)
        elif field[0].upper() == "CONSOLENAME.XBOX.COM":
            device.append(field[1])
        else:
            print "Unknown SSRP Field: %s:%s" % (field[0], field[1:])
            raise WritePcap

    # parsing done, now time to store the results

    if url != '':
        if "URLs" not in hosts[ip].keys():
            hosts[ip]["URLs"] = list()

        if url not in hosts[ip]["URLs"]:
            print "Found new URL %s: %s" % (ip, url)
            newline = True
            hosts[ip]["URLs"].append(url)

    if port is not None:
        if "Ports" not in hosts[ip].keys():
            hosts[ip]["Ports"] = dict()

        if str(port)+'/'+proto not in hosts[ip]["Ports"].keys():
            print "Found new Port %s: %s %s" % (ip, str(port) + '/' + proto, server)
            newline = True
            hosts[ip]["Ports"][str(port)+'/'+proto] = server

    if len(device) > 0:
        if "Device" not in hosts[ip].keys():
            hosts[ip]["Device"] = list()

        for devtype in device:
            if devtype not in hosts[ip]["Device"]:
                print "Found new Device Type %s: %s" % (ip, devtype)
                newline = True
                hosts[ip]["Device"].append(devtype)

    if user_agent != '':
        if "UserAgent" not in hosts[ip].keys():
            hosts[ip]["UserAgent"] = list()

        if user_agent not in hosts[ip]["UserAgent"]:
            print "Found new User Agent: %s, %s" % (ip, user_agent)
            newline = True
            hosts[ip]["UserAgent"].append(user_agent)

    for extra in extras:
        if "Extras" not in hosts[ip].keys():
            hosts[ip]["Extras"] = list()

        if extra not in hosts[ip]["Extras"]:
            print "Found new SSRP Extra: %s, %s" % (ip, extra)
            newline = True
            hosts[ip]["Extras"].append(extra)

    if newline:  # Done printing updates
        print ''


class WritePcap(Exception):
    pass


ip_hdr = 14

hosts = dict()  # stores all the recon data. Currently no way to retrieve data


# Setup Artificial Ignorance. Not sure what that is? Google Artificial Ignorance Marcus Ranum
ignorance_filename = 'ai_log.pcap'

if os.path.isfile(ignorance_filename):
    os.remove(ignorance_filename)

pcap_log = file(ignorance_filename, 'wb')
ignorance = dpkt.pcap.Writer(pcap_log)

sniffer = pcap.pcap()
sniffer.setfilter("udp and ip multicast")

print "ready.."

for ts, pkt in sniffer:
    if [ord(pkt[12]), ord(pkt[13])] != [8, 0]:
        print "Not an IP packet"
        ignorance.writepkt(pkt, ts)
        continue

    ip_sz = (ord(pkt[ip_hdr]) - 0x40) * 4
    pkt_sz = list_to_num(pkt[ip_hdr + 2: ip_hdr + 4])

    if len(pkt) != pkt_sz + 14:
        print "Size mismatch (reported %d, actual %d)" % (pkt_sz + 14, len(pkt))
        ignorance.writepkt(pkt, ts)
        continue

    if ord(pkt[ip_hdr + 6]) not in [0, 0x40]:
        print "Fragmented %d" % ord(pkt[ip_hdr + 6])
        ignorance.writepkt(pkt, ts)
        continue

    if ord(pkt[ip_hdr + 9]) != 17:
        print "Not a UDP packet"
        ignorance.writepkt(pkt, ts)
        continue

    src_host = list_to_host(pkt[ip_hdr + 12:ip_hdr + 16])

    if src_host not in hosts.keys():
        print "Found new host %s" % src_host
        hosts[src_host] = dict()

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
            print "%s:%d" % (src_host, svc_port)
            raise WritePcap
    except WritePcap:
        print "!",
        ignorance.writepkt(pkt, ts)

