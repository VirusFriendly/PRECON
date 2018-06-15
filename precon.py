import pcap


def list_to_num(x):
    total = 0

    for digit in x:
        total = total * 256 + ord(digit)

    return total


def list_to_host(x):
    return '.'.join([str(ord(y)) for y in x])


def parse_SSDP(ip, data):
    url = ''
    proto = "unk"
    port = None
    server = ''
    device = ''
    user_agent = ''
    extras = list()

    newline = False

    ssrp = data.splitlines()
    method = ssrp[0].split(' ')[0]

    if method not in ["NOTIFY", "M-SEARCH"]:
        print "SSRP: Unknown method: %s" % method

    for line in ssrp[1:]:
        field = line.split(': ')

        if field[0].upper() in ["HOST", "MAN", "CACHE-CONTROL", "NTS", "USN", "MX", "ST", 'OPT', '01-NLS', '']:
            continue

        if field[0].upper() == "LOCATION":
            url = field[1]

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

        elif field[0].upper() == "SERVER":
            server = field[1]
        elif field[0] == "NT":
            if "device:" in field[1]:
                device = field[1].split("device:")[1].split(':')[0]
        elif field[0].upper() == "USER-AGENT":
            user_agent = field[1]

            if user_agent[:13] == "Google Chrome":
                device = user_agent.split(' ')[2]
                user_agent = ' '.join(user_agent.split(' ')[:2])
        elif field[0].upper()[:2] == "X-":
            extras.append(field)
        else:
            print "Unknown SSRP Field: %s:%s" % (field[0], field[1:])

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
            print "Found new Port %s: %s" % (ip, str(port) + '/' + proto)
            newline = True
            hosts[ip]["Ports"][str(port)+'/'+proto] = server

    if device != '':
        if "Device" not in hosts[ip].keys():
            hosts[ip]["Device"] = list()

        if device not in hosts[ip]["Device"]:
            print "Found new Device Type %s: %s" % (ip, device)
            newline = True
            hosts[ip]["Device"].append(device)

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


ip_hdr = 14

hosts = dict()  # stores all the recon data. Currently no way to retrieve data

sniffer = pcap.pcap()
sniffer.setfilter("udp and ip multicast")

for ts, pkt in sniffer:
    if [ord(pkt[12]), ord(pkt[13])] != [8, 0]:
        print "Not an IP packet"
        continue

    ip_sz = (ord(pkt[ip_hdr]) - 0x40) * 4
    pkt_sz = list_to_num(pkt[ip_hdr + 2: ip_hdr + 4])

    if len(pkt) != pkt_sz + 14:
        print "Size mismatch (reported %d, actual %d)" % (pkt_sz + 14, len(pkt))
        continue

    if ord(pkt[ip_hdr + 6]) not in [0, 0x40]:
        print "Fragmented %d" % ord(pkt[ip_hdr + 6])

    if ord(pkt[ip_hdr + 9]) != 17:
        print "Not a UDP packet"
        continue

    src_host = list_to_host(pkt[ip_hdr + 12:ip_hdr + 16])

    if src_host not in hosts.keys():
        print "Found new host %s" % src_host
        hosts[src_host] = dict()

    udp_hdr = ip_hdr + ip_sz

    svc_port = list_to_num(pkt[udp_hdr + 2: udp_hdr + 4])

    if svc_port == 1900:
        parse_SSDP(src_host, pkt[udp_hdr + 8:])
    elif svc_port == 7765:
        continue
        # WonderShare MobileGo. Used to manage android phone, not really interesting except to retrieve operating system
    else:  # Artificial Ignorance Catch
        print "%s:%d" % (src_host, svc_port)
