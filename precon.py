import dpkt
import pcap
import json
import os
import select
import sys
import traceback
import xmltodict
from datetime import datetime

reload(sys)
sys.setdefaultencoding('utf8')


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
    hostname = url.split('://')[1].split(':')[0].split('/')[0]

    if len(url.split(':')) > 2:
        port = int(url.split(':')[2].split('/')[0])

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
    if ip == '0.0.0.0':
        return

    if ip not in hosts.keys():
        traceback.print_stack()
        raise WritePcap

    friendlyname = ip

    if "Hostname" in hosts[ip].keys():
        friendlyname = hosts[ip]["Hostname"][0]

    if data is list:
        print "Error %s, %s -> %s" % (ip, keyword, repr(data))
        return

    if keyword not in hosts[ip].keys():
        hosts[ip][keyword] = list()

    if data not in hosts[ip][keyword]:
        hosts[ip][keyword].append(data)

        if len(data) > 0:
            print "Found %s information on %s: %s" % (keyword, friendlyname, data)


def register_dict(ip, keyword, key, value):
    if ip == '0.0.0.0':
        return

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
            findings = findings + keyword + ': '

            if len(hosts[ip][keyword]) > 1:
                findings = findings + "\n- " + "\n- ".join(hosts[ip][keyword]) + '\n'
            elif len(hosts[ip][keyword]) == 1:
                findings = findings + hosts[ip][keyword][0] + '\n'
            else:
                pass
                # print "Error: (%s) %s - %s" % (ip, keyword, hosts[ip][keyword])
        elif isinstance(hosts[ip][keyword], dict):
            findings = findings + keyword + ": "

            if len(hosts[ip][keyword].keys()) > 1:
                findings = findings + "\n- " + "\n- ".join([x + ": " + ' '.join(hosts[ip][keyword][x]) for x in hosts[ip][keyword].keys()]) + '\n'
            else:
                findings = findings + hosts[ip][keyword].keys()[0] + ": " + ' '.join(hosts[ip][keyword][hosts[ip][keyword].keys()[0]]) + '\n'

    return findings.encode("utf8")


def register_host(ip):
    newhost = False
    friendlyname = ip

    if ip not in hosts.keys():
        print "Found new host %s" % ip
        newhost = True
        hosts[ip] = dict()

    if "Hostname" in hosts[ip].keys():
        friendlyname = hosts[ip]["Hostname"][0]

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

        prevhour = str(int(hour) - 1)

        if len(prevhour) == 1:
            prevhour = '0' + prevhour

        if not newhost and prevhour not in hosts[ip]["Time"][day]:
            print "%s is active again" % friendlyname


def register_hostname(ip, hostname):
    if ip == '0.0.0.0':
        return

    if hostname == ip:
        return

    if "Interfaces" in hosts[ip].keys() and hostname in hosts[ip]["Interfaces"]:
        return

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


def register_user_agent(ip, user_agent):
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
        usage = ''

        if day in hosts[ip]["Time"].keys():
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

        time = time + usage + '\n'

    return time.encode()


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

        findings = findings + report_findings(host, "Device")
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


def parse_dropbox(ip, data):
    dropbox = json.loads(data)
    register_extras(ip, "Contains %d dropbox files" % len(dropbox["namespaces"]))
    register_port(ip, dropbox["port"], "tcp", "Dropbox LAN Sync")


def parse_dhcp(ip, data):
    dhcp_options = dict()

    if data[15*16 - 4:15*16] != "c\x82Sc":
        print repr(data[15*16 - 4:15*16])
        raise WritePcap

    if ip == "0.0.0.0":
        if list_to_host(data[12:16]) != "0.0.0.0":
            # ip = list_to_num(data[12:16]) Why did I choose list_to_num?
            ip = list_to_host(data[12:16])
            register_host(ip)

    if list_to_host(data[16:20]) != "0.0.0.0" or list_to_host(data[20:24]) != "0.0.0.0" or list_to_host(data[24:28]) != "0.0.0.0":
        print "Found interesting dhcp"
        raise WritePcap

    offset = 15*16

    while offset + 1 < len(data) and ord(data[offset]) != 255:
        option = ord(data[offset])
        length = ord(data[offset + 1])

        if offset + length > len(data):
            break

        offset = offset + 2

        if option in [1, 51, 53, 55, 57, 58, 59, 145]:  # DHCP Options we dont care about
            pass
        elif option == 3:
            if length == 4:
                dhcp_options["Router IP Address"] = list_to_host(data[offset:offset+length])
            else:
                print "DHCP Router address length = %d" % length
        elif option == 6:
            if length % 4 == 0:
                dhcp_options["DNS Servers"] = list()

                for x in xrange(int(length/4)):
                    dhcp_options["DNS Servers"].append(list_to_host(data[offset + (x*4): offset + (x*4) + 4]))
        elif option == 12:
            dhcp_options["Host Name"] = data[offset:offset + length]
        elif option == 15:
            dhcp_options["Domain Name"] = data[offset:offset + length]
        elif option == 50:
            if length == 4:
                dhcp_options["Requested IP Address"] = list_to_host(data[offset:offset+length])
            else:
                print "DHCP address length = %d" % length
                raise WritePcap
        elif option == 54:
            if length == 4:
                dhcp_options["DHCP Server Identifier"] = list_to_host(data[offset:offset+length])
            else:
                print "DHCP address length = %d" % length
                raise WritePcap
        elif option == 60:
            dhcp_options["Vendor Class Identifier"] = data[offset:offset + length]
        elif option == 61:
            if ord(data[offset]) == 0:
                dhcp_options["Client Identifier"] = dict()
                dhcp_options["Client Identifier"]["Type"] = ord(data[offset])
                dhcp_options["Client Identifier"]["Identifier"] = data[offset+1:offset+length]
            elif ord(data[offset]) in [0xff, 1]:
                pass
            else:
                print "DHCP: Strange Vendor Class Identifier: %d" % ord(data[offset])
                raise WritePcap
        elif option == 81:
            if ord(data[offset]) != 0 or ord(data[offset + 1]) != 0 or ord(data[offset + 2]) != 0:
                print "DHCP: Strange Client FQDN"
                raise WritePcap

            dhcp_options["Client FQDN"] = data[offset + 3:offset + length]
        else:
            print "DHCP Unknown option: %d" % option
            raise WritePcap

        offset = offset + length

    if ip == "0.0.0.0":
        if "Requested IP Address" in dhcp_options.keys() and dhcp_options["Requested IP Address"] != "0.0.0.0":
            ip = dhcp_options["Requested IP Address"]
        elif list_to_host(data[12:16]) != "0.0.0.0":
            ip = list_to_host(data[12:16])
        else:
            return

        register_host(ip)

        register_host(ip)
    elif "Requested IP Address" in dhcp_options.keys() and dhcp_options["Requested IP Address"] != ip:
        register_interface(ip, dhcp_options["Requested IP Address"])
    elif list_to_host(data[12:16]) != "0.0.0.0":
        register_interface(ip, list_to_host(data[12:16]))

    for keyword in dhcp_options.keys():
        if keyword == "Host Name":
            register_hostname(ip, dhcp_options[keyword])
        elif keyword == "Domain Name":
            register_hostname(ip, dhcp_options[keyword])
        elif keyword == "DNS Servers":
            for dns_server in dhcp_options[keyword]:
                register_host(dns_server)
                register_extras(dns_server, "DNS Server")
        elif keyword == "Router IP Address":
            register_host(dhcp_options[keyword])
            register_extras(dhcp_options[keyword], "Default Gateway")
        elif keyword == "DHCP Server Identifier":
            register_host(dhcp_options[keyword])
            register_extras(dhcp_options[keyword], "DHCP Server")
        elif keyword == "Vendor Class Identifier":
            register_device(ip, dhcp_options[keyword])
        elif keyword == "Client Identifer":
            register_extras(ip, "DHCP Client Identifier: " +dhcp_options[keyword]["Identifier"])
        elif keyword == "Client FQDN":
            register_hostname(ip, dhcp_options[keyword])
        elif keyword == "Requested IP Address":
            pass
        else:
            print "DHCP: Forgot to handle option %s" % keyword


def parse_llmnr(ip, data):
    if list_to_num(data[6:8]) > 0:
        raise WritePcap


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
            x, _ = parse_mdns_name(data, (ord(data[pos]) - 0xc0) * 256 + ord(data[pos+1]))
            name.append(x)
            pos = pos+1
            break

    return '.'.join(name), pos+1


def parse_mdns_text(data, pkt):
    texts = list()
    pos = 0

    while pos < len(data):
        length = ord(data[pos])

        if length < 0xc0:
            texts.append(data[pos+1:pos+1+length])
            pos = pos+1+length
        else:
            if pos + 1 > len(data):
                x, _ = parse_mdns_name(pkt, (ord(data[pos]) - 0xc0) * 256 + ord(data[pos+1]))
                texts.append(x)
                pos = pos + 2
                print ":)"
            else:
                pos = pos + 1

    return texts


def parse_mdns(ip, data):
    if ord(data[2]) != 0x84:
        #print "Not an authortive response"
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

    for rr_entry in xrange(answer_rr + additional_rr):
        svc_type, offset = parse_mdns_name(data, offset)

        rtype = list_to_num(data[offset:offset+2])

        offset = offset + 2

        if rtype == 1:  # Host Address RR
            offset = offset + 8
            register_hostname(ip, svc_type)

            if list_to_host(data[offset:offset+4]) != ip:
                register_interface(ip, list_to_host(data[offset:offset+4]))

            offset = offset + 4
        elif rtype == 12:  # PTR RR
            offset = offset + 6

            length = list_to_num(data[offset:offset + 2])
            offset = offset + 2

            if "_sub" in svc_type.split('.'):
                svc_type = '.'.join(svc_type.split('.')[svc_type.split('.').index("_sub") + 1:])

            domain_name, unused = parse_mdns_name(data, offset)
            # I don't really see any added value in this information
            # register_svc(ip, svc_type, domain_name)
            offset = offset + length
        elif rtype == 13:  # HINFO RR
            offset = offset + 6
            length = list_to_num(data[offset:offset + 2])
            offset = offset + 2

            cpu_length = ord(data[offset])
            offset = offset + 1

            if cpu_length > length:
                print "Length mismatch: HINFO Length %d, CPU Length %d" % (length, cpu_length)
                raise WritePcap

            register_device(ip, data[offset:offset + cpu_length])
            offset = offset + cpu_length
            os_length = ord(data[offset])

            if os_length + cpu_length + 2 > length:
                print "Length mismatch: HINFO Length %d, CPU Length %d, OS Length %d" % (length, cpu_length, os_length)
                raise WritePcap

            register_device(ip, data[offset:offset + os_length])
            offset = offset + os_length
        elif rtype == 16:  # TXT RR
            offset = offset + 6

            length = list_to_num(data[offset:offset + 2])
            offset = offset + 2

            friendly_name = ip
            txt_port = ''
            txt_protocol = ''

            for txt in parse_mdns_text(data[offset:offset + length + 1], data):
                if '=' in txt:
                    field, value = txt.split('=')
                else:
                    continue

                if value == '':
                    continue

                if "_googlecast" in svc_type.split('.'):
                    if field == "fn":
                        friendly_name = value
                        register_hostname(ip, value)
                    elif field == "md":
                        register_device(ip, value)
                    elif field == "rs":
                        print "%s is casting: %s" % (friendly_name, value)
                    elif field == "st":
                        if value != '0':
                            print "%s chromecast ST is: %s" % (friendly_name, value)
                    elif field in ["id", "ic", "cd", "ve", "ca", "bs", "rm", "nf"]:
                        pass
                    else:
                        register_extras(ip, "%s - %s" % (svc_type, txt))
                elif "_amzn-wplay" in svc_type.split('.'):
                    if field in ['a', 'f', "mv", "dpv", 's', 't', 'u', 'v']:
                        pass
                    elif field == "sp":
                        txt_port = value
                    elif field == "tr":
                        txt_protocol = value
                    else:
                        register_extras(ip, "%s - %s" % (svc_type, txt))

                    if txt_port != '' and txt_protocol != '':
                        register_port(ip, txt_port, txt_protocol, "amzn-wplay-sp")
                elif [i for i in ["_printer", "_pdl-datastream", "_ipp", "_ipps"] if i in svc_type.split('.')]:
                    if field in ["ty", "usb_MDL", "usb_MFG", "product"]:
                        register_device(ip, value)
                    elif field in ["pdl", "rp", "URF", "TLS", "UUID", "mac", "Duplex", "Color", "Fax", "Scan",
                                   "txtvers", "priority", "qtotal", "Transparent", "Binary"]:
                        pass
                    elif field == "adminurl":
                        url_to_protocol(value)
                    else:
                        register_extras(ip, "%s - %s" % (svc_type, txt))
                elif "_companion-link" in svc_type.split('.'):
                    if field == "rpVr":
                        register_extras(ip, "Companion Link Version: %s" % value)
                    elif field == "rpBA":
                        pass
                    else:
                        register_extras(ip, "%s - %s" % (svc_type, txt))
                elif "_device-info" in svc_type.split('.'):
                    if "osxvers" == field:
                        register_device(ip, "OS X version 10.%s" % value)
                    elif "model" == field:
                        register_device(ip, '.'.join(value.split(',')))
                    else:
                        register_extras(ip, "%s - %s" % (svc_type, txt))
                elif "_spotify-connect" in svc_type.split('.'):
                    if "VERSION" == field:
                        register_extras(ip, "Spotify-Connect Version %s" % value)
                    elif field in ["CPATH"]:
                        pass
                    else:
                        register_extras(ip, "%s - %s" % (svc_type, txt))
                elif "_airplay" in svc_type.split('.'):
                    if "srcvers" == field:
                        register_extras(ip, "Airplay Version %s" % value)
                    elif "model" == field:
                        register_device(ip, value)
                    elif field in ["deviceid", "features", "fv"]:
                        pass
                    else:
                        register_extras(ip, "%s - %s" % (svc_type, txt))
                elif "_raop" in svc_type.split('.'):
                    if "vs" == field:
                        register_extras(ip, "Airplay Version %s" % value)
                    elif "am" == field:
                        register_device(ip, value)
                    elif field in ["cn", "da", "ft", "fv", "md", "tp", "vn"]:
                        pass
                    else:
                        register_extras(ip, "%s - %s" % (svc_type, txt))
                elif "_atc" in svc_type.split('.'):
                    if "libid" == field:
                        pass
                    else:
                        register_extras(ip, "%s - %s" % (svc_type, txt))
                else:
                    register_extras(ip, "%s - %s" % (svc_type, txt))

            offset = offset + length
        elif rtype == 28:  # AAAA RR
            offset = offset + 8
            register_interface(ip, list_to_host6(data[offset:offset+16]))
            offset = offset + 16
        elif rtype == 33:  # Service RR
            offset = offset + 6

            length = list_to_num(data[offset:offset + 2])

            port = list_to_num(data[offset+6:offset+8])
            register_port(ip, port, svc_type.split('.')[-2][1:], svc_type.split('.')[-3][1:])

            offset = offset + 2 + length
        elif rtype in [41, 47]:  # OPT, NSEC
            offset = offset + 6

            length = list_to_num(data[offset:offset + 2])

            offset = offset + 2 + length
        else:
            print "New rtype %d (%s, %s)" % (rtype, ip, svc_type)
            print "Processed %d records of %d answers and %d additional" % (rr_entry + 1, answer_rr, additional_rr)
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

            register_user_agent(ip, user_agent)
        elif field[0].upper() == "X-SONOS-SESSIONSECONDS":
            pass
        elif field[0].upper()[:2] == "X-":
            register_extras(ip, '='.join(field))
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
    register_extras(tun_client)

    if "endpoints" not in hosts[ip].keys():
        hosts[ip]["endpoints"] = list()

    if tun_server not in hosts[ip]["endpoints"]:
        print "Discovered new Teredo Server: %s" % tun_server
        hosts[ip]["endpoints"].append(tun_server)


def parse_wsd(ip, data):
    doc = xmltodict.parse(data)

    # OrderedDict(
    #     [
    #         (u'soap:Envelope', OrderedDict(
    #             [
    #                 (u'@xmlns:soap', u'http://www.w3.org/2003/05/soap-envelope'),
    #                 (u'@xmlns:wsa', u'http://schemas.xmlsoap.org/ws/2004/08/addressing'),
    #                 (u'@xmlns:wsd', u'http://schemas.xmlsoap.org/ws/2005/04/discovery'),
    #                 (u'soap:Header', OrderedDict(
    #                     [
    #                         (u'wsa:To', u'urn:schemas-xmlsoap-org:ws:2005:04:discovery'),
    #                         (u'wsa:Action', u'http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve'),
    #                         (u'wsa:MessageID', u'urn:uuid:bc5cb458-8a6f-4424-853d-31dbbd241457')
    #                     ]
    #                 )),
    #                 (u'soap:Body', OrderedDict(
    #                     [
    #                         (u'wsd:Resolve', OrderedDict(
    #                             [
    #                                 (u'wsa:EndpointReference', OrderedDict(
    #                                     [
    #                                         (u'wsa:Address', u'urn:uuid:00000000-0000-1000-8000-f80d60224c06')
    #                                     ]
    #                                 ))
    #                             ]
    #                         ))
    #                     ]
    #                 ))
    #             ]
    #         ))
    #     ]
    # )

    if 'soap:Envelope' in doc.keys() and 'soap:Body' in doc['soap:Envelope'].keys():
        if len(doc['soap:Envelope']['soap:Body'].keys()) == 1 and doc['soap:Envelope']['soap:Body'].keys()[0] in ['wsd:Resolve', 'wsd:Probe']:
            return

    print repr(doc)
    raise WritePcap


class WritePcap(Exception):
    pass


ip_hdr = 14

hosts = dict()  # stores all the recon data. Currently no way to retrieve data
date_range = list()

if os.path.isfile("data.json"):
    with open("data.json", 'r') as data_file:
        hosts = json.loads(data_file.read())

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

            with open("report.txt", 'w') as report_file:
                report_file.write(report())

            print "\nFindings written to report.txt\n"

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

        if src_host != "0.0.0.0":
            register_host(src_host)

        udp_hdr = ip_hdr + ip_sz

        svc_port = list_to_num(pkt[udp_hdr + 2: udp_hdr + 4])

        try:
            if svc_port == 67:
                # DHCP requests
                parse_dhcp(src_host, pkt[udp_hdr + 8:])
            elif svc_port == 68:
                raise WritePcap
                # Probably ignore these DHCP replies
            elif svc_port == 1124:
                # boring printer protocol
                raise WritePcap
            elif svc_port == 1228:
                parse_bnet(src_host, pkt[udp_hdr + 8:])
            elif svc_port == 1900:
                parse_ssdp(src_host, pkt[udp_hdr + 8:])
            elif svc_port == 3289:
                # boring printer protocol
                raise WritePcap
            elif svc_port == 3544:
                # Teredo IPv6 over UDP tunneling
                parse_teredo(src_host, pkt[udp_hdr + 8:])
            elif svc_port == 3702:
                # WS-Discovery - Generally looking for WSD enabled (HP) printers
                parse_wsd(src_host, pkt[udp_hdr + 8:])
            elif svc_port == 5353:
                parse_mdns(src_host, pkt[udp_hdr + 8:])
            elif svc_port == 5355:
                # Link Local Name Resolution, but unlike mDNS responses are sent unicast
                parse_llmnr(src_host, pkt[udp_hdr + 8:])
            elif svc_port == 7765:
                raise WritePcap
                # WonderShare MobileGo.
                # Used to manage android phone, not really interesting except to retrieve operating system and computer name
            elif svc_port == 17500:
                # Dropbox LAN Sync Discovery Protocol
                parse_dropbox(src_host, pkt[udp_hdr + 8:])
            elif svc_port == 48000:
                # ???
                raise WritePcap
            elif svc_port == 57621:
                # Spotify UDP
                raise WritePcap
            else:  # Artificial Ignorance Catch
                # print "%s:%d" % (src_host, svc_port)
                raise WritePcap
        except WritePcap:
            # print "!",
            ignorance.writepkt(pkt, ts)
except KeyboardInterrupt:
    with open("data.json", 'w') as data_file:
        data_file.write(json.dumps(hosts))

    with open("report.txt", 'w') as report_file:
        report_file.write(report())
