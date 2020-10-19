from .utils import list_to_host, list_to_host6, list_to_num, WritePcap

PORT = 5353

#Multicast Domain Name Resolution
def parse_mdns_name(data, offset):
    name = list()
    pos = offset
    length = data[pos]

    while length != 0:
        if length < 0xc0:
            name.append(data[pos+1:pos+1+length])
            pos = pos+1+length

            if pos < len(data):
                length = data[pos]
            else:
                length = 0
        else:
            x, _ = parse_mdns_name(data, (data[pos] - 0xc0) * 256 + data[pos+1])
            name.append(x)
            pos = pos+1
            break

    return b'.'.join(name), pos+1


def parse_mdns_text(data, pkt):
    texts = list()
    pos = 0

    while pos < len(data):
        length = data[pos]

        if length < 0xc0:
            texts.append(data[pos+1:pos+1+length])
            pos = pos+1+length
        else:
            if pos + 1 > len(data):
                x, _ = parse_mdns_name(pkt, (data[pos] - 0xc0) * 256 + data[pos+1])
                texts.append(x)
                pos = pos + 2
            else:
                pos = pos + 1

    return texts


def parse(data):
    details={"Parser": "mDNS"}

    if data[2] != 0x84:
        # Not an authortive response
        return details

    detail_labels = ["Devices", "Extras", "Hostnames", "Interfaces", "Ports"]

    for detail_label in detail_labels:
        details[detail_label] = list()

    questions = list_to_num(data[4:6])
    answer_rr = list_to_num(data[6:8])
    authority_rr = list_to_num(data[8:10])
    additional_rr = list_to_num(data[10:12])
    ignore_rtypes = [12]

    if questions > 0:
        print(f"Has {questions} questions")
        raise WritePcap

    if authority_rr > 0:
        print(f"Has {authority_rr} authorities")
        raise WritePcap

    offset = 12

    for rr_entry in range(answer_rr + additional_rr):
        svc_type, offset = parse_mdns_name(data, offset)

        rtype = list_to_num(data[offset:offset+2])

        offset = offset + 2
        if rtype in ignore_rtypes:
            continue
        elif rtype == 1:  # Host Address RR
            offset = offset + 8
            details["Hostnames"].append({"value": str(svc_type)})
            details["Interfaces"].append({"value": str(list_to_host(data[offset:offset+4]))})
            offset = offset + 4
        #elif rtype == 12:  # PTR RR
        # I don't really see any added value in this information

            #offset = offset + 6

            #length = list_to_num(data[offset:offset + 2])
            #offset = offset + 2

            #if "_sub" in svc_type.split('.'):
            #    svc_type = '.'.join(svc_type.split('.')[svc_type.split('.').index("_sub") + 1:])

            #domain_name, unused = parse_mdns_name(data, offset)
            # register_svc(ip, svc_type, domain_name)
            #offset = offset + length
        elif rtype == 13:  # HINFO RR
            offset = offset + 6
            length = list_to_num(data[offset:offset + 2])
            offset = offset + 2

            cpu_length = data[offset]
            offset = offset + 1

            if cpu_length > length:
                print(f"Length mismatch: HINFO Length {length}, CPU Length {cpu_length}")
                raise WritePcap

            details["Devices"].append({"value": str(data[offset:offset + cpu_length])})
            offset = offset + cpu_length
            os_length = data[offset]

            if os_length + cpu_length + 2 > length:
                print(f"Length mismatch: HINFO Length {length}, CPU Length {cpu_length}, OS Length {os_length}")
                raise WritePcap

            details["Devices"].append({"value": str(data[offset:offset + os_length])})
            offset = offset + os_length
        elif rtype == 16:  # TXT RR
            offset = offset + 6

            length = list_to_num(data[offset:offset + 2])
            offset = offset + 2

            txt_port = ''
            txt_protocol = ''

            for txt in parse_mdns_text(data[offset:offset + length + 1], data):
                if b'=' in txt:
                    field, value = txt.split(b'=')
                else:
                    continue

                if value == b'':
                    continue

                if b"_googlecast" in svc_type.split(b'.'):
                    if field == b"fn":
                        details["Hostnames"].append({"value": str(value)})
                    elif field == b"md":
                        details["Devices"].append({"value": str(value)})
                    elif field == b"rs":
                        details["Extras"].append({"value": f"casting: {str(value)}"})
                    elif field == b"st" and value != b'0':
                        details["Extras"].append({"value": f"chromecast ST is {str(value)}"})
                    
                    if str(field) in ["fn", "md", "rs", "st", "id", "ic", "cd", "ve", "ca", "bs", "rm", "nf"]:
                        continue
                elif b"_amzn-wplay" in svc_type.split(b'.'):
                    if field == b"sp":
                        txt_port = value
                    elif field == b"tr":
                        txt_protocol = value

                    if txt_port != b'' and txt_protocol != b'':
                        details["Ports"].append({
                            "value": str(txt_port),
                            "protocol": str(txt_protocol),
                            "name": "amzn-wplay-sp"
                        })
                        txt_port = txt_protocol = ''

                    if str(field) in ["sp", "tr", 'a', 'f', "mv", "dpv", 's', 't', 'u', 'v']:
                        continue
                elif [i for i in [b"_printer", b"_pdl-datastream", b"_ipp", b"_ipps", b"_scanner", b"_uscan"] if i in svc_type.split(b'.')]:
                    if str(field) in ["ty", "usb_MDL", "usb_MFG", "product", "mdl", "mfg"]:
                        details["Devices"].append({"value": str(value)})
                    elif field == b"adminurl":
                        url_to_protocol(value)

                    #TODO: Alphabeticize this list
                    if str(field).upper() in ["TY", "USB_MDL", "USB_MFG", "PRODUCT", "MDL", "MFG", "PDL", "RP", "URF", "TLS", "UUID", "MAC",
                            "DUPLEX", "COLOR", "FAX", "SCAN", "TXTVERS", "PRIORITY", "QTOTAL", "TRANSPARENT", "PAPERMAX", "KIND",
                            "BINARY", "ADMINURL", "BUTTON", "FLATBED", "VERS", "REPRESENTATION", "RS", "CS", "IS"]:
                        continue
                elif b"_companion-link" in svc_type.split(b'.'):
                    if field == b"rpVr":
                        details["Extras"].append({"value": f"Companion Link Version: {str(value)}"})

                    if str(field) in ["rpVr", "rpBA"]:
                        continue
                elif b"_device-info" in svc_type.split(b'.'):
                    if b"osxvers" == field:
                        details["Devices"].append({"value": f"OS X version 10.{str(value)}"})
                    elif b"model" == field:
                        details["Devices"].append({'.'.join(value.split(b','))})

                    if str(field) in ["osxvers", "model"]:
                        continue
                elif b"_spotify-connect" in svc_type.split(b'.'):
                    if b"VERSION" == field:
                        details["Extras"].append({"value": f"Spotify-Connect Version {str(value)}"})

                    if field in ["VERSION", "CPATH"]:
                        continue
                elif b"_airplay" in svc_type.split(b'.'):
                    if b"srcvers" == field:
                        details["Extras"].append({"value": f"Airplay Version {str(value)}"})
                    elif b"model" == field:
                        details["Devices"].append({"value": str(value)})
                    
                    if str(field) in ["srcvers", "model", "deviceid", "features", "fv"]:
                        continue
                elif b"_raop" in svc_type.split(b'.'):
                    if b"vs" == field:
                        details["Extras"].append({"value": f"Airplay Version {str(value)}"})
                    elif b"am" == field:
                        details["Devices"].append({"value": str(value)})

                    if str(field) in ["vs", "am", "cn", "da", "ft", "fv", "md", "tp", "vn"]:
                        continue
                elif b"_atc" in svc_type.split(b'.'):
                    if b"libid" == field:
                        continue
                elif b"_runestone" in svc_type.split(b'.'):
                    if b"ip" == field:
                        details["Interfaces"].append({"value": str(value)})
                    elif b"port" == field:
                        details["Ports"].append({"value": str(value), "protocol": "udp", "name": "Runestone"})
                    
                    if field in ["ip", "port"]:
                        continue

                details["Extras"].append({"value": f"mdns {str(svc_type)} - {str(txt)}"})

            offset = offset + length
        elif rtype == 28:  # AAAA RR
            offset = offset + 8
            details["Interfaces"].append({"value": list_to_host6(data[offset:offset+16])})
            offset = offset + 16
        elif rtype == 33:  # Service RR
            offset = offset + 6

            length = list_to_num(data[offset:offset + 2])

            port = list_to_num(data[offset+6:offset+8])
            details["Ports"].append({
                "value": port,
                "protocol": svc_type.split(b'.')[-2][1:],
                "name": svc_type.split(b'.')[-3][1:]
            })

            offset = offset + 2 + length
        elif rtype in [41, 47]:  # OPT, NSEC
            offset = offset + 6

            length = list_to_num(data[offset:offset + 2])

            offset = offset + 2 + length
        else:
            print(f"New rtype {rtype} {svc_type})")
            print(f"Processed {rr_entry+1} records of {answer_rr} answers and {additional_rr} additional")
            raise WritePcap

    return details
