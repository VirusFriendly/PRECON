from .utils import list_to_host, WritePcap

SERVER_PORT = 67
CLIENT_PORT = 68

def parse(data):
    details = dict()
    option = "option"
    detail = "detail"
    context = "context"
    value = "value"
    label = "label"

    dhcp_options = {
            "3": {option: "Router IP Address", detail: "Other Hosts", context: "Default Gateway"},
            "6": {option: "DNS Servers", detail: "Other Hosts", context: "DNS Server"},
            "12": {option: "Host Name", detail: "Hostnames"},
            "15": {option: "Domain Name", detail: "Hostnames"},
            "50": {option: "Requested IP Address", detail: "Interfaces"},
            "54": {option: "Server Identifier", detail: "Other Hosts", context: "DHCP Server"},
            "60": {option: "Vendor Class Identifier", detail: "Devices"},
            "61": {option: "Client Identifier", detail: "Extras"},
            "81": {option: "Client FQDN", detail: "Hostnames"}
    }

    ignore_options = ['1', '51', '53', '55', '57', '58', '59', '145'] # DHCP Options we dont care about
    simple_options = ['12', '15', '60']
    len4_options = ['3', '50', '54']

    for dhcp_option in dhcp_options.keys():
        if dhcp_options[dhcp_option][detail] not in details.keys():
            details[dhcp_options[dhcp_option][detail]] = list()

    #TODO: Comment why I'm watching this value
    if data[15*16 - 4:15*16] != b"c\x82Sc":
        print(data[15*16 - 4:15*16])
        raise WritePcap

    # ip = list_to_num(data[12:16]) Why did I choose list_to_num? 
    ip = list_to_host(data[12:16])

    if ip != "0.0.0.0":
        details["Interfaces"].append({"value": ip})

    #TODO: break this out better
    if list_to_host(data[16:20]) != "0.0.0.0" or list_to_host(data[20:24]) != "0.0.0.0" or list_to_host(data[24:28]) != "0.0.0.0":
        print("Found interesting dhcp")
        raise WritePcap

    offset = 15*16

    while offset + 1 < len(data) and data[offset] != 255:
        dhcp_option = str(data[offset])
        length = data[offset + 1]

        if offset + length > len(data):
            print("[!] Length extends past packet data")
            break

        dhcp_value = data[offset+2:offset+2+length]
        offset = offset + 2 + length

        if dhcp_option in ignore_options:
            continue
        elif dhcp_option in simple_options:
            detail_value = {value: dhcp_value}

            if context in dhcp_options[dhcp_option].keys():
                detail_value[context] = dhcp_options[dhcp_option][context]

            details[dhcp_options[dhcp_option][detail]].append(detail_value)
        elif dhcp_option in len4_options:
            if length != 4:  #TODO: Support IPv6 somehow
                print(f"[!] DHCP {len4_options[options]} = {length}")
                raise WritePcap

            detail_value = {value: list_to_host(dhcp_value)}

            if context in dhcp_options[dhcp_option].keys():
                detail_value[context] = dhcp_options[dhcp_option][context]

            details[dhcp_options[dhcp_option][detail]].append(detail_value)
        elif option in dhcp_options.keys():
            if dhcp_options[dhcp_option][option] == "DNS Servers":
                if length % 4 != 0: #TODO: Support IPv6 somehow
                    print(f"[!] DHCP DNS Servers length = {length}")
                    raise WritePcap

                for x in range(0, int(length), 4):
                    detail_value = {value: list_to_host(dhcp_value), context: dhcp_options[dhcp_option][context]}
                    details[dhcp_options[dhcp_option][detail]].append(detail_value)
            elif dhcp_options[dhcp_option][option] == "Client Identifier":
                if dhcp_value[0] == 0:
                    details[dhcp_options[dhcp_option][detail]].append({value: f"DHCP Client Identifier, Type: {dhcp_value[0]}, Identifier {dhcp_value[1:]}"})
                elif data[offset] in [0xff, 1]:
                    continue
                else:
                    print(f"[!] DHCP: Strange Client Identifier: {dhcp_value[0]}")
                    raise WritePcap
            elif option == '81':
                if not (dhcp_value[0] == dhcp_value[1] == dhcp_value[2] == 0):
                    print("[!] DHCP Strange Client FQDN")
                    raise WritePcap

                details[dhcp_options[dhcp_option][detail]].append(dhcp_value)
        else:
            print(f"[!] DHCP Unknown option: {option}")
            raise WritePcap

    return details

