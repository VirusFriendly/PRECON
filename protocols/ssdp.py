from .utils import WritePcap

#Simple Service Discovery Protocol
PORT = 1900

def parse(data):
    details = {"Devices": list(), "Extras": list(), "Ports": list(), "Softwares": list()}

    proto = "unk"
    port = None

    ssrp = data.splitlines()
    method = ssrp[0].split(b' ')[0]

    if method not in [b"NOTIFY", b"M-SEARCH"]:
        print(f"[!] SSRP: Unknown method: {method}")
        raise WritePcap

    for line in ssrp[1:]:
        if b": " in line:
            field = line.split(b': ')
        else:
            field = line.split(b':')

        if field[0].upper() in [b"HOST", b"MAN", b"CACHE-CONTROL", b"NTS", b"USN", b"MX", b"ST", b'OPT', b'01-NLS', b'DATE', b'']:
            continue

        if field[0].upper() == b"LOCATION":
            if b": " in line:
                url = field[1]
            else:
                url = b':'.join(field[1:])

            if url[:4] == b"http":
                proto = b"tcp"

            #TODO: extract hostname/ip from field
            #if ip in line:
            #    if len(line.split(ip)) == 2 and line.split(ip)[1][0] == b':':
            #        port = line.split(ip)[1].split(b'/')[0][1:]
            #    else:
            #        print(f"[*] SSRP IP split = {line.split(ip)}")

            if port is None:
                if url[:4] == b"http":
                    if url[4] == b's':
                        port = 443
                    else:
                        port = 80
                else:
                    print(f"[!] SSRP Unknown Protocol: {url}")
                    raise WritePcap

            #TODO: confirm that its an SSDP port that's being advertised
            details["Ports"].append({"value": port, "protocol": proto, "name": "SSDP"})

        elif field[0].upper() == b"SERVER":
            if field[1][:17] == b"Microsoft-Windows":
                win_vers = {
                        b"5.0": "Windows 2000",
                        b"5.1": "Windows XP",
                        b"5.2": "Windows XP Professional x64",
                        b"6.0": "Windows Vista",
                        b"6.1": "Windows 7",
                        b"6.2": "Windows 8",
                        b"6.3": "Windows 8.1",
                        b"10.0": "Windows 10"
                        }
                win_ver = field[1][18:21]

                if b"10." == win_ver:
                    win_ver = field[1][18:22]

                if win_ver not in win_vers.keys():
                    print(f"Unknown windows version {field[1]}")
                    raise WritePcap

                details["Devices"].append({"value": win_vers[win_ver]})

            details["Devices"].append({"value": field[1]})
        elif field[0] == b"NT":
            if b"device:" in field[1]:
                details["Devices"].append({"value": field[1].split(b"device:")[1].split(b':')[0]})
        elif field[0].upper() == b"USER-AGENT":
            user_agent = field[1]

            if user_agent[:13] == b"Google Chrome":
                details["Devices"].append({"value": user_agent.split(b' ')[2]})
                user_agent = b' '.join(user_agent.split(b' ')[:2])

            details["Softwares"].append({"value": user_agent})
        elif field[0].upper() == b"X-SONOS-SESSIONSECONDS":
            details["Devices"].append({"value": "Sonos"})
        elif field[0].upper()[:2] == b"X-":
            details["Extras"].append({"value": '='.join(field)})
        elif field[0].upper() == b"CONSOLENAME.XBOX.COM":
            details["Devices"].append({"value": field[1]})
        elif field[0].upper() == b"DEVICE-GROUP.ROKU.COM":
            details["Extras"].append({"value": f"Roku Group: {field[1:]}"})
        else:
            print(f"[!] Unknown SSDP Field: {field[0]}:{field[1:]}")
            raise WritePcap

    return details
