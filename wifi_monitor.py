import subprocess
import time
from datetime import datetime

scan = ["nmcli", "dev", "wifi", "rescan"]
report = ["nmcli", "-t", "-e", "no", "-f", "BSSID,SSID,SIGNAL,CHAN,SECURITY", "dev", "wifi"]
access_points = {}
SQUELCH = 30

try:
    while True:
        subprocess.run(scan)
        time.sleep(10)
        lines = subprocess.run(report, stdout=subprocess.PIPE).stdout.decode().split('\n')

        for line in lines:
            network = line.split(':')

            if len(network) < 8:
                if len(network) > 1:
                    print(f"error: {network}")

                continue

            bssid = ':'.join(network[0:6])
            essid = network[6]
            channel = network[8]
            security = network[-1]

            if len(essid) == 0:
                essid = "(hidden)"
            else:
                essid = '"' + essid + '"'

            if len(security) == 0:
                security = "(open)"

            if bssid not in access_points.keys():
                print(f"{datetime.now()}: Found AP {bssid}/{essid} on channel {channel} using {security}")
                access_points[bssid] = {
                    "ESSID": essid,
                    "SECURITY": security,
                    "CHANNEL": channel,
                    "LAST SEEN": f"{datetime.now()}"
                }

                continue

            access_points[bssid]["LAST SEEN"] = f"{datetime.now()}"

            if access_points[bssid]["ESSID"] != essid:
                print(f"{datetime.now()}: AP {bssid} changed its ESSID from {access_points[bssid]['ESSID']} to {essid}")
                access_points[bssid]["ESSID"] = essid

            if access_points[bssid]["SECURITY"] != security:
                print(f"{datetime.now()}: AP {bssid}/{essid} changed its SECURITY from {access_points[bssid]['SECURITY']} to {security}")
                access_points[bssid]["SECURITY"] = security

            if access_points[bssid]["CHANNEL"] != channel:
                print(f"{datetime.now()}: AP {bssid}/{essid} changed from channel {access_points[bssid]['CHANNEL']} to {channel}")
                access_points[bssid]["CHANNEL"] = channel

        time.sleep(50)
except KeyboardInterrupt:
    print()

    for ap in access_points.keys():
        print(f"{ap} {access_points[ap]['ESSID']} {access_points[ap]['SECURITY']} Channel:{access_points[ap]['CHANNEL']} {access_points[ap]['LAST SEEN']}")
