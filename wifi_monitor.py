import subprocess
import time
from datetime import datetime

scan = ["nmcli", "dev", "wifi", "rescan"]
report = ["nmcli", "-f", "BSSID,SSID,SIGNAL,SECURITY", "dev", "wifi"]
header = ['BSSID', 'SSID', 'SIGNAL', 'SECURITY']
access_points = {}
SQUELCH = 30
newline = ''

try:
    while True:
        subprocess.run(scan)
        time.sleep(10)
        lines = subprocess.run(report, stdout=subprocess.PIPE).stdout.decode().split('\n')

        for line in lines:
            network = line.split()

            if network == header or len(network) == 0 or int(network[2]) <= SQUELCH:
                continue

            security = network[3]

            if len(network) > 4:
                security = ' '.join(network[3:])

            if network[0] not in access_points.keys():
                print(f"{newline}{datetime.now()}: Found new Access point {line}")
                newline = ''
                access_points[network[0]] = {
                    "ESSID": network[1],
                    "SECURITY": security,
                    "LAST SEEN": f"{datetime.now()}"
                }
            elif access_points[network[0]]["ESSID"] != network[1]:
                print(f"{newline}{datetime.now()}: AP {network[0]} changed its ESSID from {access_points[network[0]]['ESSID']} to network[1]")
                newline = ''
                access_points[network[0]]["ESSID"] = network[1]
            elif access_points[network[0]]["SECURITY"] != security:
                print(f"{newline}{datetime.now()}: AP {network[0]} changed its SECURITY from {access_points[network[0]]['SECURITY']} to network[2]")
                newline = ''
                access_points[network[0]]["SECURITY"] = security
            else:
                print('.', end='')
                newline = '\n'

            access_points[network[0]]["LAST SEEN"] = f"{datetime.now()}"

        time.sleep(50)
except KeyboardInterrupt:
    print()

    for ap in access_points.keys():
        print(f"{ap} {access_points[ap]['ESSID']} {access_points[ap]['SECURITY']} {access_points[ap]['LAST SEEN']}")