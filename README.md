![Precon Logo](https://github.com/VirusFriendly/PRECON/blob/master/assets/precon-logo.png)
### Passive network reconnaissance relying on Multicast Protocols

## Current Features

Parses out the following information:
* Battlenet - Grabs Battlenet Username
* Dropbox - Lists the number of files, Dropbox LAN Sync Port
* DHCP - DNS Server, Default Gateway, DHCP Server, Device Type/OS
* mDNS - Service Ports, Device Type/OS, Host Name
* SSDP - Service Ports, URLs, Chrome Browser Versions and other user agents
* Teredo - Service Port, Endpoints
* WSD - Nothing Really

Saves a report of collected information 

Saves unknown protocols as ai.pcap

Saves session information as data.json

## Planned Features

* Parse more protocols
* Integrate these findings findings to Armitage/Metasploit for red team engagements
* precon_user - Daemon based package that can run as any user

## Dependancies

Currently depends on

* pypcap
* dpkt
* xmltodict

## Usage

With promisc privledges, run python precon.py (sudo python repcon.py)

Precon logs to console any new information discovered

Saves unparsed packets as ai.pcap

Writes out to report.txt on exit, or hit return if you want a report without quitting

Additionally saves session information to data.json. IMPORTANT, remove this file if you've changed networks
