from protocols.utils import list_to_num, WritePcap

def parse(udp):
    svc_port = list_to_num(udp[2:4])
    data = udp[8:]
    return dict()

    if svc_port == 67:
        # DHCP requests
        return dhcp(data)
    elif svc_port == 68:
        # Probably ignore these DHCP replies
        pass
    elif svc_port == 1124:
        # boring printer protocol
        pass
    elif svc_port == 1228:
        return bnet(data)
    elif svc_port == 1900:
        return ssdp(data)
    elif svc_port == 3289:
        # boring printer protocol
        pass
    elif svc_port == 3544:
        # Teredo IPv6 over UDP tunneling
        return teredo(data)
    elif svc_port == 3702:
        # WS-Discovery - Generally looking for WSD enabled (HP) printers
        return wsd(data)
    elif svc_port == 5353:
        return mdns(data)
    elif svc_port == 5355:
        # Link Local Name Resolution, but unlike mDNS responses are sent unicast
        return llmnr(data)
    elif svc_port == 7765:
        # WonderShare MobileGo.
        # Used to manage android phone, not really interesting except to retrieve operating system and computer name
        pass
    elif svc_port == 17500:
        # Dropbox LAN Sync Discovery Protocol
        return dropbox(data)
    elif svc_port == 48000:
        # ???
        pass
    elif svc_port == 57621:
        # Spotify UDP
        pass

    # Artificial Ignorance Catch
    raise WritePcap
