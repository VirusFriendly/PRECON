from .utils import list_to_num, WritePcap
from . import bnet
from . import dhcp
from . import dropbox
from . import llmnr
from . import mdns
from . import ssdp
from . import teredo
from . import wsd


def parse(udp):
    svc_port = list_to_num(udp[2:4])
    data = udp[8:]

    if svc_port == dhcp.SERVER_PORT:
        # DHCP requests
        return dhcp.parse(data)
    elif svc_port == dhcp.CLIENT_PORT:
        # Probably ignore these DHCP replies
        return dict()
    elif svc_port == 1124:
        # boring printer protocol
        return dict()
    elif svc_port == bnet.PORT:
        return bnet.parse(data)
    elif svc_port == ssdp.PORT:
        return ssdp.parse(data)
    elif svc_port == 3289:
        # boring printer protocol
        return dict()
    elif svc_port == teredo.PORT:
        # Teredo IPv6 over UDP tunneling
        return teredo.parse(data)
    elif svc_port == wsd.PORT:
        # WS-Discovery - Generally looking for WSD enabled (HP) printers
        return wsd.parse(data)
    elif svc_port == mdns.PORT:
        return mdns.parse(data)
    elif svc_port == llmnr.PORT:
        # Link Local Name Resolution, but unlike mDNS responses are sent unicast
        return llmnr.parse(data)
    elif svc_port == 7765:
        # WonderShare MobileGo.
        pass
    elif svc_port == dropbox.PORT:
        # Dropbox LAN Sync Discovery Protocol
        return dropbox.parse(data)
    elif svc_port == 48000:
        # ???
        pass
    elif svc_port == 57621:
        # Spotify UDP
        pass

    # Artificial Ignorance Catch
    raise WritePcap

