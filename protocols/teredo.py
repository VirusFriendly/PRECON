from .utils import WritePcap

PORT = 3544

def parse(data):
    details = {"Parser": "Teredo", "Endpoints": list(), "Other Hosts": list()}

    if 0x70 < ord(data[0]) or ord(data[0]) < 0x60:
        print(f"[*] Teredo is version {ord(data[0])}")
        raise WritePcap

    if list_to_num(data[1:5]) != 0:
        print("[*] Teredo has a flow label")
        raise WritePcap

    if ord(data[6]) != 59:
        print("[*] Teredo has a next header")
        raise WritePcap

    if data[24:40] != '\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01':
        print(f"[*] Teredo not a multicast packet: {repr(data[24:40])}")
        raise WritePcap

    ipv6 = list_to_host6(data[8:24])  # Todo: support ipv6 in the future
    tun_server = list_to_host(data[12:16])
    tun_client_port = list_to_num([chr(0xff - ord(x)) for x in data[18:20]])
    tun_client = list_to_host([chr(0xff - ord(x)) for x in data[20:24]])

    details["Other Hosts"].append({"value": tun_client, "context": "Teredo Tunnel"})
    details["Endpoints"].append({
        "value": tun_client,
        "port": tun_client_port,
        "protocol": "udp",
        "name": "Teredo Tunnel"
    })

    return details

