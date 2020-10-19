class WritePcap(Exception):
        pass

def list_to_num(x):
    total = 0

    for digit in x:
        total = total * 256 + digit

    return total


def list_to_host(x):
    return '.'.join([str(y) for y in x])


def list_to_host6(x):
    assert len(x) == 16

    return ':'.join([''.join([hex(x[i]).split('x')[-1], hex(x[i+1]).split('x')[-1]]) for i in range(0, 16, 2)])


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
        print(f"Unknown Protocol: {url}")
        raise WritePcap

    return hostname, port, proto

