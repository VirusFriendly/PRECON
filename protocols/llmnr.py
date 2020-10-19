from .utils import list_to_num, WritePcap

PORT = 5355

# Link Local Multicast Name Resolution
def parse(data):
    if list_to_num(data[6:8]) > 0:
        raise WritePcap

    return dict()
