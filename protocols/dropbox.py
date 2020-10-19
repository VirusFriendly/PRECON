import json

PORT = 17500

def dropbox(data):
    dropbox = json.loads(data)
    details = {"Parser": "Dropbox"}

    details["Extras"] = [{"value": f"Contains {len(dropbox['namespaces'])} dropbox files"}]
    details["Ports"] = [{"value": dropbox["port"], "protocol": "tcp", "name": "Dropbox LAN Sync"}]

    return details

