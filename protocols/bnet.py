from .utils import WritePcap

# CSV based protocol
# fields[0] unknown
# fields[1] some user/session dependant number between 968472 and 307445411
# fields[2] unknown
# fields[3] UID
# fields[4] user name
# fields[5] unique username number
# fields[6] unknown
# fields[7] Region
# fields[8] unknown
# fields[9] a rather peculiar value whose MSB changes more than the LSB
PORT = 1228

def parse(data):
    fields = data.split(',')
    details = dict()

    if len(fields) != 10:
        raise WritePcap

    account = fields[4] + '#' + fields[5]
    details["User Tags"]=[{"value": account, "context": "BattleNet"}]

    return details
