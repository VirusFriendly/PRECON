from .utils import WritePcap
import xmltodict

PORT = 3702

#TODO Work in progress

def parse(data):
    # OrderedDict(
    #     [
    #         (u'soap:Envelope', OrderedDict(
    #             [
    #                 (u'@xmlns:soap', u'http://www.w3.org/2003/05/soap-envelope'),
    #                 (u'@xmlns:wsa', u'http://schemas.xmlsoap.org/ws/2004/08/addressing'),
    #                 (u'@xmlns:wsd', u'http://schemas.xmlsoap.org/ws/2005/04/discovery'),
    #                 (u'soap:Header', OrderedDict(
    #                     [
    #                         (u'wsa:To', u'urn:schemas-xmlsoap-org:ws:2005:04:discovery'),
    #                         (u'wsa:Action', u'http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve'),
    #                         (u'wsa:MessageID', u'urn:uuid:bc5cb458-8a6f-4424-853d-31dbbd241457')
    #                     ]
    #                 )),
    #                 (u'soap:Body', OrderedDict(
    #                     [
    #                         (u'wsd:Resolve', OrderedDict(
    #                             [
    #                                 (u'wsa:EndpointReference', OrderedDict(
    #                                     [
    #                                         (u'wsa:Address', u'urn:uuid:00000000-0000-1000-8000-f80d60224c06')
    #                                     ]
    #                                 ))
    #                             ]
    #                         ))
    #                     ]
    #                 ))
    #             ]
    #         ))
    #     ]
    # )

    # OrderedDict(
    #     [
    #         (u'soap:Envelope', OrderedDict(
    #             [
    #                 (u'@xmlns:soap', u'http://www.w3.org/2003/05/soap-envelope'),
    #                 (u'@xmlns:wsa', u'http://schemas.xmlsoap.org/ws/2004/08/addressing'),
    #                 (u'@xmlns:wsd', u'http://schemas.xmlsoap.org/ws/2005/04/discovery'),
    #                 (u'@xmlns:wsdp', u'http://schemas.xmlsoap.org/ws/2006/02/devprof'),
    #                 (u'@xmlns:pub', u'http://schemas.microsoft.com/windows/pub/2005/07'),
    #                 (u'soap:Header', OrderedDict(
    #                     [
    #                         (u'wsa:To', u'urn:schemas-xmlsoap-org:ws:2005:04:discovery'),
    #                         (u'wsa:Action', u'http://schemas.xmlsoap.org/ws/2005/04/discovery/Hello'),
    #                         (u'wsa:MessageID', u'urn:uuid:d6d6bf5b-54f1-4b0b-a1bf-c3c2c82e23ba'),
    #                         (u'wsd:AppSequence', OrderedDict(
    #                             [
    #                                 (u'@InstanceId', u'68'),
    #                                 (u'@SequenceId', u'urn:uuid:67219220-fd87-4796-9b2b-e20a6223d047'),
    #                                 (u'@MessageNumber', u'24')
    #                             ]
    #                         ))
    #                     ]
    #                 )),
    #                 (u'soap:Body', OrderedDict(
    #                     [
    #                         (u'wsd:Hello', OrderedDict(
    #                             [
    #                                 (u'wsa:EndpointReference', OrderedDict(
    #                                     [
    #                                         (u'wsa:Address', u'urn:uuid:2f384690-4dcc-496c-bacc-191ec585b481')
    #                                     ]
    #                                 )),
    #                                 (u'wsd:Types', u'wsdp:Device pub:Computer'),
    #                                 (u'wsd:XAddrs', u'http://192.168.0.30:5357/2f384690-4dcc-496c-bacc-191ec585b481/'),
    #                                 (u'wsd:MetadataVersion', u'11')
    #                             ]
    #                         ))
    #                     ]
    #                 ))
    #             ]
    #         ))
    #     ]
    # )
    doc = xmltodict.parse(data)
    details = {"Parser": "WSD", "Extras": list(), "Ports": list()}

    if 'soap:Envelope' in doc.keys() and 'soap:Body' in doc['soap:Envelope'].keys():
        if "wsd:Hello" in doc['soap:Envelope']['soap:Body'].keys():
            if "wsd:XAddrs" in doc['soap:Envelope']['soap:Body']["wsd:Hello"].keys():
                details["Extras"].append({"value": doc['soap:Envelope']['soap:Body']["wsd:Hello"]["wsd:XAddrs"]})
                #TODO Parse URL into port, protocol, name
        if len(doc['soap:Envelope']['soap:Body'].keys()) == 1 and list(doc['soap:Envelope']['soap:Body'].keys())[0] in ['wsd:Resolve', 'wsd:Probe']:
            pass
    else:
        print(doc)
        raise WritePcap

    return details
