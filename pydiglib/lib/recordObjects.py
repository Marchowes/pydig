from ..dnsmsg import pdomainname
from ..dnsparam import qc, qt



def determineRecord(**kwargs):
    #def decodeRecord(**kwargs):
    kwargs['rrname'] = pdomainname(kwargs['rrname']) #Domain name
    kwargs['rrtype'] = qt.get_name(kwargs['rrtype']) #IN
    kwargs['rrclass'] = qc.get_name(kwargs['rrclass']) # Record Type...
    #kwargs['ttl'] = kwargs['ttl'] # TTL
    #rdata = kwargs['rdata'] #data
    ###offset = kwargs['offset'] #
    #secname = kwargs['secname'] # Question, Authority etc...
    #print '{}-{}-{}-{}-{}-{} '.format(rrname, rrtype, rrclass, ttl, rdata, secname)
    #print kwargs
    return kwargs


    #rrname, rrtype, rrclass, ttl, rdata, offset, secname




class DigObject(object):
    def __init__(self):
        #Timestamp, target server, target ip, other stuff...
        self.records = []

    def addRecord(self, *args, **kwargs):
        if kwargs['rrtype'] == 'A':
            self.records.append(A(**kwargs))

        pass





class Record(object):
    def __init__(self, **kwargs):
        self.secname = kwargs['secname']
        self.name = kwargs['rrname']
        self.type = kwargs['rrtype']
        self.recordclass = kwargs['rrclass']
        self.ttl = kwargs['ttl']


class A(Record):
    def __init__(self, **kwargs):
        super(A, self).__init__(**kwargs)
        self.ip = self.rdata = kwargs['rdata']

class AAAA(Record):
    def __init__(self, **kwargs):
        super(AAAA, self).__init__(**kwargs)
        self.ipv6 = self.rdata = kwargs['rdata']
        #Do special things with rdata

class NS(Record):
    def __init__(self, **kwargs):
        super(NS, self).__init__(**kwargs)
        self.ns = self.rdata = kwargs['rdata']

class SOA(Record):
    def __init__(self, **kwargs):
        super(SOA, self).__init__(**kwargs)
        splitArgs = kwargs['rdata'].split()
        self.ns = splitArgs[0]
        self.email = splitArgs[1]
        self.serial = splitArgs[2]
        self.refresh = splitArgs[3]
        self.retry = splitArgs[4]
        self.expiry = splitArgs[5]
        self.minimum = splitArgs[6]





        self.ns = self.rdata = kwargs['rdata']




