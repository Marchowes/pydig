from ..dnsmsg import pdomainname
from ..dnsparam import qc, qt



def determineRecord(**kwargs):
    #def decodeRecord(**kwargs):
    kwargs['rrname'] = pdomainname(kwargs['rrname']) #Domain name
    kwargs['rrtype'] = qt.get_name(kwargs['rrtype']) #IN
    kwargs['rrclass'] = qc.get_name(kwargs['rrclass']) # Record Type...
    return kwargs

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
        self.data = {'ip': kwargs['rdata']}

class AAAA(Record):
    def __init__(self, **kwargs):
        super(AAAA, self).__init__(**kwargs)
        self.data = {'ipv6': kwargs['rdata']}
        #Do special things with rdata

class NS(Record):
    def __init__(self, **kwargs):
        super(NS, self).__init__(**kwargs)
        self.data = {'ns': kwargs['rdata']}

class SOA(Record):
    def __init__(self, **kwargs):
        super(SOA, self).__init__(**kwargs)
        splitArgs = kwargs['rdata'].split()
        self.data = {'ns': splitArgs[0],
                     'email':splitArgs[1],
                     'serial':splitArgs[2],
                     'refresh':splitArgs[3],
                     'retry':splitArgs[4],
                     'expiry':splitArgs[5],
                     'minimum':splitArgs[6]}

class DHCID(Record):
    #Does not decode DHCID properly
    def __init__(self, **kwargs):
        super(DHCID, self).__init__(**kwargs)
        self.data = {'digest': kwargs['rdata']}


class MX(Record):
    def __init__(self, **kwargs):
        super(MX, self).__init__(**kwargs)
        splitArgs = kwargs['rdata'].split()
        self.data = {'preference': splitArgs[0],
                     'host': splitArgs[1]}

class KEY(Record):
    def __init__(self, **kwargs):
        super(KEY, self).__init__(**kwargs)
        splitArgs = kwargs['rdata'].split()
        self.data = {'flags': splitArgs[0],
                     'protocol': self.proto(splitArgs[1]),
                     'algorithm': self.alg(splitArgs[2]),
                     'key': splitArgs[3]}
    def proto(self, num):
            hash = {1: 'TLS', 2: 'EMAIL', 3: 'DNSSEC', 4: 'IPSEC' }
            return hash[int(num)]

    def alg(self, num):
            hash = {0 :'Reserved' , 1 :'RSA/MD5' , 2 :'Diffie-Hellman' , 3 :'DSA/SHA1' ,
                    4 :'Reserved' , 5 :'RSA/SHA-1' , 6 :'DSA-NSEC3-SHA1' ,
                    7 :'RSASHA1-NSEC3-SHA1' , 8 :'RSA/SHA-256' , 9 :'Reserved' ,
                    10 :'RSA/SHA-512' , 11 :'Reserved' , 12 :'GOST R 34.10-2001' ,
                    13 :'ECDSA Curve P-256 with SHA-256' , 14 :'ECDSA Curve P-384 with SHA-384' ,
                    123-251 :'Reserved' , 252 :'Reserved for Indirect Keys' ,
                    253 :'private algorithm' , 254 :'private algorithm OID' , 255 :'Reserved' }

            try:
                return hash[int(num)]
            except:
                return num

class LOC(Record):
    #Does not decode LOC properly
    def __init__(self, **kwargs):
        super(LOC, self).__init__(**kwargs)
        self.data = {'data': kwargs['rdata']}


class PTR(Record):
    def __init__(self, **kwargs):
        super(PTR, self).__init__(**kwargs)
        self.data = {'host': kwargs['rdata']}

class RP(Record):
    def __init__(self, **kwargs):
        super(RP, self).__init__(**kwargs)
        splitArgs = kwargs['rdata'].split()
        self.data = {'mbox-dname': splitArgs[0],
                     'txt-dname': splitArgs[1]}




class Unknown(Record):
    #Unknown or unsupported Records
    def __init__(self, **kwargs):
        super(Unknown, self).__init__(**kwargs)
        self.data = {'data': kwargs['rdata']}

