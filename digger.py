import socket
import time
import base64


from pydiglib.dnsmsg import DNSquery, DNSresponse
from pydiglib.dnsparam import qt,qc,rc
from pydiglib.util import get_socketparams, random_init
from pydiglib.query import mk_id, mk_request,send_request_udp
from pydiglib.tsig import Tsig, read_tsig_params
from pydiglib.tsig import ITIMEOUT, RETRIES


class Digger(object):
    def __init__(self, dnsserver, host, **kwargs):
        """

        :param dnsserver: DNS Server that you are querying against.
        :param host: Host that you are querying against
        :param kwargs:
        :return:
        """
        self.validKwargs = ['type', 'port', 'ipversion','aaonly',
                            'norecurse','adFlag','cdflag', 'dnssec'
                            'use_edns0', 'tsigkey', 'tsiginfo']
        self.dnsserver = dnsserver
        self.host = host
        if not self.host.endswith("."):
            self.host += "."
        self.kwargs = kwargs

        self.qclass = 'IN' # see dnsparam for this...
        self._verifyArgs() # Verify Kwargs exist in validKwargs
        self.type=self.kwargs.get('type', 'A')

        self.port=self.kwargs.get('port', 53)
        self.port = int(self.port) # in case someone passes the port as a string...

        self.ipversion=self.kwargs.get('ipversion', None)
        self._assignIPversion()

        self.aaOnly=self.kwargs.get('aaonly', False)
        self.noRecurse=self.kwargs.get('norecurse', True)
        self.adFlag=self.kwargs.get('adflag', False)
        self.cdFlag=self.kwargs.get('cdflag', False)
        self.use_edns0=self.kwargs.get('use_edns', False)
        self.do_0x20=self.kwargs.get('do_0x20', False)
        self.dnssec=self.kwargs.get('dnssec', False)
        if self.dnssec:
            self.use_edns0 = True
            self.dnssec_ok = True
        else:
            self.use_edns0 = False
            self.dnssec_ok = False
        self._tsigHandler()
        self._packageOptions()
        self._assignValues() # Assign internal values.

    def _verifyArgs(self):
        badArgs = [key for key in self.kwargs.keys() if key not in self.validKwargs]
        if badArgs:
            raise Exception('Recieved Invalid Arguments: {}. Valid Args are {}'
                            .format(', '.join(badArgs), ', '.join(self.validKwargs)))

    def _assignValues(self):
        self._qtype = qt.get_val(self.type)
        self._qclass = qc.get_val(self.qclass)
        self._qname = self.host
        self._server_addr, self._port, self._family, self._socktype = \
            get_socketparams(self.dnsserver, self.port,
                             self._af, socket.SOCK_DGRAM)
        self._query = DNSquery(self._qname, self._qtype, self._qclass)
        random_init()
        self._txid = mk_id()
        self._tc = 0
        self._requestpkt = mk_request(self._query, self._txid, self.options)
        self._size_query = len(self._requestpkt)

    def _assignIPversion(self):
        if not self.ipversion:
            self._af = socket.AF_UNSPEC
        elif int(self.ipversion) == 4:
            self._af = socket.AF_INET
        elif int(self.ipversion) == 6:
            self._af = socket.AF_INET6
        else:
            self._af = socket.AF_UNSPEC


    def _tsigHandler(self):
        self.do_tsig = False
        if 'tsigkey' in self.kwargs.keys():
            tsig_file = self.kwargs['tsigkey']
            name, key = read_tsig_params(tsig_file)
            self.tsig = Tsig()
            self.tsig.setkey(name, key)
            self.do_tsig = True

        elif 'tsiginfo' in self.kwargs.keys():
            # -y overrides -k, if both are specified
            alg, name, key = self.kwargs['tsiginfo'].split(":")
            key = base64.decodestring(key)
            self.tsig = Tsig()
            self.tsig.setkey(name, key, alg)
            self.do_tsig = True

    def _packageOptions(self):
        def boolConvert(var):
            #python package will use True|False, but lib uses 0|1 for some...
            if var:
                return 1
            else:
                return 0

        '''packages options for pre-existing libraries'''
        self.options = {'aa': boolConvert(self.aaOnly),
                        'rd': boolConvert(self.noRecurse),
                        'ad': boolConvert(self.adFlag),
                        'cd': boolConvert(self.cdFlag),
                        'use_edns0': self.use_edns0,
                        'dnssec_ok':  boolConvert(self.dnssec_ok),
                        'do_tsig': self.do_tsig,
                        'do_0x20': self.do_0x20}

    def dig(self):
        t1 = time.time()
        (responsepkt, responder_addr) = \
                      send_request_udp(self._requestpkt, self._server_addr, self._port, self._family,
                                       ITIMEOUT, RETRIES)
        t2 = time.time()
        size_response = len(responsepkt)
        if not responsepkt:
            raise Exception("No response from server")
        self.response = DNSresponse(self._family, self._query, self._requestpkt, responsepkt, self._txid)
        if not self.response.tc:
            print ";; UDP response from %s, %d bytes, in %.3f sec" % \
                  (responder_addr, size_response, (t2-t1))
            if self._server_addr != "0.0.0.0" and responder_addr[0] != self._server_addr:
                print "WARNING: Response from unexpected address %s" % \
                      responder_addr[0]

        self.response.print_preamble(self.options)
        self.response.decode_sections()










