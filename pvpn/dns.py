import base64, binascii, struct, time, fnmatch, ipaddress

class DNSError(Exception):
    pass

class BufferError(Exception):
    pass

class DNSLabel(object):
    def __init__(self, label, origin=None):
        if isinstance(label, DNSLabel):
            self.label = label.label
        elif isinstance(label, (list, tuple)):
            self.label = tuple(label)
        else:
            final = False
            if not label or label in (b'.', '.'):
                self.label = ()
                final = bool(label)
            elif isinstance(label, str):
                self.label = tuple(label.encode("idna").rstrip(b".").split(b"."))
                final = label.endswith(".")
            else:
                self.label = tuple(label.rstrip(b".").split(b"."))
                final = label.endswith(b".")
            if not final and origin is not None:
                self.label += DNSLabel(origin).label
    def matchGlob(self, pattern):
        return fnmatch.fnmatch(str(self).lower(), str(DNSLabel(pattern)).lower())
    def __str__(self):
        return ".".join(s.decode() for s in self.label)+"."
    def __repr__(self):
        return "<DNSLabel: '%s'>" % str(self)
    def __hash__(self):
        return hash(self.label)
    def __len__(self):
        return len(b'.'.join(self.label))

class Buffer(object):
    def __init__(self, data=b''):
        self.data = bytearray(data)
        self.offset = 0
        self.names = {}
    def remaining(self):
        return len(self.data) - self.offset
    def get(self, length):
        if length > self.remaining():
            raise BufferError("Not enough bytes [offset=%d,remaining=%d,requested=%d]" %
                    (self.offset, self.remaining(), length))
        start = self.offset
        self.offset += length
        return bytes(self.data[start:self.offset])
    def get1(self):
        if self.remaining() == 0:
            raise BufferError("Not enough bytes [offset=%d,remaining=%d,requested=%d]" %
                    (self.offset, self.remaining(), 1))
        self.offset += 1
        return self.data[self.offset-1]
    def pack(self, fmt, *args):
        for i, d in zip(fmt, args):
            if i == 'B':
                self.append(struct.pack('!B', d))
            elif i == 'H':
                self.append(struct.pack('!H', d))
            elif i == 'I':
                self.append(struct.pack('!I', d))
            elif i == 'L':
                self.encode_name(d)
            elif i == 'l':
                self.encode_name_nocompress(d)
            elif i == 'S':
                self.append(struct.pack('!H', len(d)))
                self.append(d)
            elif i == 's':
                if len(d) > 255:
                    raise BufferError("Error packing struct '%s' <%s>: too long string %d" % (fmt, data, len(d)))
                self.append(struct.pack('!B', len(d)))
                self.append(d)
            elif i in ('4', '6'):
                self.append(d.packed)
            elif i == 'D':
                self.append(d)
            else:
                raise BufferError("Error packing struct '%s' <%s>: unknown fmt '%s'" % (fmt, data, i))
    def append(self, s):
        self.offset += len(s)
        self.data.extend(s)
    def update(self, ptr, fmt, *args):
        s = Buffer()
        s.pack(fmt, *args)
        self.data[ptr:ptr+len(s)] = s.data
    def unpack(self, fmt):
        data = []
        for i in fmt:
            if i == 'B':
                data.append(self.get1())
            elif i == 'H':
                data.extend(struct.unpack('!H', self.get(2)))
            elif i == 'I':
                data.extend(struct.unpack('!I', self.get(4)))
            elif i in ('L', 'l'):
                data.append(self.decode_name())
            elif i == 'S':
                length, = struct.unpack('!H', self.get(2))
                data.append(self.get(length))
            elif i == 's':
                length = self.get1()
                data.append(self.get(length))
            elif i == '4':
                data.append(ipaddress.IPv4Address(self.get(4)))
            elif i == '6':
                data.append(ipaddress.IPv6Address(self.get(16)))
            elif i == 'D':
                length = self.remaining()
                data.append(self.get(length))
            else:
                raise BufferError("Error unpacking struct '%s' <%s>" % (fmt, binascii.hexlify(self.data).decode()))
        return data
    def __len__(self):
        return len(self.data)
    def decode_name(self):
        label = []
        offsets = [self.offset]
        length = self.get1()
        while 0 < length < 0xC0:
            label.append(self.get(length))
            offsets.append(self.offset)
            length = self.get1()
        if length:
            pointer = ((length&0x3F)<<8) | self.get1()
            if pointer in self.names:
                label.extend(self.names[pointer])
            else:
                raise BufferError("Invalid pointer in DNSLabel [offset=%d,pointer=%d,length=%d]" %
                        (self.offset, pointer, len(self.data)))
        for i, j in enumerate(offsets):
            self.names[j] = label[i:]
        return DNSLabel(label)
    def encode_name(self, name):
        name = list(DNSLabel(name).label)
        while name and tuple(name) not in self.names:
            self.names[tuple(name)] = self.offset
            self.pack("s", name.pop(0))
        if name:
            self.pack("H", self.names[tuple(name)]|0xC000)
        else:
            self.append(b'\x00')
    def encode_name_nocompress(self, name):
        for element in DNSLabel(name).label:
            self.pack("s", element)
        self.append(b'\x00')

# DNS codes
QTYPE =  {1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 12:'PTR', 15:'MX', 16:'TXT', 17:'RP', 18:'AFSDB',
          24:'SIG', 25:'KEY', 28:'AAAA', 29:'LOC', 33:'SRV', 35:'NAPTR', 36:'KX', 37:'CERT',
          39:'DNAME', 41:'OPT', 42:'APL', 43:'DS', 44:'SSHFP', 45:'IPSECKEY', 46:'RRSIG',
          47:'NSEC', 48:'DNSKEY', 49:'DHCID', 50:'NSEC3', 51:'NSEC3PARAM', 52:'TLSA', 55:'HIP',
          99:'SPF', 249:'TKEY', 250:'TSIG', 251:'IXFR', 252:'AXFR', 255:'ANY', 257:'TYPE257',
          32768:'TA', 32769:'DLV'}
QTYPE_OPT = 41
QTYPE_R = {j:i for i,j in QTYPE.items()}

class DNSRecord(object):
    @classmethod
    def unpack(cls, packet):
        try:
            buffer = Buffer(packet)
            header = DNSHeader.unpack(buffer)
            questions = []
            rr = []
            auth = []
            ar = []
            for i in range(header.q):
                questions.append(DNSQuestion.unpack(buffer))
            for i in range(header.a):
                rr.append(RR.unpack(buffer))
            for i in range(header.auth):
                auth.append(RR.unpack(buffer))
            for i in range(header.ar):
                ar.append(RR.unpack(buffer))
            return cls(header, questions, rr, auth=auth, ar=ar)
        except DNSError:
            raise
        except BufferError as e:
            raise DNSError("Error unpacking DNSRecord [offset=%d]: %s" % (buffer.offset, e))
    def __init__(self, header=None, questions=None, rr=None, q=None, a=None, auth=None, ar=None):
        self.header = header or DNSHeader()
        self.questions = questions or []
        self.rr = rr or []
        self.auth = auth or []
        self.ar = ar or []
        if q: self.questions.append(q)
        if a: self.rr.append(a)
        self.set_header_qa()
    def reply(self, ra=1, aa=1):
        header = DNSHeader(self.header.id, self.header.bitmap, 0, 0, 0, 0, qr=1, ra=ra, aa=aa)
        return DNSRecord(header, q=self.q)
    def add_answer(self, *rr):
        self.rr.extend(rr)
        self.set_header_qa()
    def set_header_qa(self):
        self.header.q = len(self.questions)
        self.header.a = len(self.rr)
        self.header.auth = len(self.auth)
        self.header.ar = len(self.ar)
    @property
    def q(self):
        return self.questions[0] if self.questions else DNSQuestion()
    @property
    def a(self):
        return self.rr[0] if self.rr else RR()
    def pack(self):
        self.set_header_qa()
        buffer = Buffer()
        self.header.pack(buffer)
        for q in self.questions:
            q.pack(buffer)
        for rr in self.rr:
            rr.pack(buffer)
        for auth in self.auth:
            auth.pack(buffer)
        for ar in self.ar:
            ar.pack(buffer)
        return buffer.data

make_time = lambda d: int(time.mktime(time.strptime(d+'GMT',"%Y%m%d%H%M%S%Z")))
make_hex = lambda d: binascii.unhexlify(d.encode('ascii'))
class Struct(object):
    STRUCT = ""
    ATTRS = ()
    ZONES = {}
    @classmethod
    def unpack(cls, buffer):
        try:
            return cls(*buffer.unpack(cls.STRUCT))
        except BufferError as e:
            raise DNSError("Error unpacking %s [offset=%d]: %s" % (cls.__name__, buffer.offset, e))
    @classmethod
    def fromZone(cls, rd, origin=None):
        args = []
        idx = 0
        while idx < len(cls.ATTRS):
            i = cls.STRUCT[idx]
            t = cls.ATTRS[idx]
            d = rd[idx]
            f = cls.ZONES.get(t)
            if f:
                j = f(d)
            elif i in ('B', 'H', 'I'):
                j = int(d)
            elif i in ('L', 'l'):
                j = DNSLabel(d, origin)
            elif i in ('s', 'S'):
                j = d.encode()
            elif i == 'D':
                j = base64.b64decode(("".join(rd[idx:])).encode('ascii'))
            elif i == '4':
                j = ipaddress.IPv4Address(d.rstrip('.'))
            elif i == '6':
                j = ipaddress.IPv6Address(d)
            else:
                raise DNSError("Unknown fmt '%s' in '%s'" % (i, cls.ATTRS))
            args.append(j)
            idx += 1
        return cls(*args)
    def __init__(self, *args, **kw):
        for i, d in zip(self.ATTRS, args):
            setattr(self, i, d)
        for i, d in kw.items():
            setattr(self, i, d)
    def pack(self, buffer):
        args = [getattr(self, i) for i in self.ATTRS]
        buffer.pack(self.STRUCT, *args)
    def __str__(self):
        values = [str(getattr(self, i)) for i in self.ATTRS]
        if len(values) == 1:
            return values[0]
        else:
            return str(values)

class DNSHeader(Struct):
    STRUCT = "HHHHHH"
    ATTRS = ('id', 'bitmap', 'q', 'a', 'auth', 'ar')
    def get_qr(self):
        return (self.bitmap>>15) & 1
    def set_qr(self, val):
        self.bitmap = self.bitmap | (1<<15)
    qr = property(get_qr, set_qr)
    def get_aa(self):
        return (self.bitmap>>10) & 1
    def set_aa(self,val):
        self.bitmap = self.bitmap | (1<<10)
    aa = property(get_aa,set_aa)
    def get_ra(self):
        return (self.bitmap>>7) & 1
    def set_ra(self, val):
        self.bitmap = self.bitmap | (1<<7)
    ra = property(get_ra, set_ra)

class DNSQuestion(Struct):
    STRUCT = "LHH"
    ATTRS = ('qname', 'qtype', 'qclass')
    def __eq__(self, other):
        return str(self.qname) == str(other.qname) and self.qtype == other.qtype and self.qclass == other.qclass
    def __hash__(self):
        return hash((str(self.qname), self.qtype, self.qclass))

class EDNSOption(Struct):
    STRUCT = "HS"
    ATTRS = ('code', 'data')

class RR(object):
    CLASS = {'IN':1, 'CS':2, 'CH':3, 'Hesiod':4, 'None':254, '*':255}
    @classmethod
    def unpack(cls, buffer):
        try:
            rname, rtype, rclass, ttl, buflen = buffer.unpack("LHHIH")
            if rtype == QTYPE_OPT:
                buf = Buffer(buffer.get(buflen))
                rdata = []
                while buf.remaining() > 4:
                    rdata.append(EDNSOption.unpack(buf))
            elif buflen:
                rdata = RDMAP.get(QTYPE.get(rtype), RD).unpack(buffer)
            else:
                rdata = ''
            return cls(rname, rtype, rclass, ttl, rdata)
        except BufferError as e:
            raise DNSError("Error unpacking RR [offset=%d]: %s" % (buffer.offset, e))
    @classmethod
    def fromZone(cls, zone, origin=None, ttl=0):
        for line in zone.split('\n'):
            rr = line.strip().split()
            if not rr: continue
            label = DNSLabel(rr.pop(0), origin)
            ttl = int(rr.pop(0)) if rr[0].isdigit() else ttl
            rclass = rr.pop(0) if rr[0] in ('IN','CS','CH') else 'IN'
            rtype = rr.pop(0)
            rdata = rr
            rd = RDMAP.get(rtype, RD)
            yield RR(rname=label, ttl=ttl, rclass=cls.CLASS[rclass],
                     rtype=QTYPE_R.get(rtype), rdata=rd.fromZone(rdata, origin))
    def __init__(self, rname=None, rtype=1, rclass=1, ttl=0, rdata=None):
        self.rname = rname
        self.rtype = rtype
        self.rclass = rclass
        self.ttl = ttl
        self.rdata = rdata
        if self.rtype == QTYPE_OPT:
            self.edns_len = self.rclass
            self.edns_do = self.ttl & 0x7FFF
            self.edns_ver = (self.ttl>>16) & 0xFF
            self.edns_rcode = (self.ttl>>24) & 0xFF
    def pack(self, buffer):
        buffer.pack("LHHIH", self.rname, self.rtype, self.rclass, self.ttl, 0)
        start = buffer.offset
        if self.rtype == QTYPE_OPT:
            for opt in self.rdata:
                opt.pack(buffer)
        else:
            self.rdata.pack(buffer)
        buffer.update(start-2, "H", buffer.offset-start)

class RD(Struct):
    STRUCT = "D"
    ATTRS = ('data',)
    ZONES = {'data': make_hex}

class TXT(Struct):
    STRUCT = "s"
    ATTRS = ('data',)

class A(Struct):
    STRUCT = "4"
    ATTRS = ('data',)

class AAAA(Struct):
    STRUCT = "6"
    ATTRS = ('data',)

class MX(Struct):
    STRUCT = "HL"
    ATTRS = ('preference', 'label')

class CNAME(Struct):
    STRUCT = "L"
    ATTRS = ('label',)

class DNAME(Struct):
    STRUCT = "L"
    ATTRS = ('label',)

class PTR(CNAME):
    pass

class NS(CNAME):
    pass

class SOA(Struct):
    STRUCT = "LLIIIII"
    ATTRS = ('mname', 'rname', 't0', 't1', 't2', 't3', 't4')

class SRV(Struct):
    STRUCT = "HHHL"
    ATTRS = ('priority', 'weight', 'port', 'target')

class NAPTR(Struct):
    STRUCT = "HHsssL"
    ATTRS = ('order', 'preference', 'flags', 'service', 'regexp', 'replacement')

class DNSKEY(Struct):
    STRUCT = "HBBD"
    ATTRS = ('flags', 'protocol', 'algorithm', 'key')

class RRSIG(Struct):
    STRUCT = "HBBIIIHlD"
    ATTRS = ('covered', 'algorithm', 'labels', 'orig_ttl', 'sig_exp', 'sig_inc', 'key_tag', 'name', 'sig')
    ZONES = {'sig_exp': make_time, 'sig_inc': make_time}

RDMAP = dict(CNAME=CNAME, DNAME=DNAME, A=A, AAAA=AAAA, TXT=TXT, MX=MX, PTR=PTR, SOA=SOA, NS=NS,
             NAPTR=NAPTR, SRV=SRV, DNSKEY=DNSKEY, RRSIG=RRSIG)

class DNSCache(object):
    def __init__(self):
        self.cache = {}
        self.rdns = {}
    def query(self, record):
        if len(record.questions) == 1:
            if record.q in self.cache:
                answer = self.cache[record.q]
                answer.header.id = record.header.id
                for r in answer.rr:
                    if r.rtype in (1, 5, 39) and r.rclass == 1:
                        self.rdns[str(r.rdata)] = str(r.rname)
                return answer
    def answer(self, record):
        if len(record.questions) == 1 and record.rr:
            self.cache[record.q] = record
        for r in record.rr:
            if r.rtype in (1, 5, 39) and r.rclass == 1:
                self.rdns[str(r.rdata)] = str(r.rname)
    def ip2domain(self, ip):
        while ip in self.rdns:
            ip = self.rdns[ip]
        return ip.rstrip('.')
