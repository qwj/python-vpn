import struct, io, collections, os, random, ipaddress
from . import enums

class Payload:
    def __init__(self, type, critical=False):
        self.type = enums.Payload(type)
        self.critical = critical
        self.data = None
    @classmethod
    def parse(cls, type, critical, stream, length):
        self = cls.__new__(cls)
        Payload.__init__(self, type, critical)
        self.parse_data(stream, length)
        return self
    def parse_data(self, stream, length):
        self.data = stream.read(length)
    def to_bytes(self):
        return self.data
    def to_repr(self):
        return f'data={self.data}'
    def __repr__(self):
        return f'{self.type.name}({"critical, " if self.critical else ""}{self.to_repr()})'

Transform = collections.namedtuple('Transform', 'type id keylen')

class Proposal:
    def __init__(self, num, protocol, spi, transforms):
        self.num = num
        self.protocol = enums.Protocol(protocol)
        self.spi = spi
        self.transforms = transforms
    @classmethod
    def parse(cls, stream):
        num, protocol, spi_size, n_transforms = struct.unpack('>BBBB', stream.read(4))
        spi = stream.read(spi_size)
        transforms = []
        more = True
        while more:
            more, length, type, id = struct.unpack('>BxHBxH', stream.read(8))
            keylen = None
            for attr_type, value in struct.iter_unpack('>HH', stream.read(length-8)):
                if attr_type & 0x7FFF == 0xe:
                    keylen = value
            transforms.append(Transform(enums.Transform(type), enums.TransformTable[type](id), keylen))
        return Proposal(num, protocol, spi, transforms)
    def to_bytes(self):
        data = bytearray()
        data.extend(struct.pack('>BBBB', self.num, self.protocol, len(self.spi), len(self.transforms)))
        data.extend(self.spi)
        for idx, transform in enumerate(self.transforms):
            transform_data = struct.pack('>HH', 0x800e, transform.keylen) if transform.keylen else b''
            data.extend(struct.pack('>BxHBxH', 0 if idx==len(self.transforms)-1 else 3, 
                len(transform_data)+8, transform.type, transform.id))
            data.extend(transform_data)
        return data
    def to_repr(self):
        return f'{self.protocol.name}:{self.num}(spi={self.spi.hex() or "None"}, ' + ', '.join(
            f'{i.id.name}{"(keylen="+str(i.keylen)+")" if i.keylen else ""}' for i in self.transforms) + ')'
    def remove_redundancy(self):
        transforms = []
        transformtypes = set()
        for t in self.transforms:
            if t.type not in transformtypes:
                transformtypes.add(t.type)
                transforms.append(t)
        return Proposal(self.num, self.protocol, self.spi, transforms)
    def get_transform(self, type):
        return next((x for x in self.transforms if x.type == type), None)
    def get_transforms(self, type):
        return [x for x in self.transforms if x.type == type]

class PayloadSA(Payload):
    def __init__(self, proposals, critical=False):
        Payload.__init__(self, enums.Payload.SA, critical)
        self.proposals = proposals
    def parse_data(self, stream, length):
        self.proposals = []
        more = True
        while more:
            more, length = struct.unpack('>BxH', stream.read(4))
            self.proposals.append(Proposal.parse(stream))
    def get_proposal(self, encr_id):
        for i in self.proposals:
            if i.get_transform(enums.Transform.ENCR).id == encr_id:
                return i.remove_redundancy()
    def to_bytes(self):
        data = bytearray()
        for idx, proposal in enumerate(self.proposals):
            proposal_data = proposal.to_bytes()
            data.extend(struct.pack('>BxH', 0 if idx==len(self.proposals)-1 else 2, len(proposal_data)+4))
            data.extend(proposal_data)
        return data
    def to_repr(self):
        return ', '.join(i.to_repr() for i in self.proposals)

class PayloadKE(Payload):
    def __init__(self, dh_group, ke_data, critical=False):
        Payload.__init__(self, enums.Payload.KE, critical)
        self.dh_group = dh_group
        self.ke_data = ke_data
    def parse_data(self, stream, length):
        self.dh_group, = struct.unpack('>H2x', stream.read(4))
        self.ke_data = stream.read(length-4)
    def to_bytes(self):
        return struct.pack('>H2x', self.dh_group) + self.ke_data
    def to_repr(self):
        return f'{self.dh_group}, {self.ke_data.hex()}'

class PayloadIDi(Payload):
    def __init__(self, id_type, id_data, critical=False):
        Payload.__init__(self, enums.Payload.IDi, critical)
        self.id_type = enums.IDType(id_type)
        self.id_data = id_data
    def parse_data(self, stream, length):
        self.id_type = enums.IDType(struct.unpack('>B3x', stream.read(4))[0])
        self.id_data = stream.read(length-4)
    def to_bytes(self):
        return struct.pack('>B3x', self.id_type) + self.id_data
    def _id_data_str(self):
        if self.id_type in (enums.IDType.ID_RFC822_ADDR, enums.IDType.ID_FQDN):
            return self.id_data.decode()
        elif self.id_type in (enums.IDType.ID_IPV4_ADDR, enums.IDType.ID_IPV6_ADDR):
            return str(ipaddress.ip_address(self.id_data))
        else:
            return self.id_data.hex()
    def to_repr(self):
        return f'{self.id_type.name}({self._id_data_str()})'

class PayloadIDr(PayloadIDi):
    def __init__(self, id_type, id_data, critical=False):
        Payload.__init__(self, enums.Payload.IDr, critical)
        self.id_type = enums.IDType(id_type)
        self.id_data = id_data

class PayloadAUTH(Payload):
    def __init__(self, method, auth_data, critical=False):
        Payload.__init__(self, enums.Payload.AUTH, critical)
        self.method = enums.AuthMethod(method)
        self.auth_data = auth_data
    def parse_data(self, stream, length):
        self.method = enums.AuthMethod(struct.unpack('>B3x', stream.read(4))[0])
        self.auth_data = stream.read(length-4)
    def to_bytes(self):
        return struct.pack('>B3x', self.method) + self.auth_data
    def to_repr(self):
        return f'{self.method.name}({self.auth_data.hex()})'

class PayloadNONCE(Payload):
    def __init__(self, nonce=None, critical=False):
        Payload.__init__(self, enums.Payload.NONCE, critical)
        self.nonce = os.urandom(random.randrange(16, 256)) if nonce is None else nonce
    def parse_data(self, stream, length):
        self.nonce = stream.read(length)
    def to_bytes(self):
        return self.nonce
    def to_repr(self):
        return f'{self.nonce.hex()}'

class PayloadNOTIFY(Payload):
    def __init__(self, protocol, notify, spi, data, critical=False):
        Payload.__init__(self, enums.Payload.NOTIFY, critical)
        self.protocol = enums.Protocol(protocol)
        self.notify = enums.Notify(notify)
        self.spi = spi
        self.data = data
    def parse_data(self, stream, length):
        protocol, spi_size, notify = struct.unpack('>BBH', stream.read(4))
        self.protocol = enums.Protocol(protocol)
        self.notify = enums.Notify(notify)
        self.spi = stream.read(spi_size)
        self.data = stream.read(length-4-spi_size)
    def to_bytes(self):
        data = bytearray(struct.pack('>BBH', self.protocol, len(self.spi), self.notify))
        data.extend(self.spi)
        data.extend(self.data)
        return data
    def to_repr(self):
        return f'{self.notify.name}({"protocol="+self.protocol.name+", " if self.protocol else ""}{"spi="+self.spi.hex()+", " if self.spi else ""}{"data="+self.data.hex() if self.data else ""})'

class PayloadDELETE(Payload):
    def __init__(self, protocol, spis, critical=False):
        Payload.__init__(self, enums.Payload.DELETE, critical)
        self.protocol = enums.Protocol(protocol)
        self.spis = spis
    def parse_data(self, stream, length):
        protocol, spi_size, num_spis = struct.unpack('>BBH', stream.read(4))
        self.protocol = enums.Protocol(protocol)
        self.spis = [stream.read(spi_size) for i in range(num_spis)]
    def to_bytes(self):
        data = bytearray()
        data.extend(struct.pack('>BBH', self.protocol, len(self.spis[0]) if self.spis else 0, len(self.spis)))
        for spi in self.spis:
            data.extend(spi)
        return data
    def to_repr(self):
        return f'{self.protocol.name}({", ".join(i.hex() for i in self.spis)})'

class PayloadVENDOR(Payload):
    def __init__(self, vendor=None, critical=False):
        Payload.__init__(self, enums.Payload.VENDOR, critical)
        self.vendor = vendor
    def parse_data(self, stream, length):
        self.vendor = stream.read(length)
    def to_bytes(self):
        return self.vendor
    def to_repr(self):
        return f'{self.vendor.decode()}'

class TrafficSelector:
    def __init__(self, ts_type, ip_proto, start_port, end_port, start_addr, end_addr):
        self.ts_type = enums.TSType(ts_type)
        self.ip_proto = enums.IpProto(ip_proto)
        self.start_port = start_port
        self.end_port = end_port
        self.start_addr = start_addr
        self.end_addr = end_addr
    @classmethod
    def from_network(cls, subnet, port, ip_proto):
        return TrafficSelector(enums.TSType.TS_IPV4_ADDR_RANGE, ip_proto, port,
                               65535 if port == 0 else port, subnet[0], subnet[-1])
    def get_network(self):
        network = ipaddress.ip_network(self.start_addr)
        while self.end_addr not in network:
            network = network.supernet()
        return network
    def get_port(self):
        return 0 if self.start_port==0 and self.end_port==65535 else self.end_port
    @classmethod
    def parse(cls, stream):
        ts_type, ip_proto, length, start_port, end_port = struct.unpack('>BBHHH', stream.read(8))
        addr_len = (length - 8) // 2
        start_addr = stream.read(addr_len)
        end_addr = stream.read(addr_len)
        return TrafficSelector(ts_type, ip_proto, start_port, end_port, ipaddress.ip_address(start_addr),
                               ipaddress.ip_address(end_addr))
    def to_bytes(self):
        pack_addr = self.start_addr.packed + self.end_addr.packed
        return struct.pack('>BBHHH', self.ts_type, self.ip_proto, 8 + len(pack_addr), self.start_port, self.end_port) + pack_addr
    def __repr__(self):
        return f'{self.ts_type.name}({self.ip_proto.name}, {self.start_addr} - {self.end_addr}, {self.start_port} - {self.end_port})'

class PayloadTSi(Payload):
    def __init__(self, traffic_selectors, critical=False):
        Payload.__init__(self, enums.Payload.TSi, critical)
        self.traffic_selectors = traffic_selectors
    def parse_data(self, stream, length):
        n_ts, = struct.unpack_from('>B3x', stream.read(4))
        self.traffic_selectors = [TrafficSelector.parse(stream) for i in range(n_ts)]
    def to_bytes(self):
        data = bytearray(struct.pack('>BBH', len(self.traffic_selectors), 0, 0))
        for ts in self.traffic_selectors:
            data.extend(ts.to_bytes())
        return data
    def to_repr(self):
        return ', '.join(repr(i) for i in self.traffic_selectors)

class PayloadTSr(PayloadTSi):
    def __init__(self, traffic_selectors, critical=False):
        Payload.__init__(self, enums.Payload.TSr, critical)
        self.traffic_selectors = traffic_selectors

class PayloadSK(Payload):
    def __init__(self, ciphertext, critical=False):
        Payload.__init__(self, enums.Payload.SK, critical)
        self.ciphertext = ciphertext
    def parse_data(self, stream, length):
        self.ciphertext = stream.read(length)
    def to_bytes(self):
        return self.ciphertext
    def to_repr(self):
        return self.ciphertext.hex()

class PayloadCP(Payload):
    def __init__(self, type, attrs, critical=False):
        Payload.__init__(self, enums.Payload.CP, critical)
        self.cftype = enums.CFGType(type)
        self.attrs = attrs
    def parse_data(self, stream, length):
        self.cftype = enums.CFGType(struct.unpack('>B3x', stream.read(4))[0])
        self.attrs = {}
        while length > 4:
            attr_type, attr_len = struct.unpack('>HH', stream.read(4))
            self.attrs[enums.CPAttrType(attr_type&0x7FFF)] = stream.read(attr_len)
            length -= 4+attr_len
    def to_bytes(self):
        data = bytearray(struct.pack('>B3x', self.cftype))
        for type, value in self.attrs.items():
            data.extend(struct.pack('>HH', type, len(value)))
            data.extend(value)
        return data
    def to_repr(self):
        return f'{self.cftype.name}({", ".join(k.name+"="+(v.hex() or "None") for k, v in self.attrs.items())})'

PayloadClass = {
    enums.Payload.SA: PayloadSA, 
    enums.Payload.KE: PayloadKE,
    enums.Payload.IDi: PayloadIDi,
    enums.Payload.IDr: PayloadIDr,
    enums.Payload.AUTH: PayloadAUTH,
    enums.Payload.NONCE: PayloadNONCE,
    enums.Payload.NOTIFY: PayloadNOTIFY,
    enums.Payload.DELETE: PayloadDELETE,
    enums.Payload.VENDOR: PayloadVENDOR,
    enums.Payload.TSi: PayloadTSi,
    enums.Payload.TSr: PayloadTSr,
    enums.Payload.SK: PayloadSK,
    enums.Payload.CP: PayloadCP,
}

class Message:
    def __init__(self, spi_i, spi_r, major, minor, exchange, is_response,
                 can_use_higher_version, is_initiator, message_id, payloads=None, *, first_payload=None):
        self.spi_i = spi_i
        self.spi_r = spi_r
        self.major = major
        self.minor = minor
        self.exchange = enums.Exchange(exchange)
        self.is_response = is_response
        self.can_use_higher_version = can_use_higher_version
        self.is_initiator = is_initiator
        self.message_id = message_id
        self.first_payload = first_payload
        self.payloads = [] if payloads is None else payloads
    @classmethod
    def parse(cls, stream):
        header = struct.unpack('>8s8s4B2L', stream.read(28))
        message = Message(header[0], header[1], header[3]>>4, header[3]&0x0F, header[4],
            bool(header[5]&0x20), bool(header[5] & 0x10), bool(header[5] & 0x08), header[6], first_payload=header[2])
        return message
    def parse_payloads(self, stream, *, crypto=None):
        next_payload = self.first_payload
        while next_payload:
            payload_id = next_payload
            next_payload, critical, length = struct.unpack('>BBH', stream.read(4))
            critical = bool(critical >> 7)
            payload = PayloadClass.get(payload_id, Payload).parse(payload_id, critical, stream, length-4)
            if payload_id == enums.Payload.SK:
                if crypto is not None:
                    crypto.verify_checksum(stream.getvalue())
                    decrypted = crypto.decrypt(payload.ciphertext)
                    stream = io.BytesIO(decrypted)
                    continue
                payload.next_payload = next_payload
                next_payload = enums.Payload.NONE
            self.payloads.append(payload)
    def to_bytes(self, *, crypto=None):
        first_payload = self.payloads[0].type if self.payloads else enums.Payload.NONE
        data = bytearray()
        for idx, payload in enumerate(self.payloads):
            payload_data = payload.to_bytes()
            if idx < len(self.payloads) - 1:
                next_payload = self.payloads[idx+1].type
            else:
                next_payload = enums.Payload.NONE
            data.extend(struct.pack('>BxH', next_payload, len(payload_data) + 4))
            data.extend(payload_data)
        if crypto:
            payload_sk = PayloadSK(crypto.encrypt(data))
            payload_data = payload_sk.to_bytes()
            data = bytearray(struct.pack('>BxH', first_payload, len(payload_data) + 4) + payload_data)
            first_payload = enums.Payload.SK
        data[0:0] = struct.pack(
            '>8s8s4B2L', self.spi_i, self.spi_r, first_payload,
            (self.major << 4 | self.minor & 0x0F), self.exchange,
            (self.is_response << 5 | self.can_use_higher_version << 4 | self.is_initiator << 3),
            self.message_id, 28+len(data))
        if crypto:
            crypto.add_checksum(data)
        return data
    def __repr__(self):
        return f'{self.exchange.name}(spi_i={self.spi_i.hex()}, spi_r={self.spi_r.hex()}, version={self.major}.{self.minor}, ' + \
                ('is_response, ' if self.is_response else 'is_request, ') + ('can_use_higher_version, ' if self.can_use_higher_version else '') + \
                ('is_initiator, ' if self.is_initiator else 'is_responder, ') + f'message_id={self.message_id}, ' + \
                ', '.join(repr(i) for i in self.payloads) + ')'
    def get_payloads(self, payload_type):
        return [x for x in self.payloads if x.type == payload_type]
    def get_payload(self, payload_type, encrypted=False):
        return next((x for x in self.payloads if x.type == payload_type), None)
