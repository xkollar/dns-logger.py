import socket
import struct

from datetime import datetime, timedelta

DNS_ADDR = ('127.0.0.1', 53)
LISTEN_ON = 5300

class ArpResolver(object):
    def __init__(self, timeout=timedelta(0, 300)):
        self.timeout = timeout
        self.data = dict()
        self._update()

    def _update(self):
        print "Updating arp table"
        lines = file("/proc/net/arp").readlines()[1:]
        self.data = dict(x.split()[0:4:3] for x in lines)
        self.data['127.0.0.1'] = '00:00:00:00:00:00'
        self.updated = datetime.now()

    def getMac(self, ip):
        mac = self.data.get(ip)
        if datetime.now() - self.updated > self.timeout or mac is None:
            self._update()
        else:
            return mac
        return self.data.get(ip)

def procDnsQuery(data):
    q = dict()
    q['id'] = struct.unpack('>H', data[0:2])[0]

    q['qr'] =      (ord(data[2]) & 0b10000000) >> 7
    q['op_code'] = (ord(data[2]) & 0b01111000) >> 3
    q['aa'] =      (ord(data[2]) & 0b00000100) >> 2
    q['tc'] =      (ord(data[2]) & 0b00000010) >> 1
    q['rd'] =      (ord(data[2]) & 0b00000001) >> 0

    q['ra'] =      (ord(data[3]) & 0b10000000) >> 7
    q['z'] =       (ord(data[3]) & 0b01110000) >> 4
    q['rcode'] =   (ord(data[3]) & 0b00001111) >> 0

    q['qdcount'] = struct.unpack('>H', data[4:6])[0]
    q['ancount'] = struct.unpack('>H', data[6:8])[0]
    q['nscount'] = struct.unpack('>H', data[8:10])[0]
    q['arcount'] = struct.unpack('>H', data[10:12])[0]

    pos = 12
    query = []
    while True:
        n = struct.unpack('>B', data[pos])[0]
        pos += 1
        if n == 0:
            break
        query.append(data[pos:pos+n])
        pos += n
    q['query'] = query

    q['qtype'] = struct.unpack('>H', data[pos:pos+2])[0]
    pos += 2
    q['qclass'] = struct.unpack('>H', data[pos:pos+2])[0]

    return q

if __name__ == '__main__':
    print "Starting DNS forwarder 0.1: listening on %d, forwarding to %s" % (LISTEN_ON, str(DNS_ADDR))
    arp_resolver = ArpResolver()

    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udps.bind(('', LISTEN_ON))

    udpc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        while True:
            req, req_addr = udps.recvfrom(1024)
            udpc.sendto(req, DNS_ADDR)
            resp, _ = udpc.recvfrom(1024)
            udps.sendto(resp, req_addr)
            try:
                q = procDnsQuery(req)
            except struct.error:
                print "Invalid DNS request"
                q = dict()
            print "%s %s(%s): %s" % (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"), req_addr[0], arp_resolver.getMac(req_addr[0]), ".".join(q.get('query')))
    except KeyboardInterrupt:
        print "Shutting down..."
        udps.close()
