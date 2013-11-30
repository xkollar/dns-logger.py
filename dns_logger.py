#!/usr/bin/env python

"""DNS query forwarder/logger

Handy for detecting malware on network.
"""

__author__     = "Matej Kollar"
__contact__    = "xkolla06@stud.fit.vutbr.cz"

__version__    = "0.1"
__date__       = "2013. 01. 20."
__license__    = "GPLv3"

__credits__    = [__author__]
__maintainer__ = __author__
__status__     = "Working"


import Queue

import SocketServer
import itertools
import random
import socket
import struct
import sys
import threading
import time

from datetime import datetime, timedelta


class ForbiddenAttribute(Exception):
    """Exception for FilterWrapper"""
    pass


class FilterWrapper(object):
    """Wrapper to hide attributes/methods.
    Mostly useful for debugging, similar to assert."""
    def __init__(self, obj, allowed):
        self.__allowed = allowed
        self.__obj = obj

    def __getattr__(self, attr):
        # print "Access to attribute %s" % attr
        if attr in self.__allowed:
            return getattr(self.__obj, attr)
        raise ForbiddenAttribute(attr)


READER_METHODS = ["get", "get_nowait", "empty", "task_done"]
WRITER_METHODS = ["put", "put_nowait", "full", "join"]


def proc_dns_query(data):
    """Breaks DNS query into more understandable structure"""
    query = dict()
    query['id'] = struct.unpack('>H', data[0:2])[0]

    query['qr'] =      (ord(data[2]) & 0b10000000) >> 7
    query['op_code'] = (ord(data[2]) & 0b01111000) >> 3
    query['aa'] =      (ord(data[2]) & 0b00000100) >> 2
    query['tc'] =      (ord(data[2]) & 0b00000010) >> 1
    query['rd'] =      (ord(data[2]) & 0b00000001) >> 0

    query['ra'] =      (ord(data[3]) & 0b10000000) >> 7
    query['z'] =       (ord(data[3]) & 0b01110000) >> 4
    query['rcode'] =   (ord(data[3]) & 0b00001111) >> 0

    query['qdcount'] = struct.unpack('>H', data[4:6])[0]
    query['ancount'] = struct.unpack('>H', data[6:8])[0]
    query['nscount'] = struct.unpack('>H', data[8:10])[0]
    query['arcount'] = struct.unpack('>H', data[10:12])[0]

    pos = 12
    qname = []
    while True:
        size = struct.unpack('>B', data[pos])[0]
        pos += 1
        if size == 0:
            break
        qname.append(data[pos:pos + size])
        pos += size
    query['qname'] = qname

    query['qtype'] = struct.unpack('>H', data[pos:pos + 2])[0]
    pos += 2
    query['qclass'] = struct.unpack('>H', data[pos:pos + 2])[0]

    return query


class TimedItem(object):
    """Keep time information for object."""
    def __init__(self, obj):
        self.time = datetime.utcnow()
        self.val = obj

    def age(self):
        """Returns timedelta between from creation."""
        return datetime.utcnow() - self.time


class LoggerQueue(Queue.Queue):
    """Queue that adds time information to objects."""
    def put(self, item, block=True, timeout=None):
        return Queue.Queue.put(self, TimedItem(item), block, timeout)

    def put_nowait(self, item):
        return Queue.Queue.put_nowait(self, TimedItem(item))


class BaseLogger(threading.Thread):
    """Base logger to extend."""
    reader = None
    writer = None
    outs = None
    num = 0

    def __init__(self, outs=[sys.stdout]):
        queue = LoggerQueue()
        self.reader = FilterWrapper(queue, READER_METHODS)
        self.writer = FilterWrapper(queue, WRITER_METHODS)
        self.outs = outs
        super(BaseLogger, self).__init__()

    def format_entry(self, entry):
        """Base formatter, to be overwritten."""
        return repr(entry)

    def run(self):
        """Main logging functionality, override/extend with caution."""
        while True:
            entry = self.reader.get()
            self.num = self.num + 1
            for out in self.outs:
                print >> out, ("[%s] %d %s" % (
                    entry.time.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    self.num,
                    self.format_entry(entry.val))).encode('utf-8')
                out.flush()
            self.reader.task_done()


class AgingEntry(object):
    """Keeps number of ticks along with value."""
    age = 0

    def __init__(self, val):
        self.val = val

    def tick(self):
        """Increment age."""
        self.age += 1


class ArpResolver(object):
    """Resolution IP -> MAC.
    Based on /proc/net/arp, maintains cache."""
    static = [("127.0.0.1", "00:00:00:00:00:00")]

    def __init__(self, timeout=300):
        self.timeout = timedelta(0, timeout)
        self.data = {}
        self.updated = None
        self._update()

    def _get_current(self):
        """Fetch current data."""
        with open("/proc/net/arp", "r") as arpfile:
            lines = arpfile.readlines()[1:]
        new_data = itertools.chain(
            (x.split()[0:4:3] for x in lines),
            self.static)
        return dict((k, AgingEntry(v)) for k, v in new_data)

    def _update(self):
        """Try to update cache with new entries."""
        # print "Updating ARP table"
        for val in self.data.itervalues():
            val.tick()
        self.data.update(self._get_current())
        self.updated = datetime.now()

    def get_mac(self, ip, retry=1):
        """Tries to resolve IP -> MAC."""
        if datetime.now() - self.updated > self.timeout:
            self._update()

        mac = self.data.get(ip)

        if (mac is None or mac.age > 0) and retry > 0:
            time.sleep(0.5)
            self._update()
            return self.get_mac(ip, retry - 1)

        if mac is not None and mac.age == 0:
            return mac.val

        if mac is not None:
            return "%s!%d" % (mac.val, mac.age)

        return mac


class DnsLogEntry(object):
    """Keep info about dns request for logging purposes."""
    def __init__(self, ip, query):
        self.ip = ip
        self.query = query


class DnsArpLogger(BaseLogger):
    """Specific functionality to log Mac address and IP with DNS query"""
    def __init__(self, arp_resolver, *args, **kwargs):
        self.arp_resolver = arp_resolver
        super(DnsArpLogger, self).__init__(*args, **kwargs)

    def format_entry(self, entry):
        if isinstance(entry, str):
            return entry
        if isinstance(entry, DnsLogEntry):
            try:
                query = proc_dns_query(entry.query)
                return "%s(%s): %s" % (
                    entry.ip,
                    self.arp_resolver.get_mac(entry.ip),
                    ".".join(query.get('qname')))
            except struct.error:
                return "Invalid DNS request from %s." % entry.ip

        return super(DnsArpLogger, self).format_entry(entry)


class Stamper(threading.Thread):
    """Generates timestamps into given log queue.
    This makes possible differenciate time that server
    was down vs. no requests came."""
    writer = None
    periode = None
    run_id = None
    num = 0

    def __init__(self, writer, run_id, periode=60):
        self.writer = writer
        self.periode = periode
        self.run_id = run_id
        super(Stamper, self).__init__()

    def run(self):
        while True:
            time.sleep(self.periode)
            self.writer.put("TickMark %d run %d" % (self.num, self.run_id))
            self.num += 1


class DnsServer(SocketServer.ThreadingUDPServer):
    """Extended ThreadingUDPServer to serve our purposes."""
    # May be false in production environments(?)
    allow_reuse_address = True
    max_packet_size = 1024

    def __init__(self, log, server_address, RequestHandlerClass):
        SocketServer.ThreadingUDPServer.__init__(
            self,
            server_address,
            RequestHandlerClass)
        self.log = log


class DnsRequestHandler(SocketServer.DatagramRequestHandler):
    """Handle separate DNS queries."""
    def handle(self):
        req, udps = self.request
        udpc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udpc.sendto(req, DNS_ADDR)

        self.server.log.put(DnsLogEntry(self.client_address[0], req))

        resp, _ = udpc.recvfrom(1024)
        udps.sendto(resp, self.client_address)
        udpc.close()


def main(listen_on):
    """Main function"""

    with open("/var/log/dns.log", "a") as logfile:
        logger = DnsArpLogger(ArpResolver(), [logfile])
        logger.setDaemon(True)
        logger.start()

        log = logger.writer

        run_id = int(random.random() * 2 ** 20)

        log.put("DNS request log start run %d (version %s)." %
                (run_id, __version__))

        log.put("Serving on %d, forwarding to %s." %
                (listen_on, str(DNS_ADDR)))

        stamper = Stamper(log, run_id, 60 * 5)
        stamper.setDaemon(True)
        stamper.start()

        try:
            server = DnsServer(log, ('', listen_on), DnsRequestHandler)
            server.serve_forever()
        except KeyboardInterrupt:
            pass

        log.put("Shutting down...")
        log.join()


DNS_ADDR = ('127.0.0.1', 54)

if __name__ == "__main__":
    main(53)
