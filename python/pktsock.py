#!/usr/bin/env python
#
# pktsock -- TCP socket implemented by using scapy
#

from scapy.all import *
import os
from select import select
import cPickle
import signal
from threading import Thread, Event

class SessionError(Exception):
    pass

class TCPPacketSock(object):
    MTU = 1500

    def __init__(self, iface = None):
        # IP stuff
        self.dst = None
        self.src = None

        # TCP stuff
        self.dport = None
        self.sport = None
        self.acked = 0
        self.rseq = 0
        self.seq = 0
        self.ack = 0

        # worker
        self.psock = conf.L3socket(iface = iface)
        self.iface = iface
        self.sendpkt_buf = []
        self.recvpkt_buf = []
        self.worker = None

    def __del__(self):
        if self.dst is not None:
            # remove filtering rule added on rbind()
            os.popen('iptables -D OUTPUT -p tcp --tcp-flags RST RST -d %s --dport %d -j DROP' %\
                     (self.dst, self.dport))
        if self.worker and self.worker.isAlive():
            # kill sendrecv worker
            self.worker_ev.set()

    def sig_handler(self, signum, frame):
        print self.worker_ev, 'set'
        self.worker_ev.set()

    def init_sock_worker(self):
        """Initialize a worker to send/recv on another process
        """

        self.worker_ev = Event()
        signal.signal(signal.SIGTERM, self.sig_handler)
        signal.signal(signal.SIGINT, self.sig_handler)
        self.worker = Thread(target = self.sendrecv_work, args = (self.worker_ev, ))
        self.worker.start()

    def sendrecv_work(self, ev):
        while not ev.isSet():
            inp, outp, err = select([self.psock], [], [], 1)
            # if self.sendpkt_buf in inp:
            #     # sendbuf has a packet
            #     print 'send_pipe', self.sendpkt_buf.pop(0)
            if ev.isSet():
                break
            if self.psock in inp:
                # packet recieved
                p = self._recv_pkt(1)
                if p:
                    print 'recv', repr(p)

    # socket method
    def bind(self, addr):
        """Bind socket
        addr = (host, port)
        """
        self.src =addr[0]
        self.sport = addr[1]

        # initialize worker here
        self.init_sock_worker()

    def connect(self, addr = None):
        """Connect to remote socket
        """
        if addr:
            self.rbind(addr)
        self.send_syn()
        p = self.recv_pkt()
        if not p[TCP].flags & (1<<4) | (1<<1):
            # not a SYN/ACK packet
            raise SessionError, 'connect failed'
        self.send_ack()


    def send(self, data):
        self.send_pkt(IP()/TCP(flags='A')/data)
        p = self.recv_pkt()
        if not p[TCP].flags & (1<<4):
            raise SessionError, 'send error - not ack flag'
        if self.acked != self.seq:
            raise SessionError, 'send error - not acked acked:%d seq:%d' % (self.acked, self.seq)

    def close(self):
        self.send_fin()
        self.recv_pkt()
        self.send_ack()

    def rbind(self, addr):
        """Bind remote host
        addr = (rhost, rport)
        """
        self.dst = addr[0]
        self.dport = addr[1]

        # ignore sending RST to remote host
        os.popen('iptables -A OUTPUT -p tcp --tcp-flags RST RST -d %s --dport %d -j DROP' %\
                 (self.dst, self.dport)) 

    def _set_dst(self, pkt):
        pkt.dst = self.dst
        pkt.dport = self.dport

    def _set_src(self, pkt):
        pkt.src = self.src
        pkt.sport = self.sport

    def set_ip_param(self, pkt):
        self._set_dst(pkt)
        self._set_src(pkt)

    def set_tcp_param(self, pkt):
        pkt.seq = self.seq
        pkt.ack = self.rseq

    def _send_pkt(self, pkt):
        # self.psock.send(pkt)
        self.psock.send(pkt)

    def send_pkt(self, pkt):
        if not TCP in pkt:
            raise ValueError, 'packet does not have TCP layer'

        self.set_ip_param(pkt)
        self.set_tcp_param(pkt)
        self._send_pkt(pkt)
        self.seq += len(pkt[TCP].payload)

        # SYN or FIN packet -> seq++
        if pkt[TCP].flags & (1<<1) or pkt[TCP].flags & (1<<0):
            self.seq += 1

    def send_syn(self):
        self.send_pkt(IP()/TCP(flags='S'))

    def send_fin(self):
        self.send_pkt(IP()/TCP(flags = 'FA'))

    def send_ack(self):
        p = IP()/TCP(flags='A')
        self.set_ip_param(p)
        self.set_tcp_param(p)
        self.send_pkt(p)

    def send_rst(self):
        p = IP()/TCP(flags='RA')
        self.set_ip_param(p)
        self.set_tcp_param(p)
        self.send_pkt(p)

    def _handle_recv_pkt(self, pkt):
        self.rseq = pkt.seq + len(pkt[TCP].payload)
        self.acked = pkt.ack
        if pkt[TCP].flags & (1<<1) or pkt[TCP].flags & (1<<0):
            self.rseq += 1

    def _recv_pkt(self, num):
        p = self.psock.recv(self.MTU)
        if p is  None or TCP not in p:
            return None
        if p.dst == self.src and p.dport == self.sport:
            self._handle_recv_pkt(p)
            return p
        return None

    def recv_pkt(self, num = 1):
        return self._recv_pkt(num)

def main():
    s = TCPPacketSock()
    s.bind(('192.168.11.76', 9000))
    s.rbind(('192.168.11.1', 8000))

    s.send_syn()
    s.send_ack()
    s.send_rst()
    raw_input()
    # s.connect()
    # s.send('abcde')
    # s.close()
    s.worker_ev.set()

if __name__ == "__main__":
    main()
