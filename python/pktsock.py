#!/usr/bin/env python

from scapy.all import *

class SessionError(Exception):
    pass

class TCPPacketSock(object):
    MTU = 1500

    def __init__(self):
        self.psock = conf.L3socket()

        self.dst = None
        self.dport = None
        self.src = None
        self.sport = None

        # TCP stuff
        self.acked = 0
        self.rseq = 0
        self.seq = 0
        self.ack = 0

    def __del__(self):
        if self.dst is not None:
            # remove filtering rule added on rbind()
            os.popen('iptables -D OUTPUT -p tcp --tcp-flags RST RST -d %s --dport %d -j DROP' %\
                     (self.dst, self.dport)) 

    # socket method
    def bind(self, addr):
        """Bind socket
        addr = (host, port)
        """
        self.src =addr[0]
        self.sport = addr[1]


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

    def send_pkt(self, pkt):
        if not TCP in pkt:
            raise ValueError, 'packet does not have TCP layer'

        self.set_ip_param(pkt)
        self.set_tcp_param(pkt)
        self.psock.send(pkt)
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
        while True:
            p = self.psock.recv(self.MTU)
            if p is  None or TCP not in p:
                continue
            if p.dst == self.src and p.dport == self.sport:
                self._handle_recv_pkt(p)
                return p
    def recv_pkt(self, num = 1):
        return self._recv_pkt(num)

def main():
    s = TCPPacketSock()
    s.bind(('192.168.11.76', 9000))
    s.rbind(('192.168.11.1', 8000))

    s.connect()
    s.send('abcde')
    s.close()

if __name__ == "__main__":
    main()
