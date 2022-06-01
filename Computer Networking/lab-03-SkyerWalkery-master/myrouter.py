#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.arp_tab = {}
        # other initialization stuff here

    def log_arp_tab(self) -> None:
        log_info("ARP Table:")
        for ip, mac in self.arp_tab.items():
            log_info("{:<13} -> {}".format(str(ip), str(mac)))
        # log_info('\n')

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        arp = packet.get_header(Arp)
        # not an arp packet
        if arp is None or arp.operation != ArpOperation.Request:
            return
        
        self.arp_tab[arp.senderprotoaddr] = arp.senderhwaddr
        target_iface = None
        for iface in self.net.interfaces():
            if iface.ipaddr == arp.targetprotoaddr:
                target_iface = iface
                break
        else:
            return
        # send arp reply
        arp_reply = create_ip_arp_reply(target_iface.ethaddr, 
                                    arp.senderhwaddr, 
                                    target_iface.ipaddr, 
                                    arp.senderprotoaddr)
        # self.arp_tab[target_iface.ipaddr] = target_iface.ethaddr
        self.net.send_packet(ifaceName, arp_reply)

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)
            self.log_arp_tab()
        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
