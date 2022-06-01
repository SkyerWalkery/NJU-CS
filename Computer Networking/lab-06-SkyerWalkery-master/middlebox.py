#!/usr/bin/env python3

import random
import time
import copy

import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Middlebox:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            dropRate="0.3"
    ):
        self.net = net
        self.dropRate = float(dropRate)
        self.blaster_mac = EthAddr('10:00:00:00:00:01')
        self.blastee_mac = EthAddr('20:00:00:00:00:01')
        random.seed(time.time())

    def should_drop(self) -> bool:
        return random.random() < self.dropRate

    def modify_packet(self, packet: Packet, src_mac, dst_mac):
        '''
        Modify the headers of the packet
        '''
        packet[Ethernet].src = src_mac
        packet[Ethernet].dst = dst_mac
        packet[IPv4].ttl -= 1

    def get_seq(self, packet: Packet) -> int:
        '''
        Get the sequence number of the packet
        '''
        copy_packet = copy.deepcopy(packet)
        del copy_packet[Ethernet]
        del copy_packet[IPv4]
        del copy_packet[UDP]
        return int.from_bytes(copy_packet[0].to_bytes()[:4], byteorder='big')


    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        seq_num: int = self.get_seq(packet)
        if fromIface == "middlebox-eth0":
            log_debug("Received from blaster")
            '''
            Received data packet
            Should I drop it?
            If not, modify headers & send to blastee
            '''
            if not self.should_drop():
                self.modify_packet(
                    packet, 
                    self.net.interface_by_name("middlebox-eth1").ethaddr, 
                    self.blastee_mac
                )
                log_info(f"Sending to blastee: seq:{seq_num}")
                self.net.send_packet("middlebox-eth1", packet)
            else:
                log_info(f"Dropping: seq:{seq_num}")
            
        elif fromIface == "middlebox-eth1":
            log_debug("Received from blastee")
            '''
            Received ACK
            Modify headers & send to blaster. Not dropping ACK packets!
            '''
            self.modify_packet(
                packet,
                self.net.interface_by_name("middlebox-eth0").ethaddr,
                self.blaster_mac
            )
            log_info(f"Sending to blaster: seq:{seq_num}")
            self.net.send_packet("middlebox-eth0", packet)
        else:
            log_debug("Oops :))")

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

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    middlebox = Middlebox(net, **kwargs)
    middlebox.start()
