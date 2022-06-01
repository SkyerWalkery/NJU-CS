#!/usr/bin/env python3


import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blastee:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasterIp = '192.168.100.1',
            num = '15'
    ):
        self.net = net
        self.blaster_ip = IPAddr(blasterIp)
        self.packets_num = int(num)
        self.has_receive_all = False

    def make_ack(self, origin_packet: Packet) -> Packet:
        '''
        Make an ACK packet
        '''
        '''
        Packet from blaster looks likes this
        <------- Switchyard headers -----> <----- Your packet header(raw bytes) ------> <-- Payload in raw bytes --->
        -------------------------------------------------------------------------------------------------------------
        |  ETH Hdr |  IP Hdr  |  UDP Hdr  | Sequence number(32 bits) | Length(16 bits) |   Variable length payload  |
        -------------------------------------------------------------------------------------------------------------
        '''
        origin_eth = origin_packet.get_header(Ethernet)
        origin_ipv4 = origin_packet.get_header(IPv4)
        origin_udp = origin_packet.get_header(UDP)
        # delete ethernet, ipv4, udp headers
        del origin_packet[Ethernet]
        del origin_packet[IPv4]
        del origin_packet[UDP]
        seq_num = origin_packet[0].to_bytes()[:4]
        if int.from_bytes(seq_num, byteorder='big') == self.packets_num:
            self.has_receive_all = True
        payload = origin_packet[0].to_bytes()[6:]
        if len(payload) < 8:
            payload += (bytes(b'\x23') * (8 - len(payload)))
        else:
            payload = payload[:8]
        eth_header = Ethernet(
            dst = origin_eth.src,
            src = origin_eth.dst,
            ethertype = EtherType.IPv4
        )
        ip_header = IPv4(
            dst = origin_ipv4.src,
            src = origin_ipv4.dst,
            protocol = IPProtocol.UDP,
            ttl = 64
        )
        udp_header = UDP(
            dst = origin_udp.src,
            src = origin_udp.dst,
        )
        log_info(f"ACK packet: seq:{int.from_bytes(seq_num, byteorder='big')}")
        return eth_header + ip_header + udp_header + RawPacketContents(seq_num + payload)
        

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug(f"I got a packet from {fromIface}")
        log_debug(f"Pkt: {packet}")
        ack_packet = self.make_ack(packet)
        self.net.send_packet(fromIface, ack_packet)
        

    def start(self):
        '''A running daemon of the blastee.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=3.0)
            except NoPackets:
                if self.has_receive_all:
                    break
                else:
                    continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.shutdown()

    def shutdown(self):
        log_info("Blastee has received all packets, shutting down.")
        self.net.shutdown()


def main(net, **kwargs):
    blastee = Blastee(net, **kwargs)
    blastee.start()
