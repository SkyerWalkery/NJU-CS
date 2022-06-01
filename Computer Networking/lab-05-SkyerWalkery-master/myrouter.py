#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import threading
import switchyard
from switchyard.lib.userlib import *


class ForwardingTableEntry:
    def __init__(self, network_ip: IPv4Address, subnet_mask: IPv4Address, next_hop_ip: IPv4Address, interface: str):
        self.ip_with_mask = IPv4Network(str(network_ip) + '/' + str(subnet_mask), strict=False)
        self.next_hop_ip = next_hop_ip
        self.interface = interface
    
    # sort by length of prefix, so that longest prefix match is supported
    def __lt__(self, other):
        return self.ip_with_mask.prefixlen < other.ip_with_mask.prefixlen


class ForwardingTable:
    def __init__(self, file = None, router_interfaces = None):
        self.table = []
        # from file read forwarding table
        if file is not None:
            with open(file) as f:
                for line in f:
                    line = line.strip()
                    if line == '':
                        continue
                    network, subnet, next_hop, interface = line.split()
                    self.table.append(ForwardingTableEntry(IPv4Address(network),
                                                           IPv4Address(subnet),
                                                           IPv4Address(next_hop),
                                                           interface))
        # The IP address 0.0.0.0 means that  
        # if a packet's destination IP matches this network address
        # just throw the packet out of this interface, 
        # expecting that the next hop is the destination.                                                   
        if router_interfaces is not None:
            for itface in router_interfaces:
                self.table.append(ForwardingTableEntry(itface.ipaddr,
                                                       itface.netmask,
                                                       IPv4Address('0.0.0.0'),
                                                       itface.name))
        # Sort the table by prefix length, so longer prefixes are checked first
        self.table.sort(reverse=True)

    def match(self, ip_addr: IPv4Address):
        """ find an entry to macth the given IP address """
        for entry in self.table:
            if ip_addr in entry.ip_with_mask:
                return entry
        return None


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.arp_tab = dict()
        self.forwarding_table = ForwardingTable('forwarding_table.txt', self.net.interfaces())
        # queue of packets waiting for mac address(a dict)
        # (ip: [ReceivedPackets, forward_interface, timestamp, times of arp request])
        self.waiting_packets = dict() 

        # mutiple thread supported
        # To activate mutiple thread, set self.muti_thread = True
        self.lock = threading.RLock()
        self.start_thread = threading.Thread(target=self.start)
        self.arp_req_thread = threading.Thread(target=self.make_arp_request)
        self.muti_thread = False
        if self.muti_thread:
            self.arp_req_thread.start()
            self.start_thread.start()


    def handle_arp(self, recv: switchyard.llnetbase.ReceivedPacket) -> None:
        """ handle an arp packet """
        timestamp, ifaceName, packet = recv
        arp = packet.get_header(Arp)
        # completed in lab3, response to arp request
        if arp.operation is ArpOperation.Request:
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
        else:
            # receive an arp reply
            # update the arp table
            # if the packet is waiting for this mac address, forward it
            self.arp_tab[arp.senderprotoaddr] = arp.senderhwaddr
            if self.muti_thread:
                self.lock.acquire()
            if arp.senderprotoaddr in self.waiting_packets:
                recv_packets, forward_interface, timestamp, times = self.waiting_packets[arp.senderprotoaddr]
                for timestamp, ifaceName, packet in recv_packets: 
                    self.forward_packet(packet, arp.senderhwaddr, forward_interface)
                del self.waiting_packets[arp.senderprotoaddr]
            if self.muti_thread:
                self.lock.release()


    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket) -> None:
        """ handle a non-arp packet """
        timestamp, ifaceName, packet = recv
        ip_header = packet.get_header(IPv4)
        if ip_header is None:
            return

        # Check if the packet is destined for this router, drop it
        if ip_header.dst in [iface.ipaddr for iface in self.net.interfaces()]:
            # ICMP request
            if ip_header.protocol is IPProtocol.ICMP and packet.get_header(ICMP).icmptype is ICMPType.EchoRequest:
                icmp_reply = self.make_icmp_packet(recv, icmp_type=ICMPType.EchoReply)
                self.handle_packet((timestamp, ifaceName, icmp_reply))
            # ICMP error
            else:
                icmp_error = self.make_icmp_packet(
                    recv, 
                    icmp_type=ICMPType.DestinationUnreachable,
                    icmp_code=ICMPTypeCodeMap[ICMPType.DestinationUnreachable].PortUnreachable
                )
                self.handle_packet((timestamp, ifaceName, icmp_error))
            return

        
        match_entry = self.forwarding_table.match(ip_header.dst)
        # If there is no match in the table, send an ICMP destination unreachable
        if match_entry is None:
            icmp_error = self.make_icmp_packet(
                recv, 
                icmp_type=ICMPType.DestinationUnreachable, 
                icmp_code=ICMPTypeCodeMap[ICMPType.DestinationUnreachable].NetworkUnreachable
            )
            self.handle_packet((timestamp, ifaceName, icmp_error))
            return
        forward_ip = (match_entry.next_hop_ip 
                    if match_entry.next_hop_ip != IPv4Address('0.0.0.0')
                    else ip_header.dst)
        
        ip_header.ttl -= 1
        # if ttl is 0, send icmp time exceeded
        if ip_header.ttl <= 0:
            icmp_error = self.make_icmp_packet(
                recv, 
                icmp_type=ICMPType.TimeExceeded,
                icmp_code=ICMPTypeCodeMap[ICMPType.TimeExceeded].TTLExpired
            )
            self.handle_packet((timestamp, ifaceName, icmp_error))
            return
        
        # the mac is unknown, send Relevant information into waiting_queue(dict)
        if forward_ip not in self.arp_tab:
            if self.muti_thread:
                self.lock.acquire()
            if forward_ip not in self.waiting_packets:
                self.waiting_packets[forward_ip] = [[recv], match_entry.interface, time.time() - 1, 0]
            else:
                self.waiting_packets[forward_ip][0].append(recv)
            if self.muti_thread:
                self.lock.release()
            return
        # If there is a match, forward the packet
        self.forward_packet(packet, self.arp_tab[forward_ip], match_entry.interface)


    def make_arp_request(self) -> None:
        """ make arp request according to the waiting_queue """
        re = True
        while re:
            if self.muti_thread:
                self.lock.acquire()
            time_out_record = []
            icmp_errors = []
            for next_hop_ip, (recv_packets, forward_interface, timestamp, times) in self.waiting_packets.items():
                # we have tried 5 times, drop the packet
                if times >= 5:
                    # del self.waiting_packets[next_hop_ip]
                    time_out_record.append(next_hop_ip)
                    # send icmp error
                    for timestamp, ifaceName, packet in recv_packets:
                        icmp_error = self.make_icmp_packet(
                            (timestamp, ifaceName, packet), 
                            icmp_type=ICMPType.DestinationUnreachable, 
                            icmp_code=ICMPTypeCodeMap[ICMPType.DestinationUnreachable].HostUnreachable
                        )
                        icmp_errors.append(icmp_error)
                # make a request every 1 second
                elif time.time() - timestamp >= 1.0:
                    sender_mac = self.net.interface_by_name(forward_interface).ethaddr
                    sender_ip = self.net.interface_by_name(forward_interface).ipaddr
                    arp_request = create_ip_arp_request(sender_mac, sender_ip, next_hop_ip)
                    self.net.send_packet(forward_interface, arp_request)
                    self.waiting_packets[next_hop_ip] = [recv_packets, forward_interface, time.time(), times + 1]
            # avoid changing size while iterating
            for next_hop_ip in time_out_record:
                del self.waiting_packets[next_hop_ip]
            if self.muti_thread:
                self.lock.release()
            for icmp_error in icmp_errors:
                self.handle_packet((None, None, icmp_error))
            re = self.muti_thread
            # if self.muti_thread:
                # time.sleep(0.5)

    def make_icmp_packet(self, ori_recv: switchyard.llnetbase.ReceivedPacket, icmp_code=None, icmp_type=None) -> switchyard.lib.packet.Packet:
        """ make a icmp packet """
        timestamp, ifaceName, ori_packet = ori_recv
        icmp_header = ICMP()
        ipv4_header = IPv4()
        ipv4_header.protocol = IPProtocol.ICMP
        ipv4_header.ttl = 64 + 1 # ttl will decrease by 1 in handle_packet()
        ethernet_header = Ethernet()
        if icmp_type is ICMPType.EchoReply:
            # just swap the src and dst mac and ip
            ipv4_header.src = ori_packet.get_header(IPv4).dst
            ipv4_header.dst = ori_packet.get_header(IPv4).src
            request_icmp_header = ori_packet.get_header(ICMP)
            icmp_header.icmpdata = ICMPEchoReply()
            icmp_header.icmpdata.data = request_icmp_header.icmpdata.data
            icmp_header.icmpdata.identifier = request_icmp_header.icmpdata.identifier
            icmp_header.icmpdata.sequence = request_icmp_header.icmpdata.sequence
            ethernet_header.src = ori_packet.get_header(Ethernet).dst
            ethernet_header.dst = ori_packet.get_header(Ethernet).src
        else:
            # need to set src according to the interface of router
            ipv4_header.src = self.net.interface_by_name(ifaceName).ipaddr
            ipv4_header.dst = ori_packet.get_header(IPv4).src
            icmp_header.icmptype = icmp_type
            icmp_header.icmpcode = icmp_code
            ethernet_header.src = self.net.interface_by_name(ifaceName).ethaddr
            ethernet_header.dst = ori_packet.get_header(Ethernet).src
            # we need first 28 bytes from ipv4 header, so ethernet_header has to be deleted
            del ori_packet[Ethernet]
            icmp_header.icmpdata.data = ori_packet.to_bytes()[:28]
            # restore ethernet header of original packet
            ori_packet.prepend_header(ethernet_header)
        return ethernet_header + ipv4_header + icmp_header

    
    def forward_packet(self, packet, dst_mac, iface) -> None:
        eth_header = packet.get_header(Ethernet)
        if eth_header is None:
            return
        # Ethernet src also needs to be updated, 
        # since the packet will enter another network.
        eth_header.src = self.net.interface_by_name(iface).ethaddr
        eth_header.dst = dst_mac
        self.net.send_packet(iface, packet)
        

    def start(self):
        """
        A running daemon of the router.
        Receive packets until the end of time.
        """
        while True:
            try:
                recv_pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                # We should send arp request, 
                # since last request may be lost
                if not self.muti_thread:
                    self.make_arp_request()
                continue
            except Shutdown:
                break

            timestamp, ifaceName, packet = recv_pkt
            if packet.has_header(Arp):
                self.handle_arp(recv_pkt)
            else:
                self.handle_packet(recv_pkt)
            if not self.muti_thread:
                self.make_arp_request()

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    """
    Main entry point for router.  Just create Router
    object and get it going.
    """
    router = Router(net)
    router.start()
