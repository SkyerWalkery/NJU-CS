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
    def __init__(self, file: str = None, router_interfaces = None):
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
        ''' find an entry to macth the given IP address '''
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
        # (ip: [packets, forward_interface, timestamp, times of arp request])
        self.waiting_packets = dict() 

        # mutiple thread supported
        # To activate mutiple thread, set self.muti_thread = True
        self.lock = threading.RLock()
        self.arp_req_thread = threading.Thread(target=self.make_arp_request)
        self.start_thread = threading.Thread(target=self.start)
        self.muti_thread = False
        if self.muti_thread:
            self.arp_req_thread.start()
            self.start_thread.start()


    def print_arp_tab(self) -> None:
        ''' for test, print the arp table '''
        print("ARP Table:")
        for ip, mac in self.arp_tab.items():
            print(f"{ip} -> {mac}")
        print()


    def handle_arp(self, recv: switchyard.llnetbase.ReceivedPacket) -> None:
        ''' handle an arp packet '''
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
                packets, forward_interface, timestamp, times = self.waiting_packets[arp.senderprotoaddr]
                for packet in packets: 
                    self.forward_packet(packet, arp.senderhwaddr, forward_interface)
                del self.waiting_packets[arp.senderprotoaddr]
            if self.muti_thread:
                self.lock.release()


    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket) -> None:
        ''' handle a non-arp packet '''
        timestamp, ifaceName, packet = recv
        ip_header = packet.get_header(IPv4)
        if ip_header is None:
            return
        ip_header.ttl -= 1

        # Check if the packet is destined for this router, drop it
        if ip_header.dst in [iface.ipaddr for iface in self.net.interfaces()]:
            return

        match_entry = self.forwarding_table.match(ip_header.dst)
        # If there is no match in the table, just drop the packet
        if match_entry is None:
            return
        forward_ip = (match_entry.next_hop_ip 
                    if match_entry.next_hop_ip != IPv4Address('0.0.0.0')
                    else ip_header.dst)
        # the mac is unknown, send Relevant information into waiting_queue(dict)
        if forward_ip not in self.arp_tab:
            if self.muti_thread:
                self.lock.acquire()
            if forward_ip not in self.waiting_packets:
                self.waiting_packets[forward_ip] = [[packet], match_entry.interface, time.time() - 1, 0]
            else:
                self.waiting_packets[forward_ip][0].append(packet)
            if self.muti_thread:
                self.lock.release()
            return
        # If there is a match, forward the packet
        self.forward_packet(packet, self.arp_tab[forward_ip], match_entry.interface)


    def make_arp_request(self) -> None:
        if self.muti_thread:
            while True:
                self.lock.acquire()
                time_out_record = []
                for next_hop_ip, (packets, forward_interface, timestamp, times) in self.waiting_packets.items():
                    if times >= 5:
                        # del self.waiting_packets[next_hop_ip]
                        time_out_record.append(next_hop_ip)
                    elif time.time() - timestamp >= 1.0:
                        sender_mac = self.net.interface_by_name(forward_interface).ethaddr
                        sender_ip = self.net.interface_by_name(forward_interface).ipaddr
                        arp_request = create_ip_arp_request(sender_mac, sender_ip, next_hop_ip)
                        self.net.send_packet(forward_interface, arp_request)
                        self.waiting_packets[next_hop_ip] = [packets, forward_interface, time.time(), times + 1]
                for next_hop_ip in time_out_record:
                    del self.waiting_packets[next_hop_ip]
                self.lock.release()
                # time.sleep(0.5)
        else:
            time_out_record = []
            for next_hop_ip, (packets, forward_interface, timestamp, times) in self.waiting_packets.items():
                # we have tried 5 times, drop the packet
                if times >= 5:
                    # del self.waiting_packets[next_hop_ip]
                    time_out_record.append(next_hop_ip)
                # make a request every 1 second
                elif time.time() - timestamp >= 1.0:
                    sender_mac = self.net.interface_by_name(forward_interface).ethaddr
                    sender_ip = self.net.interface_by_name(forward_interface).ipaddr
                    arp_request = create_ip_arp_request(sender_mac, sender_ip, next_hop_ip)
                    self.net.send_packet(forward_interface, arp_request)
                    self.waiting_packets[next_hop_ip] = [packets, forward_interface, time.time(), times + 1]
            # avoid delete while iterating
            for next_hop_ip in time_out_record:
                del self.waiting_packets[next_hop_ip]

    
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
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''

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
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
