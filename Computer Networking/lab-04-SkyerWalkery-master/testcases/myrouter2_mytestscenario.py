from switchyard.lib.userlib import *


def new_packet(hwsrc, hwdst, ipsrc, ipdst, reply=False):
    ether = Ethernet(src=hwsrc, dst=hwdst, ethertype=EtherType.IP)
    ippkt = IPv4(src=ipsrc, dst=ipdst, protocol=IPProtocol.ICMP, ttl=32)
    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest
    return ether + ippkt + icmppkt

def new_arp_packet(hwsrc, hwdst, ipsrc, ipdst, reply=False):
    ether = Ethernet(src=hwsrc, dst=hwdst, ethertype=EtherType.ARP)
    arppkt = None
    arppkt = Arp(
        operation=ArpOperation.Reply if reply else ArpOperation.Request,
        senderhwaddr=hwsrc, 
        senderprotoaddr=ipsrc, 
        targethwaddr=hwdst, 
        targetprotoaddr=ipdst
    )
    return ether + arppkt


def test_hub():
    s = TestScenario("router tests")
    forward_table = (
        "192.168.1.0 255.255.255.0 192.168.1.100 router-eth1\n"
        "192.168.1.252 255.255.255.252 192.168.1.253 router-eth0\n"
        "192.168.3.0 255.255.255.0 192.168.3.100 router-eth2\n"
    )
    with open('forwarding_table.txt', 'w+') as f:
        f.write(forward_table)
    hosts = (
        {'mac':'20:00:00:00:00:11', 'ip':'192.168.1.253'},
        {'mac':'20:00:00:00:00:01', 'ip':'192.168.1.100'},
        {'mac':'20:00:00:00:00:03', 'ip':'192.168.3.100'},
    )
    ifaces = (
        {'name':'router-eth0', 'mac':'10:00:00:00:00:11', 'ip':'192.168.1.254'},
        {'name':'router-eth1', 'mac':'10:00:00:00:00:01', 'ip':'192.168.1.101'},
        {'name':'router-eth2', 'mac':'10:00:00:00:00:03', 'ip':'192.168.3.101'},
    )
    s.add_interface(ifaces[0]['name'], ifaces[0]['mac'], ipaddr=ifaces[0]['ip'])
    s.add_interface(ifaces[1]['name'], ifaces[1]['mac'], ipaddr=ifaces[1]['ip'])
    s.add_interface(ifaces[2]['name'], ifaces[2]['mac'], ipaddr=ifaces[2]['ip'])

    # test case 1: an ARP request from hosts[0] to router-eth1
    # a reply should be sent to hosts[0]
    # other hosts should not receive the packet
    reqpkt = new_arp_packet(
        hosts[0]['mac'],
        'ff:ff:ff:ff:ff:ff',
        hosts[0]['ip'],
        ifaces[1]['ip'],
    )
    reppkt = new_arp_packet(
        ifaces[1]['mac'],
        hosts[0]['mac'],
        ifaces[1]['ip'],
        hosts[0]['ip'],
        reply=True
    )
    # 1 - 3
    s.expect(PacketInputEvent("router-eth0", reqpkt), ("An ARP request should arrive on router-eth0"))
    s.expect(PacketOutputEvent("router-eth0", reppkt),("An ARP reply should arrive on router-eth0"))
    s.expect(PacketInputTimeoutEvent(2.0), ("Other hosts should not receive any packet"))


    # test case 2: a IPv4 packet from hosts[2] to hosts[0]
    # the router should just forward the packet, since arp cache has info of hosts[0]
    in_pkt = new_packet(
        hosts[2]['mac'],
        ifaces[2]['mac'],
        hosts[2]['ip'],
        hosts[0]['ip'],
    )
    out_pkt = new_packet(
        ifaces[0]['mac'],
        hosts[0]['mac'],
        hosts[2]['ip'],
        hosts[0]['ip'],
    )
    out_pkt[IPv4].ttl -= 1
    # 4 - 6
    s.expect(PacketInputEvent("router-eth2", in_pkt), ("A packet should arrive on router-eth2"))
    s.expect(PacketOutputEvent("router-eth0", out_pkt), ("A packet should be forwarded out router-eth0"))
    s.expect(PacketInputTimeoutEvent(2.1), ("Other hosts should not receive any packet"))

    # test case 3: a IPv4 packet from hosts[0] to hosts[1]
    # the router should make arp request, since arp cache has no info of hosts[1]
    in_pkt = new_packet(
        hosts[0]['mac'],
        ifaces[0]['mac'],
        hosts[0]['ip'],
        hosts[1]['ip'],
    )
    arp_request = new_arp_packet(
        ifaces[1]['mac'],
        'ff:ff:ff:ff:ff:ff',
        ifaces[1]['ip'],
        hosts[1]['ip'],
    )
    arp_reply = new_arp_packet(
        hosts[1]['mac'],
        ifaces[1]['mac'],
        hosts[1]['ip'],
        ifaces[1]['ip'],
        reply=True
    )
    out_pkt = new_packet(
        ifaces[1]['mac'],
        hosts[1]['mac'],
        hosts[0]['ip'],
        hosts[1]['ip'],
    )
    out_pkt[IPv4].ttl -= 1
    # 7 - 11
    s.expect(PacketInputEvent("router-eth0", in_pkt), ("A packet should arrive on router-eth0"))
    s.expect(PacketOutputEvent("router-eth1", arp_request), ("An ARP request should be sent out router-eth1"))
    s.expect(PacketInputEvent("router-eth1", arp_reply), ("An ARP reply should arrive on router-eth1"))
    s.expect(PacketOutputEvent("router-eth1", out_pkt), ("A packet should be forwarded out router-eth1"))
    s.expect(PacketInputTimeoutEvent(5.1), ("Other hosts should not receive any packet"))
    
    # test case 4: a IPv4 packet from hosts[2] to hosts[1]
    # the router should just forward the packet, since arp cache has info of hosts[1]
    in_pkt = new_packet(
        hosts[2]['mac'],
        ifaces[2]['mac'],
        hosts[2]['ip'],
        hosts[1]['ip'],
    )
    out_pkt = new_packet(
        ifaces[1]['mac'],
        hosts[1]['mac'],
        hosts[2]['ip'],
        hosts[1]['ip'],
    )
    out_pkt[IPv4].ttl -= 1
    # 12 - 14
    s.expect(PacketInputEvent("router-eth2", in_pkt), ("A packet should arrive on router-eth2"))
    s.expect(PacketOutputEvent("router-eth1", out_pkt), ("A packet should be forwarded out router-eth1"))
    s.expect(PacketInputTimeoutEvent(2.1), ("Other hosts should not receive any packet"))

    # test case 5: a IPv4 packet from hosts[0] to hosts[2]
    # the router should make arp request, since arp cache has no info of hosts[2]
    # but hosts[2] won't reply, so the router should timeout and resend the packet for 5 times
    # after the 5th time, the packet should be dropped
    in_pkt = new_packet(
        hosts[0]['mac'],
        ifaces[0]['mac'],
        hosts[0]['ip'],
        hosts[2]['ip'],
    )
    arp_request = new_arp_packet(
        ifaces[2]['mac'],
        'ff:ff:ff:ff:ff:ff',
        ifaces[2]['ip'],
        hosts[2]['ip'],
    )
    # 15 - 21
    s.expect(PacketInputEvent("router-eth0", in_pkt), ("A packet should arrive on router-eth0"))
    s.expect(PacketOutputEvent("router-eth2", arp_request), ("An ARP request should be sent out router-eth2"))
    s.expect(PacketOutputEvent("router-eth2", arp_request), ("resend ARP request"))
    s.expect(PacketOutputEvent("router-eth2", arp_request), ("resend ARP request"))
    s.expect(PacketOutputEvent("router-eth2", arp_request), ("resend ARP request"))
    s.expect(PacketOutputEvent("router-eth2", arp_request), ("resend ARP request"))
    s.expect(PacketInputTimeoutEvent(5.1), ("Packet should be dropped, the router will nerver request"))

    return s


scenario = test_hub()