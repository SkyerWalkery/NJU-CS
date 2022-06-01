from switchyard.lib.userlib import *


def new_packet(hwsrc, hwdst, ipsrc, ipdst, ip_ttl=64):
    ether = Ethernet(src=hwsrc, dst=hwdst, ethertype=EtherType.IP)
    ippkt = IPv4(src=ipsrc, dst=ipdst, protocol=IPProtocol.UDP, ttl=ip_ttl)
    return ether + ippkt + UDP(src=5555, dst=8888) + b'some payload'

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

def new_icmp_packet(hwsrc, hwdst, ipsrc, ipdst, icmp_type, icmp_code, icmp_data):
    ether = Ethernet(src=hwsrc, dst=hwdst, ethertype=EtherType.IP)
    ippkt = IPv4(src=ipsrc, dst=ipdst, protocol=IPProtocol.ICMP, ttl=64)
    icmppkt = ICMP()
    icmppkt.icmpdata = icmp_data
    icmppkt.icmptype = icmp_type
    icmppkt.icmpcode = icmp_code
    return ether + ippkt + icmppkt

def make_icmp_data(ori_pkt) -> bytes:
    ether = ori_pkt.get_header(Ethernet)
    del ori_pkt[Ethernet]
    ret = ori_pkt.to_bytes()[:28]
    ori_pkt.prepend_header(ether)
    return ret
    


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
    arp_reqpkt = new_arp_packet(
        hosts[0]['mac'],
        'ff:ff:ff:ff:ff:ff',
        hosts[0]['ip'],
        ifaces[1]['ip'],
    )
    arp_reppkt = new_arp_packet(
        ifaces[1]['mac'],
        hosts[0]['mac'],
        ifaces[1]['ip'],
        hosts[0]['ip'],
        reply=True
    )
    # 1 - 3
    s.expect(PacketInputEvent("router-eth0", arp_reqpkt), ("An ARP request should arrive on router-eth0"))
    s.expect(PacketOutputEvent("router-eth0", arp_reppkt),("An ARP reply should arrive on router-eth0"))
    s.expect(PacketInputTimeoutEvent(2.0), ("Other hosts should not receive any packet"))


    # test case 2: hosts[0] sends an ICMP echo request to router.
    # the router should reply with an ICMP echo reply.
    # other hosts should not receive the packet
    icmp_data = ICMPEchoRequest()
    icmp_data.sequence, icmp_data.identifier, icmp_data.data = 11204, 31112, 'Hi'
    icmp_reqpkt = new_icmp_packet(
        hosts[0]['mac'],
        ifaces[0]['mac'],
        hosts[0]['ip'],
        ifaces[0]['ip'],
        ICMPType.EchoRequest,
        ICMPTypeCodeMap[ICMPType.EchoRequest].EchoRequest,
        icmp_data
    )
    icmp_data = ICMPEchoReply()
    icmp_data.sequence, icmp_data.identifier, icmp_data.data = 11204, 31112, 'Hi'
    icmp_reppkt = new_icmp_packet(
        ifaces[0]['mac'],
        hosts[0]['mac'],
        ifaces[0]['ip'],
        hosts[0]['ip'],
        ICMPType.EchoReply,
        ICMPTypeCodeMap[ICMPType.EchoReply].EchoReply,
        icmp_data
    )
    # 4 - 6
    s.expect(PacketInputEvent("router-eth0", icmp_reqpkt), ("An ICMP echo request should arrive on router-eth0"))
    s.expect(PacketOutputEvent("router-eth0", icmp_reppkt),("An ICMP echo reply should arrive on router-eth0"))
    s.expect(PacketInputTimeoutEvent(2.0), ("Other hosts should not receive any packet"))


    # test case 3: hosts[1] sends an ICMP echo request to router.
    # the router should make an ARP request, since mac of hosts[1] is unknown.
    # after reveive an ARP reply, the router should reply with an ICMP echo reply.
    icmp_data = ICMPEchoRequest()
    icmp_data.sequence, icmp_data.identifier, icmp_data.data = 4455, 6677, 'Ah'
    icmp_reqpkt = new_icmp_packet(
        hosts[1]['mac'],
        ifaces[1]['mac'],
        hosts[1]['ip'],
        ifaces[1]['ip'],
        ICMPType.EchoRequest,
        ICMPTypeCodeMap[ICMPType.EchoRequest].EchoRequest,
        icmp_data
    )
    icmp_data = ICMPEchoReply()
    icmp_data.sequence, icmp_data.identifier, icmp_data.data = 4455, 6677, 'Ah'
    icmp_reppkt = new_icmp_packet(
        ifaces[1]['mac'],
        hosts[1]['mac'],
        ifaces[1]['ip'],
        hosts[1]['ip'],
        ICMPType.EchoReply,
        ICMPTypeCodeMap[ICMPType.EchoReply].EchoReply,
        icmp_data
    )
    arp_reqpkt = new_arp_packet(
        ifaces[1]['mac'],
        'ff:ff:ff:ff:ff:ff',
        ifaces[1]['ip'],
        hosts[1]['ip'],
    )
    arp_reppkt = new_arp_packet(
        hosts[1]['mac'],
        ifaces[1]['mac'],
        hosts[1]['ip'],
        ifaces[1]['ip'],
        reply=True
    )
    # 7 - 11
    s.expect(PacketInputEvent("router-eth1", icmp_reqpkt), ("An ICMP echo request should arrive on router-eth1"))
    s.expect(PacketOutputEvent("router-eth1", arp_reqpkt),("An ARP request should arrive on router-eth1"))
    s.expect(PacketInputEvent("router-eth1", arp_reppkt),("An ARP reply should arrive on router-eth1"))
    s.expect(PacketOutputEvent("router-eth1", icmp_reppkt),("An ICMP echo reply should arrive on router-eth1"))
    s.expect(PacketInputTimeoutEvent(2.0), ("Other hosts should not receive any packet"))


    # test case 4: hosts[1] sends an IPv4 packet to ifaces[1]
    # the router should send an icmp error, and drop the packet
    ip_pkt = new_packet(
        hosts[1]['mac'],
        ifaces[1]['mac'],
        hosts[1]['ip'],
        ifaces[1]['ip']
    )
    icmp_data = ICMPDestinationUnreachable()
    # ip_pkt[IPv4].ttl -= 1
    icmp_data.data = make_icmp_data(ip_pkt)
    # ip_pkt[IPv4].ttl += 1
    icmp_pkt = new_icmp_packet(
        ifaces[1]['mac'],
        hosts[1]['mac'],
        ifaces[1]['ip'],
        hosts[1]['ip'],
        ICMPType.DestinationUnreachable,
        ICMPTypeCodeMap[ICMPType.DestinationUnreachable].PortUnreachable,
        icmp_data
    )
    # 12 - 14
    s.expect(PacketInputEvent("router-eth1", ip_pkt), ("An IPv4 packet should arrive on router-eth1"))
    s.expect(PacketOutputEvent("router-eth1", icmp_pkt),("An ICMP error should arrive on router-eth1"))
    s.expect(PacketInputTimeoutEvent(2.0), ("Other hosts should not receive any packet"))


    # test case 5: hosts[1] sends an IPv4 packet to hosts[2], but its ttl is only 1
    # the router should send an icmp error, and drop the packet
    ip_pkt = new_packet(
        hosts[1]['mac'],
        ifaces[1]['mac'],
        hosts[1]['ip'],
        hosts[2]['ip'],
        ip_ttl=1
    )
    icmp_data = ICMPTimeExceeded()
    ip_pkt[IPv4].ttl -= 1
    icmp_data.data = make_icmp_data(ip_pkt)
    ip_pkt[IPv4].ttl += 1
    icmp_pkt = new_icmp_packet(
        ifaces[1]['mac'],
        hosts[1]['mac'],
        ifaces[1]['ip'],
        hosts[1]['ip'],
        ICMPType.TimeExceeded,
        ICMPTypeCodeMap[ICMPType.TimeExceeded].TTLExpired,
        icmp_data
    )
    # 15 - 17
    s.expect(PacketInputEvent("router-eth1", ip_pkt), ("An IPv4 packet should arrive on router-eth1"))
    s.expect(PacketOutputEvent("router-eth1", icmp_pkt),("An ICMP error should arrive on router-eth1"))
    s.expect(PacketInputTimeoutEvent(2.0), ("Other hosts should not receive any packet"))


    # test case 6: hosts[1] sends an IPv4 packet to a non-existent host
    # the router should send an icmp error, and drop the packet
    ip_pkt = new_packet(
        hosts[1]['mac'],
        ifaces[1]['mac'],
        hosts[1]['ip'],
        '123.122.121.120'
    )
    icmp_data = ICMPDestinationUnreachable()
    # ip_pkt[IPv4].ttl -= 1
    icmp_data.data = make_icmp_data(ip_pkt)
    # ip_pkt[IPv4].ttl += 1
    icmp_pkt = new_icmp_packet(
        ifaces[1]['mac'],
        hosts[1]['mac'],
        ifaces[1]['ip'],
        hosts[1]['ip'],
        ICMPType.DestinationUnreachable,
        ICMPTypeCodeMap[ICMPType.DestinationUnreachable].NetworkUnreachable,
        icmp_data
    )
    # 18 - 20
    s.expect(PacketInputEvent("router-eth1", ip_pkt), ("An IPv4 packet should arrive on router-eth1"))
    s.expect(PacketOutputEvent("router-eth1", icmp_pkt),("An ICMP error should arrive on router-eth1"))
    s.expect(PacketInputTimeoutEvent(2.0), ("Other hosts should not receive any packet"))


    # test case 7: hosts[0] and hosts[1] send IPv4 packets to hosts[2]
    # the router should make ARP requests
    # out of some reason, hosts[2] doesn't reply
    # after trying for 5 times, 
    # the router should send an icmp error to hosts[0] and hosts[1], and drop the packet
    ip_pkt0 = new_packet(
        hosts[0]['mac'],
        ifaces[0]['mac'],
        hosts[0]['ip'],
        hosts[2]['ip']
    )
    ip_pkt1 = new_packet(
        hosts[1]['mac'],
        ifaces[1]['mac'],
        hosts[1]['ip'],
        hosts[2]['ip']
    )
    arp_reqpkt = new_arp_packet(
        ifaces[2]['mac'],
        'ff:ff:ff:ff:ff:ff',
        ifaces[2]['ip'],
        hosts[2]['ip']
    )
    icmp_data0 = ICMPDestinationUnreachable()
    ip_pkt0[IPv4].ttl -= 1
    icmp_data0.data = make_icmp_data(ip_pkt0)
    ip_pkt0[IPv4].ttl += 1
    icmp_data1 = ICMPDestinationUnreachable()
    ip_pkt1[IPv4].ttl -= 1
    icmp_data1.data = make_icmp_data(ip_pkt1)
    ip_pkt1[IPv4].ttl += 1
    icmp_pkt0 = new_icmp_packet(
        ifaces[0]['mac'],
        hosts[0]['mac'],
        ifaces[0]['ip'],
        hosts[0]['ip'],
        ICMPType.DestinationUnreachable,
        ICMPTypeCodeMap[ICMPType.DestinationUnreachable].HostUnreachable,
        icmp_data0
    )
    icmp_pkt1 = new_icmp_packet(
        ifaces[1]['mac'],
        hosts[1]['mac'],
        ifaces[1]['ip'],
        hosts[1]['ip'],
        ICMPType.DestinationUnreachable,
        ICMPTypeCodeMap[ICMPType.DestinationUnreachable].HostUnreachable,
        icmp_data1
    )
    # 21 - 29
    s.expect(PacketInputEvent("router-eth0", ip_pkt0), ("An IPv4 packet should arrive on router-eth0"))
    s.expect(PacketOutputEvent("router-eth2", arp_reqpkt),("An ARP request should arrive on router-eth2"))
    s.expect(PacketInputEvent("router-eth1", ip_pkt1), ("An IPv4 packet should arrive on router-eth1"))
    s.expect(PacketOutputEvent("router-eth2", arp_reqpkt),("router should resend ARP request"))
    s.expect(PacketOutputEvent("router-eth2", arp_reqpkt),("router should resend ARP request"))
    s.expect(PacketOutputEvent("router-eth2", arp_reqpkt),("router should resend ARP request"))
    s.expect(PacketOutputEvent("router-eth2", arp_reqpkt),("router should resend ARP request"))
    s.expect(PacketOutputEvent("router-eth0", icmp_pkt0),("An ICMP error should arrive on router-eth0"))
    s.expect(PacketOutputEvent("router-eth1", icmp_pkt1),("An ICMP error should arrive on router-eth1"))
    s.expect(PacketInputTimeoutEvent(2.0), ("Other hosts should not receive any packet"))

    
    return s


scenario = test_hub()