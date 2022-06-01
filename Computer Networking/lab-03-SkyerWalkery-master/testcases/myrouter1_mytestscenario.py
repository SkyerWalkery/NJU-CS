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
    s.add_interface('eth0', '10:00:00:00:00:01', ipaddr='192.168.1.1')
    s.add_interface('eth1', '10:00:00:00:00:02', ipaddr='192.168.1.2')
    s.add_interface('eth2', '10:00:00:00:00:03', ipaddr='192.168.1.3')

    hosts = (
        {'mac':'20:00:00:00:00:01', 'ip':'172.16.42.1'},
        {'mac':'20:00:00:00:00:02', 'ip':'172.16.42.2'},
        {'mac':'20:00:00:00:00:03', 'ip':'172.16.42.3'},
    )

    # test case 1: an ARP request from hosts[0] to eth1
    # a reply should be sent to hosts[0]
    # other hosts should not receive the packet
    reqpkt = new_arp_packet(
        hosts[0]['mac'],
        'ff:ff:ff:ff:ff:ff',
        hosts[0]['ip'],
        '192.168.1.2'
    )
    reppkt = new_arp_packet(
        '10:00:00:00:00:02',
        hosts[0]['mac'],
        '192.168.1.2',
        hosts[0]['ip'],
        reply=True
    )
    s.expect(PacketInputEvent("eth0", reqpkt), ("An ARP request should arrive on eth0"))
    s.expect(PacketOutputEvent("eth0", reppkt),("An ARP reply should arrive on eth0"))
    s.expect(PacketInputTimeoutEvent(2.0), ("Other hosts should not receive any packet"))

    # test case 2: a non-ARP packet should be dropped
    testpkt = new_packet(
        hosts[0]['mac'],
        hosts[1]['mac'],
        hosts[0]['ip'],
        hosts[1]['ip']
    )
    s.expect(PacketInputEvent("eth0", testpkt), ("A non-ARP packet should arrive on eth0"))
    s.expect(PacketInputTimeoutEvent(2.0), ("The packet should be dropped"))

    # test case 3: an ARP reply from hosts[1] to eth0
    # it should be dropped
    reppkt = new_arp_packet(
        hosts[0]['mac'],
        '10:00:00:00:00:02',
        hosts[0]['ip'],
        '192.168.1.1',
        reply=True
    )
    s.expect(PacketInputEvent("eth0", reppkt), ("An ARP reply should arrive on eth0"))
    s.expect(PacketInputTimeoutEvent(2.0), ("The packet should be dropped"))

    return s


scenario = test_hub()