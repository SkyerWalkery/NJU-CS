import time
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


def test_hub():
    s = TestScenario("switch_LRU tests")
    s.add_interface('eth0', '10:00:00:00:00:01')
    s.add_interface('eth1', '10:00:00:00:00:02')
    s.add_interface('eth2', '10:00:00:00:00:03')

    # test case 1: a frame with broadcast destination should get sent out
    # all ports except ingress
    testpkt = new_packet(
        "30:00:00:00:00:01",
        "ff:ff:ff:ff:ff:ff",
        "172.16.42.2",
        "255.255.255.255"
    )
    s.expect(
        PacketInputEvent("eth1", testpkt, display=Ethernet),
        ("An Ethernet frame with a broadcast destination address "
         "should arrive on eth1")
    )
    s.expect(
        PacketOutputEvent("eth0", testpkt, "eth2", testpkt, display=Ethernet),
        ("The Ethernet frame with a broadcast destination address should be "
         "forwarded out ports eth0 and eth2")
    )

    # test case 2: a frame with any unicast address except one assigned to hub
    # interface should be sent out one port after self-learning
    reqpkt = new_packet(
        "20:00:00:00:00:01",
        "30:00:00:00:00:01",
        '192.168.1.100',
        '172.16.42.2'
    )
    s.expect(
        PacketInputEvent("eth2", reqpkt, display=Ethernet),
        ("An Ethernet frame from 20:00:00:00:00:01 to 30:00:00:00:00:01 "
         "should arrive on eth2")
    )
    s.expect(
        PacketOutputEvent("eth1", reqpkt, display=Ethernet),
        ("Ethernet frame destined for 30:00:00:00:00:01 should arrive"
         "on eth1 after self-learning")
    )

    # test case 3: 4 more packets with different mac addresses
    for i in range(4):
        hw_src = '40:00:00:00:00:0' + str(i)
        hw_dst = '50:00:00:00:00:0' + str(i)
        ip_src = '192.168.127.' + str(i)
        ip_dst = '192.168.128.' + str(i)
        reqpkt = new_packet(hw_src, hw_dst, ip_src, ip_dst)
        s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet), (''))
        s.expect(PacketOutputEvent("eth1", reqpkt, "eth2", reqpkt, display=Ethernet),(''))

    # test case 4: the entry whose mac is 30:00:00:00:00:01 should be erased
    reqpkt = new_packet(
        "20:00:00:00:00:01",
        "30:00:00:00:00:01",
        '192.168.1.100',
        '172.16.42.2'
    )
    s.expect(
        PacketInputEvent("eth2", reqpkt, display=Ethernet),
        ("An Ethernet frame from 20:00:00:00:00:01 to 30:00:00:00:00:01 "
         "should arrive on eth2")
    )
    s.expect(
        PacketOutputEvent("eth0", reqpkt, "eth1", reqpkt, display=Ethernet),
        ("the entry whose mac is 30:00:00:00:00:01 should have been erased ")
    )
    

    return s


scenario = test_hub()
