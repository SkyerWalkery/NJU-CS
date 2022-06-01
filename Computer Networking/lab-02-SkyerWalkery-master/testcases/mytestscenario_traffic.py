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


##########################################################
# Attention: The test is for switch with table size of 2 #
##########################################################


def test_hub():
    s = TestScenario("switch_traffic_volume tests")
    s.add_interface('eth0', '10:00:00:00:00:01')
    s.add_interface('eth1', '10:00:00:00:00:02')
    s.add_interface('eth2', '10:00:00:00:00:03')

    # test case 1: a frame with broadcast destination should get sent out
    # all ports except ingress
    # 2 frames at all, from different ports
    testpkt = new_packet(
        "30:00:00:00:00:00",
        "ff:ff:ff:ff:ff:ff",
        "172.16.42.0",
        "255.255.255.255"
    )
    s.expect(
        PacketInputEvent("eth0", testpkt, display=Ethernet),
        ("An Ethernet frame with a broadcast destination address "
         "should arrive on eth0")
    )
    s.expect(
        PacketOutputEvent("eth1", testpkt, "eth2", testpkt, display=Ethernet),
        ("The Ethernet frame with a broadcast destination address should be "
         "forwarded out ports eth1 and eth2")
    )
    testpkt = new_packet(
        "30:00:00:00:00:01",
        "ff:ff:ff:ff:ff:ff",
        "172.16.42.1",
        "255.255.255.255"
    )
    s.expect(
        PacketInputEvent("eth1", testpkt, display=Ethernet),
        ("An Ethernet frame with a broadcast destination address "
         "should arrive on eth0")
    )
    s.expect(
        PacketOutputEvent("eth0", testpkt, "eth2", testpkt, display=Ethernet),
        ("The Ethernet frame with a broadcast destination address should be "
         "forwarded out ports eth0 and eth2")
    )

    # test case 2: a frame with any unicast address except one assigned to hub
    # interface should be sent out one port after self-learning
    # increase volume of (30:00:00:00:00:01, eth1)
    reqpkt = new_packet(
        "30:00:00:00:00:00",
        "30:00:00:00:00:01",
        '172.16.42.0',
        '172.16.42.1'
    )
    s.expect(
        PacketInputEvent("eth0", reqpkt, display=Ethernet),
        ("An Ethernet frame from 30:00:00:00:00:00 to 30:00:00:00:00:01 "
         "should arrive on eth0")
    )
    s.expect(
        PacketOutputEvent("eth1", reqpkt, display=Ethernet),
        ("Ethernet frame destined for 30:00:00:00:00:01 should arrive"
         "on eth1 after self-learning")
    )

    # test case 3: a frame from a new port
    # (30:00:00:00:00:00, eth0) should be erased from table
    testpkt = new_packet(
        "30:00:00:00:00:02",
        "ff:ff:ff:ff:ff:ff",
        "172.16.42.2",
        "255.255.255.255"
    )
    s.expect(
        PacketInputEvent("eth2", testpkt, display=Ethernet),
        ("An Ethernet frame with a broadcast destination address "
         "should arrive on eth2")
    )
    s.expect(
        PacketOutputEvent("eth0", testpkt, "eth1", testpkt, display=Ethernet),
        ("The Ethernet frame with a broadcast destination address should be "
         "forwarded out ports eth0 and eth1")
    )

    # test case 4: a frame whose destination is eth0
    # the frame should be broadcasted out all ports except ingress
    testpkt = new_packet(
        "30:00:00:00:00:01",
        "30:00:00:00:00:00",
        "172.16.42.1",
        "172.16.42.0"
    )
    s.expect(
        PacketInputEvent("eth1", testpkt, display=Ethernet),
        ("An Ethernet frame destined for 30:00:00:00:00:00 "
         "should arrive on eth1")
    )
    s.expect(
        PacketOutputEvent("eth0", testpkt, "eth2", testpkt, display=Ethernet),
        ("The Ethernet frame destined for 30:00:00:00:00:00 should be "
         "forwarded out ports eth0 and eth2")
    )


    return s


scenario = test_hub()
