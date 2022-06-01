'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import time
import switchyard
from switchyard.lib.userlib import *


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    def broadcast(ignore_intf, pkt) -> None:
        nonlocal my_interfaces
        for intf in my_interfaces:
            if intf.name != ignore_intf:
                log_info (f"Flooding packet {packet} to {intf.name}")
                net.send_packet(intf, pkt)
    def update_mem() -> None:
        ''' timeout case '''
        nonlocal mem
        keys = list(mem.keys())
        for key in keys:
            if time.time() - mem[key][1] > 10:
                del mem[key]

    # tab saving the mac address and the interface name
    mem = {}

    while True:
        try:
            _, fromIface, packet = net.recv_packet()
            # any time we receive a packet, we update the table
            mem[packet[Ethernet].src] = (fromIface, time.time())
        except NoPackets:
            continue
        except Shutdown:
            break

        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        update_mem()
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        elif eth.dst in mem:
            log_info(f"Send packet {packet} to {mem[eth.dst][0]}")
            net.send_packet(mem[eth.dst][0], packet)
        else:
            # broadcast
            broadcast(fromIface, packet)
        
    net.shutdown()
