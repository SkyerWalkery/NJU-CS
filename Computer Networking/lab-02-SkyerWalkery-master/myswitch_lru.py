'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from collections import deque
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

    def update_mem(mac_addr, new_port) -> None:
        nonlocal mem, mem_capacity
        for entry in mem:
            # if the mac address is already in the table, do nothing
            if entry == (mac_addr, new_port):
                break
        else:
            mem.append((mac_addr, new_port))
            # if the table is full, remove the oldest entry
            if len(mem) > mem_capacity: 
                mem.popleft()
    
    # tab saving the mac address and the interface name
    mem = deque()
    mem_capacity = 5

    while True:
        try:
            _, fromIface, packet = net.recv_packet()
            # any time we receive a packet, we update the table
            update_mem(packet[Ethernet].src, fromIface)
        except NoPackets:
            continue
        except Shutdown:
            break

        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            for addr, port in mem:
                # if the mac address is already in the table, send the packet
                # and update the entry
                if addr == eth.dst:
                    log_info(f"Send packet {packet} to {port}")
                    net.send_packet(port, packet)
                    mem.remove((addr, port))
                    mem.append((addr, port))
                    break
            else:
                broadcast(fromIface, packet)
        
    net.shutdown()
