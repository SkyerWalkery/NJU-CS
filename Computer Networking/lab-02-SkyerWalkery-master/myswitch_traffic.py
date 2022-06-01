'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import heapq
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
        for vol, addr, port in mem:
            # if the mac address is already in the table, do nothing
            if (addr, port)== (mac_addr, new_port):
                break
        else:
            # if the table is full, remove the entry with the lowest volume
            if len(mem) >= mem_capacity: 
                heapq.heappop(mem)
            heapq.heappush(mem, (0, mac_addr, new_port))
    
    mem = [] # a heap
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
            for i in range(len(mem)):
                # if the mac address is already in the table, send the packet
                # and update the entry(vol += 1)
                if mem[i][1] == eth.dst:
                    vol, dst_addr, dst_port = mem.pop(i)
                    log_info(f"Send packet {packet} to {dst_port}")
                    net.send_packet(dst_port, packet)
                    mem.append((vol + 1, dst_addr, dst_port))
                    heapq.heapify(mem)
                    break
            else:
                broadcast(fromIface, packet)

    net.shutdown()
