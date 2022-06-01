#!/usr/bin/env python3


import time
from collections import deque
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blaster:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasteeIp = '192.168.200.1',
            num='15',
            length="100",
            senderWindow="3",
            timeout="3100",
            recvTimeout="1000"
    ):
        self.net = net
        # TODO: store the parameters
        self.blaster_ip = IPAddr('192.168.100.1')
        self.blastee_ip = IPAddr(blasteeIp)
        self.middle_mac = EthAddr('40:00:00:00:00:01')
        self.packet_num = int(num)
        self.payload_length = int(length)
        self.sender_window = int(senderWindow)
        self.timeout = float(timeout) / 1000 # convert to seconds
        self.recvtimeout = float(recvTimeout) / 1000 # convert to seconds
        assert(self.timeout >= self.recvtimeout * self.sender_window) 

        # next packet expected(lhs) and to send(rhs)
        self.lhs = self.rhs = 1
        # set of seq numbers that have been acked
        self.get_acked = set()
        self.timer = None
        self.send_que = deque() #(deque[(seq, resend_flag)])

    def make_payload(self, data = 'Hello, world') -> bytes:
        '''Make a payload of the given length.'''
        data *= (self.payload_length // len(data) + 1)
        data = data[:self.payload_length]
        return data.encode('utf-8')


    def make_packet(self, seq: int) -> Packet:
        '''Make a packet with the given sequence number and payload.'''
        eth_header = Ethernet(
            src = self.net.interfaces()[0].ethaddr,
            dst = self.middle_mac,
            ethertype = EtherType.IP
        )
        ip_header = IPv4(
            src = self.blaster_ip,
            dst = self.blastee_ip,
            protocol = IPProtocol.UDP,
            ttl = 64
        )
        udp_header = UDP(
            src = 2333,
            dst = 3332
        )
        seq_num = seq.to_bytes(length=4, byteorder='big')
        payload_length = self.payload_length.to_bytes(length=2, byteorder='big')
        payload = self.make_payload()
        return eth_header + ip_header + udp_header + RawPacketContents(seq_num + payload_length + payload)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket) -> None:
        _, fromIface, packet = recv
        # get the seq number
        # delete ethernet, ipv4, udp headers
        del packet[Ethernet]
        del packet[IPv4]
        del packet[UDP]
        seq_num = int.from_bytes(packet[0].to_bytes()[:4], byteorder='big')
        self.get_acked.add(seq_num)
        # move lhs, if needed
        if self.lhs in self.get_acked:
            self.timer = time.time()
        while self.lhs in self.get_acked:
            self.lhs += 1
        log_info(f"get ack {seq_num}, lhs is {self.lhs}, rhs is {self.rhs}")
        # All packets are received
        if self.lhs > self.packet_num:
            log_info("Blaster is done")
            self.end_stat()
            self.print_stat()
            self.net.shutdown()


    def handle_no_packet(self) -> None:
        log_info(f"no pkg, lhs is {self.lhs}, rhs is {self.rhs}")

        # send a new packet
        if self.rhs - self.lhs < self.sender_window and self.rhs <= self.packet_num:
            self.send_que.append((self.rhs, False))
        # resend
        if self.timer is not None and time.time() - self.timer > self.timeout:
            for i in range(self.lhs, self.rhs):
                if i not in self.get_acked and i not in self.send_que:
                    self.send_que.append((i, True))
            self.timer = time.time()
            if hash(self.timer) != self.timeout_flag:
                self.timeout_num += 1
                self.timeout_flag = hash(self.timer)
        
    def handle_send_que(self) -> None:
        while len(self.send_que) > 0:
            seq, resend_flag = self.send_que.popleft()
            if seq in self.get_acked:
                continue
            if resend_flag:
                self.resend_num += 1
                log_info(f"resend pkg {seq}")
            else:
                self.rhs += 1
                log_info(f"send pkg {seq}")
            self.net.send_packet(
                self.net.interfaces()[0].name,
                self.make_packet(seq)
            )
            # send single packet at most per loop
            break

    def init_stat(self):
        self.start_time = time.time() # time to send the first packet(in seconds)
        self.end_time = None # time to receive the last ACK
        self.resend_num = 0 # number of resend packets
        self.timeout_num = 0 # number of timeout packets
        self.timeout_flag = hash(0) # to distinguish timeout events

    def end_stat(self):
        self.end_time = time.time()

    def print_stat(self):
        print(f'Total TX time: {(self.end_time - self.start_time):.4} seconds')
        print(f'Total resend times: {self.resend_num}')
        print(f'Total timeout times: {self.timeout_num}')
        print(f'Throughput: {self.payload_length * (self.packet_num + self.resend_num) / (self.end_time - self.start_time):.4} Bps')
        print(f'Goodput: {self.payload_length * self.packet_num / (self.end_time - self.start_time):.4} Bps')

    def start(self):
        '''A running daemon of the blaster.
        Receive packets until the end of time.
        '''
        self.timer = time.time()
        self.init_stat()
        while True:
            try:
                recv = self.net.recv_packet(timeout=self.recvtimeout)
            except NoPackets:
                self.handle_no_packet()
                self.handle_send_que()
                continue
            except Shutdown:
                break

            self.handle_packet(recv)
            self.handle_send_que()

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blaster = Blaster(net, **kwargs)
    blaster.start()
