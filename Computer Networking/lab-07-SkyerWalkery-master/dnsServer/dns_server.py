'''DNS Server for Content Delivery Network (CDN)
'''

import random
import sys
from socketserver import UDPServer, BaseRequestHandler
from typing import *
from utils.dns_utils import DNS_Request, DNS_Rcode
from utils.ip_utils import IP_Utils
from datetime import datetime
import math


__all__ = ["DNSServer", "DNSHandler"]


class DNSRecord:
    def __init__(self, **kwargs):
        self.domain_name: str = None
        self.type: str = None
        self.values: list[str] = None
        if 'line' in kwargs:
            line = kwargs['line'].split()
            self.domain_name = line[0]
            self.type = line[1]
            self.values = line[2:]
        elif 'domain_name' in kwargs and 'type' in kwargs and 'values' in kwargs:
            self.domain_name = kwargs['domain_name']
            self.type = kwargs['type']
            self.values = list(kwargs['values'].split())
        else:
            raise ValueError('Invalid arguments')
        assert(self.type in ('A', 'CNAME'))

    def match(self, request_domain_name: str) -> Optional[List[str or List[str]]]:
        match_str = self.domain_name[:]
        if match_str.endswith('.'):
            match_str = match_str[:-1]
        if match_str.startswith('*.'):
            match_str = match_str[2:]
        if match_str in request_domain_name:
            return [self.type, self.values]
        else:
            return None


class DNSServer(UDPServer):
    def __init__(self, server_address, dns_file, RequestHandlerClass, bind_and_activate=True):
        super().__init__(server_address, RequestHandlerClass, bind_and_activate=True)
        self._dns_table = []
        self.parse_dns_file(dns_file)
        
    def parse_dns_file(self, dns_file) -> None:
        # ---------------------------------------------------
        # TODO: your codes here. Parse the dns_table.txt file
        # and load the data into self._dns_table.
        # --------------------------------------------------
        with open(dns_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    self._dns_table.append(DNSRecord(line=line))

    @property
    def table(self):
        return self._dns_table


class DNSHandler(BaseRequestHandler):
    """
    This class receives clients' udp packet with socket handler and request data. 
    ----------------------------------------------------------------------------
    There are several objects you need to mention:
    - udp_data : the payload of udp protocol.
    - socket: connection handler to send or receive message with the client.
    - client_ip: the client's ip (ip source address).
    - client_port: the client's udp port (udp source port).
    - DNS_Request: a dns protocl tool class.
    We have written the skeleton of the dns server, all you need to do is to select
    the best response ip based on user's infomation (i.e., location).

    NOTE: This module is a very simple version of dns server, called global load ba-
          lance dns server. We suppose that this server knows all the ip addresses of 
          cache servers for any given domain_name (or cname).
    """
    
    def __init__(self, request, client_address, server):
        self.table = server.table
        super().__init__(request, client_address, server)

    def calc_distance(self, pointA, pointB) -> int:
        ''' TODO: calculate distance between two points '''
        # we don't sqrt the distance, because we only need make a comparison
        return (pointA[0] - pointB[0])**2 + (pointA[1] - pointB[1])**2

    def get_response(self, request_domain_name) -> Tuple[Optional[str]]:
        response_type, response_val = (None, None)
        # ------------------------------------------------
        # TODO: your codes here.
        # Determine an IP to response according to the client's IP address.
        #       set "response_ip" to "the best IP address".
        client_ip, _ = self.client_address

        for record in self.table:
            if record.match(request_domain_name):
                response_type, optional_response_val = record.match(request_domain_name)
                break
        else:
            return None, None # no match

        if response_type == 'CNAME':
            response_val = optional_response_val[0]
            assert(response_val is not None)
        elif response_type == 'A':
            client_location = IP_Utils.getIpLocation(client_ip)
            # we don't know the location of the client, so we just select a random ip
            if client_location is None:
                response_val = random.choice(optional_response_val)
            else:
                min_distance = math.inf
                for ip_str in optional_response_val:
                    dns_location = IP_Utils.getIpLocation(ip_str)
                    distance = self.calc_distance(client_location, dns_location)
                    if distance < min_distance:
                        min_distance = distance
                        response_val = ip_str
            assert(response_val is not None)
        else:
            raise ValueError('Invalid response type')
        return (response_type, response_val)

    def handle(self):
        """
        This function is called once there is a dns request.
        """
        ## init udp data and socket.
        udp_data, socket = self.request

        ## read client-side ip address and udp port.
        client_ip, client_port = self.client_address

        ## check dns format.
        valid = DNS_Request.check_valid_format(udp_data)
        if valid:
            ## decode request into dns object and read domain_name property.
            dns_request = DNS_Request(udp_data)
            request_domain_name = str(dns_request.domain_name)
            self.log_info(f"Receving DNS request from '{client_ip}' asking for "
                          f"'{request_domain_name}'")

            # get caching server address
            response = self.get_response(request_domain_name)

            # response to client with response_ip
            if None not in response:
                dns_response = dns_request.generate_response(response)
            else:
                dns_response = DNS_Request.generate_error_response(
                                             error_code=DNS_Rcode.NXDomain)
        else:
            self.log_error(f"Receiving invalid dns request from "
                           f"'{client_ip}:{client_port}'")
            dns_response = DNS_Request.generate_error_response(
                                         error_code=DNS_Rcode.FormErr)

        socket.sendto(dns_response.raw_data, self.client_address)

    def log_info(self, msg):
        self._logMsg("Info", msg)

    def log_error(self, msg):
        self._logMsg("Error", msg)

    def log_warning(self, msg):
        self._logMsg("Warning", msg)

    def _logMsg(self, info, msg):
        ''' Log an arbitrary message.
        Used by log_info, log_warning, log_error.
        '''
        info = f"[{info}]"
        now = datetime.now().strftime("%Y/%m/%d-%H:%M:%S")
        sys.stdout.write(f"{now}| {info} {msg}\n")
