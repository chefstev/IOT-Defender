from scapy.all import *
from netfilterqueue import NetfilterQueue
from datetime import datetime, timedelta

# This program keeps track of all packets being sent over 
# the router and keeps track of the types of connections being
# formed by that device. It spends a day learning all of the
# connections that are being formed and then blocks connections
# that do not match this

# Ip to time it was entered dictionary
IP_DATE = {}
# A dictionary of all the outward ports that this
# device usually connects to detect the kind of applications
# that are being run
IP_PORTS = {}
IP_DST_IPS = {}

#===Temporary for testing===#
# https should be blocked
#IP_DATE['192.168.220.132'] = datetime.now() - timedelta(days=1)
#IP_PORTS['192.168.220.132'] = [53, 80, 443, 5528]
#IP_DST_IPS['192.168.220.132'] = ['8.8.8.8']

# Top level method that every packet from wlan0 is sent to
def filter(packet):
    #==Call various filters here==#
    accept = True
    accept = accept and ipPortFilter(packet)
    accept = accept and ipFilter(packet)

    if accept:
        packet.accept()
    else:
        packet.drop()

def ipPortFilter(packet):
    pkt = IP(packet.get_payload())
    pkt_ip = pkt.src
    if pkt_ip not in IP_DATE:
        print "> New device at ip: " + str(pkt_ip)
        IP_DATE[pkt_ip] = datetime.now()
        IP_PORTS[pkt_ip] = []
        IP_DST_IPS[pkt_ip] = []
        
    if TCP in pkt:
        dst_port = pkt[TCP].dport
    elif UDP in pkt:
        dst_port = pkt[UDP].dport
    else: # For now accept unknown protocols
        return True

    ports = IP_PORTS[pkt_ip]
    # Check if the device has already been tracked for a day
    if (datetime.now() - IP_DATE[pkt_ip]).days > 0:
        # Check if the port is valid, if not then drop the
        # packet
        if dst_port in ports:
            return True
        else:
            print ">>> Packet dropped from " + str(pkt_ip) + " on unvalidated port: " + str(dst_port)
            return False
    else:
        # Device is new so track the ports that it uses
        if dst_port not in ports:
            print ">> New port on ip: " + str(pkt_ip) + " port: " + str(dst_port)
            ports.append(dst_port)
        return True

def ipFilter(packet):
    pkt = IP(packet.get_payload())
    pkt_src_ip = pkt.src
    pkt_dst_ip = pkt.dst

    if pkt_src_ip not in IP_DATE:
        print "> New device at ip: " + str(pkt_src_ip)
        IP_DATE[pkt_src_ip] = datetime.now()
        IP_PORTS[pkt_src_ip] = []
        IP_DST_IPS[pkt_src_ip] = []

    ips = IP_DST_IPS[pkt_src_ip]
    if (datetime.now() - IP_DATE[pkt_src_ip]).days > 0:
        if pkt_dst_ip in ips:
            return True
        else:
            print ">>> Packet dropped from " + str(pkt_src_ip) + " to unvalidated destination: " + str(pkt_dst_ip)
            return False
    else:
        if pkt_dst_ip not in ips:
            print ">> New destination ip for ip: " + str(pkt_src_ip) + " ip: " + str(pkt_dst_ip)
            ips.append(pkt_dst_ip)
        return True
    

nfqueue = NetfilterQueue()
nfqueue.bind(1, filter)
try:
    print "[*] waiting for data"
    nfqueue.run()
except KeyboardInterrupt:
    pass
