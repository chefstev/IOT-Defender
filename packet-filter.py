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

#===Temporary for testing===#
# https should be blocked
#IP_DATE['192.168.220.64'] = datetime.now() - timedelta(days=1)
#IP_PORTS['192.168.220.64'] = [53, 80, 5528]

# Top level method that every packet from wlan0 is sent to
def filter(packet):
    #==Call various filters here==#
    ipPortFilter(packet)

def ipPortFilter(packet):
    pkt = IP(packet.get_payload())
    pkt_ip = pkt.src
    if pkt_ip not in IP_DATE:
        print "> New device at ip: " + str(pkt_ip)
        IP_DATE[pkt_ip] = datetime.now()
        IP_PORTS[pkt_ip] = []
        
    if TCP in pkt:
        dst_port = pkt[TCP].dport
    elif UDP in pkt:
        dst_port = pkt[UDP].dport
    else: # For now accept unknown protocols
        packet.accept()
        return

    ports = IP_PORTS[pkt_ip]
    # Check if the device has already been tracked for a day
    if (datetime.now() - IP_DATE[pkt_ip]).days > 0:
        # Check if the port is valid, if not then drop the
        # packet
        if dst_port in ports:
            packet.accept()
        else:
            print ">>> Packet dropped from " + str(pkt_ip) + " on unvalidated port: " + str(dst_port)
            packet.drop()
    else:
        # Device is new so track the ports that it uses
        if dst_port not in ports:
            print ">> New port on ip: " + str(pkt_ip) + " port: " + str(dst_port)
            ports.append(dst_port)
        packet.accept()
    

nfqueue = NetfilterQueue()
nfqueue.bind(1, filter)
try:
    print "[*] waiting for data"
    nfqueue.run()
except KeyboardInterrupt:
    pass
