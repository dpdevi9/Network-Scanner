# hwtype     : XShortField                         = 1               (1)
# ptype      : XShortEnumField                     = 2048            (2048)
# hwlen      : ByteField                           = 6               (6)
# plen       : ByteField                           = 4               (4)
# op         : ShortEnumField                      = 1               (1)
# hwsrc      : ARPSourceMACField                   = '00:0c:29:a3:97:a3' (None)
# psrc       : SourceIPField                       = '192.168.11.142' (None)
# hwdst      : MACField                            = '00:00:00:00:00:00' ('00:00:00:00:00:00')
# pdst       : IPField                             = '0.0.0.0'       ('0.0.0.0')

# dst        : DestMACField                        = 'ff:ff:ff:ff:ff:ff' (None)
# src        : SourceMACField                      = '00:0c:29:a3:97:a3' (None)
# type       : XShortEnumField                     = 36864           (36864)


# hwsrc      : ARPSourceMACField                   = '00:50:56:c0:00:08' (None)
# psrc       : SourceIPField                       = '192.168.11.1'  (None)


import scapy.all as scapy


def scan_network(ip):


    arp_request = scapy.ARP(pdst=ip)
    boradcast_macaddress = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_packet = boradcast_macaddress/arp_request

    answered = scapy.srp(arp_packet,timeout=1)[0]

    print "ip"+"\t" * 4+"mac"+"\t" * 4

    for answer in answered:

        target_dictionary[answer[1].psrc] = answer[1].hwsrc



    pass

if __name__ == '__main__':

    target_dictionary = {}
    ip_address = raw_input("Enter ip address (e.g = 192.168.1.1 or 192.168.1.1/24) : ")
    scan_network(ip_address)
    print target_dictionary

