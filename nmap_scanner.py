import nmap

nmScan = nmap.PortScanner()

ip_address = raw_input("Please enter ip address (e.g 192.168.11.1 or 192.168.11.1/24): ")
port_range = raw_input("Port range for Scanning: ")

nmScan.scan(ip_address, "1"+"-"+port_range)

for host in nmScan.all_hosts():
    print('Host : %s (%s)' % (host, nmScan[host].hostname()))
    print('State : %s' % nmScan[host].state())
    for proto in nmScan[host].all_protocols():
        print('----------')
        print('Protocol : %s' % proto)

        lport = nmScan[host][proto].keys()
        lport.sort()
        for port in lport:
            print 'port : %s\tstate : %s' % (port, nmScan[host][proto][port]['state'])
