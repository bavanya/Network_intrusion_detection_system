# Return a dictionary of tcp/udp to port numbers
def get_iana():
    # Open the CSV file
    service_mapping = {}
    filename = 'helper_functions/all.csv'
    with open(filename, 'r') as fd:

        for line in fd:
            stuff = line.split(',')
            try:
                service = stuff[0]
                port_protocol_tuple = (stuff[2].lower(), int(stuff[1]))
                if service == '' or stuff[1] == '' or stuff[2] == '':
                    continue
                else:
                    # Ensure the port is number!
                    # print(port_protocol_tuple)
                    # print(service)
                    service_mapping[port_protocol_tuple] = service
            except IndexError:
                continue
            except ValueError:
                continue
    # Manually enter port 80
    service_mapping[('tcp', 80)] = 'http'
    service_mapping[('udp', 80)] = 'http'
    service_mapping[('udp', 50005)] = 'Unassigned'

    return service_mapping

def get_network_service_at_dst(packet):
    service_mapping = get_iana()
    src_port = int(packet.tcp.srcport)
    dst_port = int(packet.tcp.dstport)
    if src_port <= dst_port:
        if ('tcp', src_port) not in service_mapping.keys():
            service="Unassigned"
        else:
            service = service_mapping[('tcp', src_port)]
    else:
        if ('tcp', dst_port) not in service_mapping.keys():
            service="Unassigned"
        else:
            service = service_mapping[('tcp', dst_port)]
            #service = service_mapping[('tcp', dst_port)]
    return service
  