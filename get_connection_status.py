def get_connection_status(packets):

    # NO S2F or S3F was found
    conn = {'INIT': {('0', '1', '1', '0', '0'): 'S4', ('1', '0', '0', '0', '1'): 'SH', ('1', '1', '0', '0', '0'): 'S0'}, # OTH IS ACCOUNTED FOR
            'S4': {('0', '0', '0', '1', '0'): 'SHR', ('0', '0', '0', '0', '1'): 'RSTRH'},
            'SH': {},              
            'SHR': {},              
            'RSTRH': {},          
            'OTH': {},              
            'S0': {('0', '1', '1', '0', '0'): 'S1', ('0', '0', '0', '1', '0'): 'REJ', ('1', '0', '0', '1', '0'): 'RST0S0'},
            'REJ': {},             
            'RST0S0': {},           
            'RST0': {},             
            'RSTR': {},       
            'S1': {('1', '0', '1', '0', '0'): 'ESTAB', ('1', '0', '0', '1', '0'): 'RST0', ('0', '0', '0', '1', '0'): 'RSTR'},
            'ESTAB': {('1', '0', '1', '0', '1'): 'S2', ('0', '0', '1', '0', '1'): 'S3'},
            'S2': {('0', '0', '1', '0', '0'): 'SF'},
            'S3': {('1', '0', '1', '0', '0'): 'SF'},
            'SF': {}}                 
    # Define source and destination
    if(hasattr(packet_list[0], 'ipv6')):
        source_ip = packets[0].ipv6.src
    else:
        source_ip = packets[0].ip.src
    connection_status = 'INIT'

    for packet in packets:
        if(hasattr(packet_list[0], 'ipv6')):
            if source_ip == packet.ipv6.src:
                key = ('1', packet.tcp.flags_syn, packet.tcp.flags_ack, packet.tcp.flags_reset, packet.tcp.flags_fin)
            else:
                key = ('0', packet.tcp.flags_syn, packet.tcp.flags_ack, packet.tcp.flags_reset, packet.tcp.flags_fin)
        else:
            if source_ip == packet.ip.src:
                key = ('1', packet.tcp.flags_syn, packet.tcp.flags_ack, packet.tcp.flags_reset, packet.tcp.flags_fin)
            else:
                key = ('0', packet.tcp.flags_syn, packet.tcp.flags_ack, packet.tcp.flags_reset, packet.tcp.flags_fin)


        try:
            connection_status = conn[connection_status][key]
        except KeyError:
            if connection_status == 'INIT':
                return 'OTH'
            elif connection_status == 'SH' or connection_status == 'SHR':
                return connection_status
            elif connection_status == 'RSTRH' or connection_status == 'OTH':
                return connection_status
            elif connection_status == 'REJ' or connection_status == 'RST0S0' or connection_status == 'RST0':
                return connection_status
            elif connection_status == 'RSTR' or connection_status == 'SF':
                return connection_status
            else:
                continue
    return connection_status
