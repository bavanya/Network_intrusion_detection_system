def get_content_data(packet_list):
    num_failed_logins = 0
    logged_in = 0
    num_compromised = 0
    is_guest_login = 0

    packet_no = 1
    for packet in packet_list:
        try:
            # Get the ASCII output
            byte_list = packet.tcp.payload.replace(':', '')
            command = bytes.fromhex(byte_list).decode()
         
            print(command, end="")

            # First check if for login attempt successful or not
            if logged_in == 1:
                # User is logged in, try to get the prompt!
                if '$' or '#' in command:
                    print(command, end='')
            else:
                # User is NOT logged in
                if 'Last login' in command:
                    logged_in = 1
                if 'failed' in command:
                    num_failed_logins += 1
            packet_no += 1
        except UnicodeDecodeError:
            continue
        except AttributeError:
            continue
    return [num_failed_logins, logged_in, num_compromised, logged_in,
            is_guest_login]
  
