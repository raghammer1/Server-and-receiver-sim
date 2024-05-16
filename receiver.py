import socket
import sys
import select
import time
import struct

# All required params in the receiver logs
original_data_received = 0
original_segments_received = 0
dup_data_segments_received = 0
dup_ack_segments_sent = 0

# Initializing session time var
session_start_time = None

# File name that the incoming data will be set in
txt_file_received = None

# the port that is being used by the sender
sender_port = None

# Tracker for all the packets that are incoming
received_parts = []

# Next data sequence number that is required to be set in the new file
next_data_seq_req = None
# Packet buffer to set the file data in correct order
packet_buffer = {}

# Creating the udp socket
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def create_stp_segment(seq_number, data, segment_type):
    """
    Create an STP segment with the specified sequence number, data, and segment type.

    Args:
    - packet_type: The type of the segment (2-byte unsigned integer, 0=DATA, 1=ACK, 2=SYN, 3=FIN).
    - seq_num: The sequence number (2-byte unsigned integer).
    - data: The payload data (0 to MSS bytes).

    Returns:
    - A bytes object representing the STP segment in binary format.
    """

    # Checking if the data is not bytes then encode it using UTF-8
    if not isinstance(data, bytes):
        data = data.encode("utf-8")

    # Packing the packet type and sequence number into binary format, then concatenating the data to create the STP segment
    stp_segment = struct.pack(">HH", segment_type, seq_number) + data

    return stp_segment


def decode_stp_segment(segment):
    """
    Decode an STP segment received over the network.

    Args:
    - segment: The bytes object representing the received STP segment.

    Returns:
    - A dictionary containing the decoded 'type', 'seq_number', and 'data' from the STP segment.
    """

    # Unpack the first four bytes to get the packet type and sequence number
    segment_type, seq_number = struct.unpack(">HH", segment[:4])

    # Remainder of the segment is data
    data = segment[4:]

    # This is a mapping of packet types to human-readable names
    packet_type = {0: "DATA", 1: "ACK", 2: "SYN", 3: "FIN"}

    # Creating a dictionary to store the decoded segment information
    decoded_segment = {
        "type": packet_type[segment_type],
        "seq_number": seq_number,
        "data": data.decode("utf-8"),
    }

    return decoded_segment


def send_udp_packet(destination_ip, destination_port, data, seq_num, segment_type):
    """
    Sends a UDP packet to the specified destination IP and port.

    Args:
        destination_ip (str): The IP address of the destination where the packet is to be sent.
        destination_port (int): The port number at the destination to which the packet will be delivered.
        data: The actual data payload of the packet to be sent.
        seq_num(str) : The sequence number of the ACK that is being sent
        segment_type (str): The type or category of the packet being sent. Useful for handling packet
                                     processing logic based on its type.
    """
    global udp_socket
    # Logging the sending event
    generate_log_entry(
        "snd",
        round(((time.time() - session_start_time) * 1000)),
        "ACK",
        seq_num,
        "0",
    )

    # Creating the segment with sequence number, data, and type
    data = create_stp_segment(seq_num, data, segment_type)

    # Sending the packet using the UDP socket
    udp_socket.sendto(data, (destination_ip, destination_port))


def receive_udp_packet():
    """
    Receive UDP packets in this function which keeps on running until a end condition

    This function used the udp_socket to receive packets from anyone transmitting on this port.
    It listens for SYN/DATA/FIN packets and processes them accordingly. It also calls the function
    to set packets in a buffered fashion
    """
    global udp_socket, sender_port, session_start_time, dup_data_segments_received, dup_ack_segments_sent, original_segments_received, original_data_received, next_data_seq_req, packet_buffer
    try:
        while True:
            ready = select.select([udp_socket], [], [], 10)
            if ready[0]:
                udp_packet, addr = udp_socket.recvfrom(2048)

                # decoding the received data
                received_data = decode_stp_segment(udp_packet)
                data = received_data

                # Checking if the data we have received is out of sync then add to dup ACK counter
                # and send an ACK to the sender to revert back with the required data
                if (
                    data["seq_number"] != next_data_seq_req
                    and (data["type"] == "DATA" or data["type"] == "SYN")
                    and next_data_seq_req != None
                ):
                    if data["type"] != "SYN":
                        dup_ack_segments_sent += 1
                    send_udp_packet(addr[0], sender_port, b"", next_data_seq_req, 1)

                # This is checking if the data packet was already acked from receiver size but received again
                if data in received_parts:
                    if data["type"] == "SYN":

                        # Log SYN received in the receiver_log
                        generate_log_entry(
                            "rcv",
                            round(((time.time() - session_start_time) * 1000)),
                            "SYN",
                            data["seq_number"],
                            "0",
                        )

                        # increment the next required data segment to match the ISN
                        next_data_seq_req = int(data["seq_number"]) + 1

                        # send the ACK
                        send_udp_packet(
                            addr[0], sender_port, b"", int(data["seq_number"]) + 1, 1
                        )
                    elif data["type"] == "FIN":
                        # Log FIN received in the receiver_log
                        generate_log_entry(
                            "rcv",
                            round(((time.time() - session_start_time) * 1000)),
                            "FIN",
                            data["seq_number"],
                            "0",
                        )

                        # send the ACK
                        send_udp_packet(
                            addr[0], sender_port, b"", int(data["seq_number"]) + 1, 1
                        )
                    elif data["type"] == "DATA":
                        # Log data received in the receiver_log
                        generate_log_entry(
                            "rcv",
                            round(((time.time() - session_start_time) * 1000)),
                            "DATA",
                            data["seq_number"],
                            len(data["data"]),
                        )

                        # send the ACK
                        send_udp_packet(
                            addr[0],
                            sender_port,
                            b"",
                            (int(data["seq_number"]) + len(data["data"])) % 2**16,
                            1,
                        )

                        # increase the dupACK and dupDATA as data received again and ack sent again
                        dup_ack_segments_sent += 1
                        dup_data_segments_received += 1
                else:
                    # come here if receiving the packet for the first time

                    # If packet type is SYN
                    if data["type"] == "SYN":
                        with open(
                            f"{txt_file_received}", "w", encoding="utf-8"
                        ) as file:
                            file.write("")

                        # SYN segment received so we can now start the session timer
                        if session_start_time is None:
                            session_start_time = time.time()

                        # Log SYN received in the receiver_log
                        generate_log_entry(
                            "rcv",
                            round(((time.time() - session_start_time) * 1000)),
                            "SYN",
                            data["seq_number"],
                            "0",
                        )

                        # increment the next required data segment to match the ISN
                        next_data_seq_req = int(data["seq_number"]) + 1

                        # Add to received packets array
                        received_parts.append(data)

                        # send the ACK
                        send_udp_packet(
                            addr[0], sender_port, b"", int(data["seq_number"]) + 1, 1
                        )

                    # If packet type is FIN
                    elif data["type"] == "FIN":
                        # This means no more data packets left hence one more check if data needs to be set else continue shutdown
                        while next_data_seq_req in packet_buffer:
                            buffered_data = packet_buffer.pop(next_data_seq_req)
                            write_data_to_file(buffered_data)
                            next_data_seq_req += len(buffered_data)
                            next_data_seq_req = next_data_seq_req % 2**16

                        # Log FIN received in the receiver_log
                        generate_log_entry(
                            "rcv",
                            round(((time.time() - session_start_time) * 1000)),
                            "FIN",
                            data["seq_number"],
                            "0",
                        )

                        # Add to received packets array
                        received_parts.append(data)

                        # send the ACK
                        send_udp_packet(
                            addr[0], sender_port, b"", int(data["seq_number"]) + 1, 1
                        )

                        # After receiving the first FIN wait 2 seconds to check for second one as well
                        wait_for_second_fin(data["seq_number"])

                        # Then proceed with shutdown
                        break
                    # If packet type is DATA
                    elif data["type"] == "DATA":
                        # This is the first time data was received hence incrementing the
                        # original data received and the original segments received
                        original_data_received += len(data["data"])
                        original_segments_received += 1

                        # Add to received packets array
                        received_parts.append(data)
                        process_tcp_segment(data, addr)
                    else:
                        print("Unexpected packet received. Ignoring.")
            else:
                break
    finally:
        udp_socket.close()
        sys.exit(0)


def wait_for_second_fin(seq_num):
    """
    The function waits for 2 seconds FIN for two seconds and responds in case there is a
    second FIN request else continues to shut down
    """
    global original_data_received, udp_socket

    # Setting the time when the function will end to wait
    end_time = time.time() + 2

    # Starting the waiting loop
    while time.time() < end_time:
        ready = select.select([udp_socket], [], [], 0.005)
        if ready[0]:
            udp_packet, addr = udp_socket.recvfrom(1024)
            received_data = decode_stp_segment(udp_packet)
            # If FIN is received then again send the ACK for this
            if received_data["type"] == "FIN":

                # Logging the extra FIN requests
                generate_log_entry(
                    "rcv",
                    round(((time.time() - session_start_time) * 1000)),
                    "FIN",
                    received_data["seq_number"],
                    "0",
                )
                # Finally sending the ACK to the FIN AGAIN
                send_udp_packet(addr[0], sender_port, b"", int(seq_num) + 1, 1)

    # Logging the final transfer statistics to the end of the receiver_log as well
    with open("receiver_log.txt", "a") as file:
        text_width = 30
        file.write(
            f"\n\nOriginal data received:{'':<{text_width - len('Original data received')}} {original_data_received}"
        )
        file.write(
            f"\nOriginal segments received:{'':<{text_width - len('Original segments received')}} {original_segments_received}"
        )
        file.write(
            f"\nDup data segments received:{'':<{text_width - len('Dup data segments received')}} {dup_data_segments_received}"
        )
        file.write(
            f"\nDup ack segments sent:{'':<{text_width - len('Dup ack segments sent')}} {dup_ack_segments_sent}"
        )


def generate_log_entry(event, time_log, type_log, seq_num, length):
    """
    Writes a log entry to sender_log.txt with specified details about an event.

    Args:
        event (str): The type of event to log (e.g., 'send', 'drop').
        time_log (int or float): The time at which the event occurred.
        type_log (str): Packet type involved in the event (e.g., 'DATA', 'SYN', 'ACK', 'FIN').
        seq_num (int): The sequence number of the packet involved in the event.
        length (int): Packet data byte number.
    """
    with open("receiver_log.txt", "a") as file:
        file.write(
            # Formatting the log entry with appropriate spacing and writing in the file
            f"{event:<4}{time_log:>20}  {type_log:<8}{seq_num:>10} {length:>5}\n"
        )


def process_tcp_segment(data, addr):
    """
    Processes a STP segment received over UDP, logs the event, sends an acknowledgment,
    and handles file setup based on the data received.
    Args:
        data (dict): A dictionary containing the received segment's details such as sequence number and data.
                     Expected keys are 'seq_number' and 'data'.
        addr (tuple): A tuple containing the sender's IP address and port number.
    """
    global session_start_tim

    try:
        # Calculate the next sequence number, max being 65536
        next_seq_num = (int(data["seq_number"]) + len(data["data"])) % 2**16

        # Log data received in the receiver_log
        generate_log_entry(
            "rcv",
            round(((time.time() - session_start_time) * 1000)),
            "DATA",
            data["seq_number"],
            len(data["data"]),
        )

        # Send the ACK
        send_udp_packet(addr[0], sender_port, b"", next_seq_num, 1)

        # Buffer function to set the data in the file
        process_file_setup(data)
    except Exception as e:
        # General Exception handler
        with open(f"{txt_file_received}.txt", "a", encoding="utf-8") as file_write:
            file_write.write(
                "Received packet format is incorrect or not a data packet.\n", e
            )
            file_write.write("\n")


def process_file_setup(data):
    """
    This function handles data packets by ensuring they are processed in the correct sequence order. It writes
    data immediately if it arrives in the expected sequence, or buffers it if it arrives out of order. This ensures
    that the data can be reconstructed correctly from the packets, mimicking TCP's reliable data transfer over an
    unreliable protocol like UDP.

    Args:
        data (dict): A dictionary containing the packet's sequence number and data payload.
    """
    global next_data_seq_req

    # Getting the info from the current data packet
    seq_num = int(data["seq_number"])
    packet_data = data["data"]

    # Calculating the next expected sequence number after this packet's data
    next_expected_seq = (next_data_seq_req + len(packet_data)) % 65536

    if seq_num == next_data_seq_req:
        # If the packet is the next in sequence, write its data to file
        write_data_to_file(packet_data)
        next_data_seq_req = next_expected_seq

        # Checking if subsequent packets are now in sequence and can be processed
        while next_data_seq_req in packet_buffer:
            data_to_write = packet_buffer.pop(next_data_seq_req)
            write_data_to_file(data_to_write["data"])
            next_data_seq_req = (next_data_seq_req + len(data_to_write["data"])) % 65536

    else:
        # If out of order, buffer this packet
        packet_buffer[seq_num] = data


def write_data_to_file(data):
    """Write packet data to the provided file in cmd args."""
    try:
        with open(f"{txt_file_received}", "a", encoding="utf-8") as file_write:
            file_write.write(data)
    except Exception as e:
        print(f"Failed to write data to file: {e}")


def add_extension_txt(txt_file_receive):
    """
    This function checks if the provided filename string ends with '.txt'. If it does not, the function
    appends '.txt' to the end of the string.

    Args:
        txt_file_to_send_check (str): The filename to check.

    Returns:
        str: The filename, guaranteed to end with '.txt'.

    Example:
        >>> add_extension_txt("example")
        returns 'example.txt'
        >>> add_extension_txt("document.txt")
        returns 'document.txt'
    """
    if not txt_file_receive.endswith(".txt"):
        txt_file_receive += ".txt"
    return txt_file_receive


if __name__ == "__main__":
    # Main function to execute the initial setup functionalities of the receiver.

    # Checking if enough cmd args were provided else kill the code with error message
    if len(sys.argv) != 5:
        exit(1)

    # Setting up the logger file
    open("receiver_log.txt", "w", encoding="utf-8")

    # Getting all the info from the cmd args
    receiver_port = int(sys.argv[1])
    sender_port = int(sys.argv[2])
    txt_file_received = sys.argv[3]
    max_win = sys.argv[4]

    # Default IP as provided in the spec (localhost)
    listen_ip = "127.0.0.1"

    # Adding the required extension to the text file that is being received
    txt_file_received = add_extension_txt(txt_file_received)

    # Binding the receiver socket to a port provided in cmd arg
    udp_socket.bind((listen_ip, receiver_port))
    udp_socket.setblocking(0)

    # Starting function to start listening to the syn/fin/data packets
    receive_udp_packet()

