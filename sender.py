import socket
import sys
import threading
import select
import random
import time
import struct

# All required params in the sender logs
original_data_sent = 0
original_data_acked = 0
original_segments_sent = 0
retransmitted_segments = 0
dup_acks_received = 0
data_segments_dropped = 0
ack_segments_dropped = 0

# A random seed to keep randomness in control
random.seed(42)

# Creating the udp socket
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Getting a random ISN between 0 and 2^16
seq_number = random.randint(0, 2**16)

# Initializing session time var
session_start_time = None

# A set to keep track of acks that are still needed to be sent by the receiver
awaited_acks = set()

# Creating an event and condition for thread management
handshake_ack_received = threading.Event()
window_condition = threading.Condition()
stop_event = threading.Event()

# max window size var initialization
max_win = None
relative_max_win = None

# dataset to keep track of data that hasn't been acked yet
oldestDatasetWithNoAck = []

# General variables to manage code flow and for state changes
syn_received = False
send_data_now = False
need_fin_now = False

# variables to set forward and reverse loss probabilities
rlp_global = None
flp_global = None

# Dataset that contains info of all the data that was sent
allDataInfo = []

# variable to keep track of duplicate acks for the oldest segment to be retransmitted
dupAckCount = 0


def send_udp_packet(destination_ip, destination_port, data, packet_type, data_size=0):
    """
    Sends a UDP packet to the specified destination IP and port.

    Args:
        destination_ip (str): The IP address of the destination where the packet is to be sent.
        destination_port (int): The port number at the destination to which the packet will be delivered.
        data: The actual data payload of the packet to be sent.
        packet_type (str): The type or category of the packet being sent. Useful for handling packet
                                     processing logic based on its type.
        data_size (int, optional): The size of the data to be sent. This could be used to verify packet integrity or
                                   for logging purposes. Defaults to 0 if not provided like in case of FIN or SYN.
    """

    # Getting all the global variables required for this function
    global seq_number, data_segments_dropped, original_segments_sent, oldestDatasetWithNoAck, flp_global, stop_event, original_data_sent

    # To stop the thread when its work (for graceful shutdown)
    if not stop_event.is_set():
        try:
            with window_condition:
                # Condition to wait any more data sends in case that window size is 0
                while (
                    packet_type not in ("FIN", "SYN")
                    and relative_max_win - data_size < 0
                ):
                    window_condition.wait()

                # Getting time at the start for exact time logging
                curr_time = time.time()

                # If the sent packet is SYN or FIN
                if packet_type == "SYN" or packet_type == "FIN":
                    sent_seq_no = seq_number

                    # Updating the sequence number value
                    seq_number = (seq_number + 1) % 2**16

                    # adding packet info to the data info array
                    allDataInfo.append(
                        {
                            "sent_seq_no": sent_seq_no,
                            "ACK_received": False,
                            "data": None,
                            "bytes_sent": 1,
                            "packet_type": packet_type,
                            "time_sent": curr_time,
                            "receive_seq_no": seq_number,
                            "time_ack_received": None,
                        }
                    )

                    # Finally sending the packet
                    udp_socket.sendto(data, (destination_ip, destination_port))

                    # putting the sent data to the sender_log
                    generate_log_entry(
                        "snd",
                        round(((curr_time - session_start_time) * 1000)),
                        packet_type,
                        sent_seq_no,
                        "0" if packet_type in ("FIN", "SYN") else data_size,
                    )
                # Packet type is Data
                else:
                    sent_data = decode_stp_segment(data)

                    sent_seq_no = seq_number

                    # Updating the sequence number value
                    seq_number = (seq_number + len(sent_data["data"])) % 2**16

                    # adding packet info to the data info array
                    dataSet = {
                        "sent_seq_no": sent_seq_no,
                        "ACK_received": False,
                        "data": sent_data["data"],
                        "bytes_sent": len(sent_data["data"]),
                        "packet_type": packet_type,
                        "time_sent": curr_time,
                        "receive_seq_no": seq_number,
                        "time_ack_received": None,
                    }
                    allDataInfo.append(dataSet)

                    # This data was really sent or added to the retransmission queue hence updating the data sent value
                    original_data_sent += len(sent_data["data"])
                    # Also updating the segments sent value
                    original_segments_sent += 1

                    # This is where forward loss is being handled meaning data packet is dropped depending on flp
                    if random.random() >= (int(flp_global) / 100):
                        # if not dropped then sending it to the receiver
                        udp_socket.sendto(data, (destination_ip, destination_port))

                        # Also this packet was just sent hence adding it at the end of this array for in case retransmission is required
                        oldestDatasetWithNoAck.append(dataSet)

                        # Finally logging the sent data info
                        generate_log_entry(
                            "snd",
                            round(((curr_time - session_start_time) * 1000)),
                            packet_type,
                            sent_seq_no,
                            "0" if packet_type in ("FIN", "SYN") else data_size,
                        )
                    else:
                        # if dropped then not sending it to the receiver

                        # logging the dropped data info
                        generate_log_entry(
                            "drp",
                            round(((curr_time - session_start_time) * 1000)),
                            packet_type,
                            sent_seq_no,
                            "0" if packet_type in ("FIN", "SYN") else data_size,
                        )
                        # Incrementing the lost data count
                        data_segments_dropped += 1

                        # Adding packet info to this array for retransmission checks
                        oldestDatasetWithNoAck.append(dataSet)

        except socket.error as e:
            # Handling socket errors here, printing the error message to standard error (stderr).
            print(f"Error sending UDP packet: {e}", file=sys.stderr)


def send_file_in_chunks_threaded(file_path, destination_port, chunk_size=1000):
    """
    Reads a file in specified size chunks and calls send udp packet to send the chunk to receiver.

    This function is made to handle files by breaking them down into chunks of 1000 bytes.

    Args:
        file_path (str): The path to the file that needs to be read. This should be a valid
                         file in the current working directory
        destination_port (int): The network port to which the file chunks need to be sent.
                                This parameter expects a valid port number where the receiver is listening.
        chunk_size (int): The size of each chunk that the file will be divided into. The default
                                    size is 1000 bytes.
    """

    # Getting all the global variables required for this function
    global relative_max_win, max_win, original_data_sent

    destination_ip = "127.0.0.1"
    try:
        # function to open the file and start reading chunks of 1000 bytes from it
        with open(file_path, "rb") as file:
            # Runs until the EOF given
            while True:
                chunk = file.read(chunk_size)
                if not chunk:
                    break

                # Adding this sent data chunk to awaited ACK array so as this data was initialized
                # to be sent and needs an ACK to be certain that it was recognized by the receiver
                awaited_acks.add(f"{(seq_number + len(chunk)) % 2**16}")

                # Calling function to send the packet
                send_udp_packet(
                    destination_ip,
                    destination_port,
                    create_stp_segment(seq_number, chunk, 0),
                    "DATA",
                    len(chunk),
                )

                # Reducing the window size
                relative_max_win -= 1000

        return True
    except IOError as e:
        # Handling I/O errors that might occur during file reading
        print(f"Error reading file {file_path}: {e}", file=sys.stderr)


# Binding the sender socket to a port provided in cmd arg
def bind_udp_socket(source_ip="", source_port=54321):
    global udp_socket
    udp_socket.bind((source_ip, source_port))


# Function to close the udp socket
def close_udp_socket():
    udp_socket.close()


def send_syn_and_wait_for_ack(destination_ip, destination_port, flp, rto):
    """
    Sends a SYN packet to initiate a connection and waits for an ACK response to establish the connection.

    This function is part of a STP handshake process implemented over UDP. It sends a SYN (synchronize)
    segment to the specified destination and waits for an ACK (acknowledgment) from the receiver. If an ACK is
    received, the function returns True, indicating that the connection has been
    successfully established. If the ACK is not received in time, it logs the attempt and retries.

    Args:
    destination_ip (str): The IP address of the destination to which the SYN packet is sent.
    destination_port (int): The port number at the destination to which the SYN packet is sent.
    flp (str or int): Probability that a SYN packet is dropped and not sent.
    rto (str or int): Time function waits for an ACK before considering the attempt failed and retransmitting.
    """
    global session_start_time
    while True:
        handshake_ack_received.clear()

        # Probability that a SYN will be sent or dropped
        if random.random() >= (int(flp) / 100):
            # Setting session start time
            if session_start_time is None:
                session_start_time = time.time()
            # If SYN not dropped then send SYN request
            send_udp_packet(
                destination_ip,
                destination_port,
                create_stp_segment(seq_number, b"", 2),
                "SYN",
            )

        # Wait for an ACK for the specified time then continue to send the SYN request
        # Handshake will be set if ACK was received
        if handshake_ack_received.wait(timeout=(int(rto) / 1000)):
            return True
        # SYN might have been dropped hence again checking time for exact start timing
        if session_start_time is None:
            session_start_time = time.time()

        # Logging that SYN packet for lost (dropped)
        generate_log_entry(
            "drp",
            round(((time.time() - session_start_time) * 1000)),
            "SYN",
            seq_number,
            "0",
        )


def send_fin_and_wait_for_ack(destination_ip, destination_port, flp, rto):
    """
    Sends a FIN packet to initiate the termination of a connection and wait for an ACK to confirm it.

    This function manages the termination phase of a STP session over UDP. It repeatedly sends a FIN
    (finish) packet to the specified destination until an ACK (acknowledgment) is received, indicating that
    the receiver has acknowledged the termination request. The function handles potential packet drops by
    retransmitting the FIN packet based on a specified probability and a timeout.

    Args:
    destination_ip (str): The IP address of the destination to which the FIN packet is sent.
    destination_port (int): The port number at the destination to which the FIN packet is sent.
    flp (str or int): Probability that a FIN packet is dropped and not sent.
    rto (str or int): Time function waits for an ACK before considering the attempt failed and retransmitting.
    """
    global session_start_time

    # Timer for when the first FIN is successfully sent
    first_fin_sent_time = None

    while True:
        handshake_ack_received.clear()

        # Probability that a FIN will be sent or dropped
        if random.random() >= (int(flp) / 100):
            # If FIN not dropped then send SYN request
            send_udp_packet(
                destination_ip,
                destination_port,
                create_stp_segment(seq_number, b"", 3),
                "FIN",
            )
            # Starting timer if success
            if first_fin_sent_time == None:
                first_fin_sent_time = time.time()

        # Wait for an ACK for the specified time then continue to send the FIN request
        # Handshake will be set if ACK was received
        if handshake_ack_received.wait(timeout=(int(rto) / 1000)):
            return True

        # Time returns True after 5 seconds of first FIN because receiver will auto kill after 2 seconds
        # Hence avoiding infinite looping here
        if first_fin_sent_time != None:
            if time.time() - first_fin_sent_time >= 5:
                generate_log_entry(
                    "timeout",
                    round(((time.time() - session_start_time) * 1000)),
                    "FIN_TIMEOUT_RECEIVER",
                    seq_number,
                    "0",
                )
                return True

        # Logging that SYN packet for lost (dropped)
        generate_log_entry(
            "drp",
            round(((time.time() - session_start_time) * 1000)),
            "FIN",
            seq_number,
            "0",
        )


def listen_for_acks(rto, destination_ip, destination_port):
    """
    This function continuously listens on a UDP socket for incoming ACK packets from a specified IP and port.
    This function also continuously checks if the last unAcked packet has timed out if it has then this
    function retransmits the packets, it is also checking that if it has received 3 ACKS for the same sequence
    number then also it retransmits the oldest unACked element.

    Args:
        rto (int): Retransmission Timeout in seconds, specifies how long to wait for an ACK before giving up.
        destination_ip (str): The IP address to listen for ACKs from.
        destination_port (int): The port number to listen for ACKs from.
    """
    global seq_number, ack_segments_dropped, retransmitted_segments, acknowledged_packets, session_start_time, dupAckCount, max_win, relative_max_win, need_fin_now, syn_received, send_data_now, rlp_global, stop_event, allDataInfo, udp_socket, oldestDatasetWithNoAck
    while not stop_event.is_set():
        try:
            ready = select.select([udp_socket], [], [], 0.000001)
            if ready[0]:
                # Getting the ACK from the udp listener
                data, addr = udp_socket.recvfrom(1024)

                # Decoding the ACK to get the info it contains
                ack_info = decode_stp_segment(data)

                # Here ACK can now be dropped depending on the reverse loss probability
                if ack_info["type"] == "ACK" and random.random() >= (
                    int(rlp_global) / 100
                ):
                    with window_condition:
                        # If not dropped and no wait set comes here

                        # Getting the time so that I get the exact time when ACK was received
                        time_ack_received = time.time()
                        window_condition.notify_all()

                        # Conditions to check if the ACK might be for the SYN packet
                        if (
                            len(ack_info["data"]) == 0
                            and not syn_received
                            and not send_data_now
                        ):
                            # Getting the sequence number of the ACK
                            ack_seq_num = int(ack_info["seq_number"])

                            # Generating the received log
                            generate_log_entry(
                                "rcv",
                                round(
                                    ((time_ack_received - session_start_time) * 1000)
                                ),
                                "ACK",
                                ack_info["seq_number"],
                                "0",
                            )
                            seq_number = ack_info["seq_number"]

                            # Setting all the arrays that the ACK was received
                            element_finder(ack_seq_num, time_ack_received)

                            # Setting SYN-ACK received True and now need data transfer
                            syn_received = True
                            send_data_now = True
                            handshake_ack_received.set()

                        elif send_data_now and not need_fin_now:
                            # Condition to check that this was ACK for a data packet

                            # Ack received hence we can now increase the window by 1 packet size
                            # Or set it to the max window size possible as given by cmd args
                            relative_max_win = min(relative_max_win + 1000, max_win)
                            ack_seq_num = ack_info["seq_number"]

                            # This might be a duplicated ACK for a previous data packet hence checking for that
                            if ack_seq_num == oldestDatasetWithNoAck[0]["sent_seq_no"]:
                                dupAckCount += 1

                            # Removing that unacked seq number from the awaited acks list
                            if str(ack_seq_num) in awaited_acks:
                                awaited_acks.remove(str(ack_seq_num))

                            # Generating the received log
                            generate_log_entry(
                                "rcv",
                                round(
                                    ((time_ack_received - session_start_time) * 1000)
                                ),
                                "ACK",
                                ack_seq_num,
                                "0",
                            )

                            # Setting all the arrays that the ACK was received
                            element_finder(ack_seq_num, time_ack_received)

                        elif (
                            len(ack_info["data"]) == 0 and syn_received and need_fin_now
                        ):
                            # This is the condition that we now have received the FIN ACK
                            handshake_ack_received.set()

                            # Generating the received log
                            generate_log_entry(
                                "rcv",
                                round(
                                    ((time_ack_received - session_start_time) * 1000)
                                ),
                                "ACK",
                                ack_info["seq_number"],
                                "0",
                            )

                            # Setting all the arrays that the ACK was received
                            element_finder(ack_info["seq_number"], time_ack_received)

                            exit(0)
                else:
                    # If this ACK was dropped then increment the ACK dropped counter
                    ack_segments_dropped += 1

            # If no packet that requires ACK then no need to go down
            if len(oldestDatasetWithNoAck) == 0:
                time.sleep(0.000001)
                continue

            # Again getting the current time to avoid any lags
            current_time = time.time()

            # Checking that if timer has expired or dup ack count has reached 3 for the
            # last unAcked segment then resend that segment
            if (
                not oldestDatasetWithNoAck[0]["ACK_received"]
                and (
                    current_time - oldestDatasetWithNoAck[0]["time_sent"]
                    >= int(rto) / 1000
                )
            ) or (not oldestDatasetWithNoAck[0]["ACK_received"] and (dupAckCount == 3)):
                retransmitted_segments += 1

                # Set duplicate ACK count to 0 as now it has been retransmitted
                dupAckCount = 0
                retransmit_segment = create_stp_segment(
                    oldestDatasetWithNoAck[0]["sent_seq_no"],
                    oldestDatasetWithNoAck[0]["data"],
                    0,
                )

                # Resending the packet to receiver
                udp_socket.sendto(
                    retransmit_segment, (destination_ip, destination_port)
                )

                # Generating the log that packet was sent again
                generate_log_entry(
                    "snd",
                    round(((current_time - session_start_time) * 1000)),
                    oldestDatasetWithNoAck[0]["packet_type"],
                    oldestDatasetWithNoAck[0]["sent_seq_no"],
                    (
                        "0"
                        if oldestDatasetWithNoAck[0]["packet_type"] in ("FIN", "SYN")
                        else oldestDatasetWithNoAck[0]["bytes_sent"]
                    ),
                )

                # Setting new time to retry after rto in case still unAcked
                oldestDatasetWithNoAck[0]["time_sent"] = current_time
        except Exception as e:
            print(f"Error in listen_for_acks: {e}")


def decode_stp_segment(segment):
    """
    Decode an STP segment received over the network.

    Args:
    - segment: The bytes object representing the received STP segment.

    Returns:
    - A dictionary containing the decoded 'type', 'seq_number', and 'data' from the STP segment.
    """
    # Unpack the first four bytes to get the packet type and sequence number
    segment_type, seq_number_2 = struct.unpack(">HH", segment[:4])

    # Remainder of the segment is data
    data = segment[4:]

    # This is a mapping of packet types to human-readable names
    packet_type = {0: "DATA", 1: "ACK", 2: "SYN", 3: "FIN"}

    # Creating a dictionary to store the decoded segment information
    decoded_segment = {
        "type": packet_type[segment_type],
        "seq_number": seq_number_2,
        "data": data,
    }

    return decoded_segment


def create_stp_segment(seq_num, data, packet_type):
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
    stp_segment = struct.pack(">HH", packet_type, seq_num) + data

    return stp_segment


def generate_log_entry(event, time_log, type_log, seq_num, length):
    """
    Writes a log entry to sender_log.txt with specified details about an event.

    Args:
        event (str): The type of event to log (e.g., 'send', 'drop', 'receive').
        time_log (int or float): The time at which the event occurred.
        type_log (str): Packet type involved in the event (e.g., 'DATA', 'SYN', 'ACK', 'FIN').
        seq_num (int): The sequence number of the packet involved in the event.
        length (int): Packet data byte number.
    """
    with open("sender_log.txt", "a") as file:
        # Formatting the log entry with appropriate spacing and writing in the file
        file.write(
            f"{event:<4}{time_log:>20}  {type_log:<8}{seq_num:>10} {length:>5}\n"
        )


def element_finder(received_seq, time_ack_received):
    """
    This function updates the status of data packets based on the sequence number of received acknowledgments.

    Here I search through a collection of data packet information to update the acknowledgment status
    for a packet that matches the given sequence number.
    Also I remove the oldest unacked element as it has now been acked

    Args:
        received_seq (int or str): The sequence number of the received acknowledgment.
        time_ack_received (float or int): The timestamp when the acknowledgment was received.

    Side Effects:
        Modifies the global variables `oldestDatasetWithNoAck`, `allDataInfo`, `dup_acks_received`, and
        `original_data_acked` by updating acknowledgment statuses and removing acknowledged packets from the
        tracking list.
    """
    global oldestDatasetWithNoAck, allDataInfo, dup_acks_received, original_data_acked
    for obj in allDataInfo:
        if obj["receive_seq_no"] == int(received_seq):
            # Only need to check for data packets as stated in the spec
            if obj["ACK_received"] and obj["packet_type"] not in ["FIN", "SYN"]:
                # This is duplicate ack as this obj has already been acked before as it is set to True
                dup_acks_received += 1
            elif not obj["ACK_received"] and obj["packet_type"] not in ["FIN", "SYN"]:
                # This is first ack as this obj wasn't acked before, as set to False
                original_data_acked += obj["bytes_sent"]

            # Now element has been acked hence setting to True
            obj["ACK_received"] = True
            # Setting time that it got acked
            obj["time_ack_received"] = time_ack_received
            break

    # Also checking for the object in this array so that it isn't retransmitted as it has now been acked
    for obj in oldestDatasetWithNoAck:
        if obj["receive_seq_no"] == int(received_seq):
            oldestDatasetWithNoAck.remove(obj)
            break


def add_extension_txt(txt_file_to_send_check):
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
    if not txt_file_to_send_check.endswith(".txt"):
        txt_file_to_send_check += ".txt"
    return txt_file_to_send_check


def main():
    """
    Main function to execute the initial setup functionalities of the sender.
    """
    global max_win, handshake_ack_received, relative_max_win, need_fin_now, flp_global, rlp_global

    # Checking if enough cmd args were provided else kill the code with error message
    if len(sys.argv) != 8:
        print("All system args not provided")
        sys.exit(0)

    # Setting up the logger file
    open("sender_log.txt", "w", encoding="utf-8")

    # Getting all the info from the cmd args
    sender_port = int(sys.argv[1])
    receiver_port = int(sys.argv[2])
    txt_file_to_send = sys.argv[3]
    max_win = int(sys.argv[4])
    relative_max_win = max_win
    rto = sys.argv[5]
    flp = sys.argv[6]
    flp_global = flp
    rlp = sys.argv[7]
    rlp_global = rlp

    # Binding the UDP socket with the ip and the given port number to listen and transmit packets on
    listen_ip = "127.0.0.1"
    bind_udp_socket(listen_ip, sender_port)

    # Adding the required extension to the text file that needs to be sent
    txt_file_to_send = add_extension_txt(txt_file_to_send)

    # Default IP as provided in the spec (localhost)
    destination_ip = "127.0.0.1"

    # Setting and starting the first thread to listen to the ACK packets
    ack_listener_thread = threading.Thread(
        target=listen_for_acks, args=(rto, destination_ip, receiver_port), daemon=True
    )
    ack_listener_thread.start()

    # Setting up the thread to start sending the packets
    send_thread = threading.Thread(
        target=send_file_in_chunks_threaded,
        args=(txt_file_to_send, receiver_port),
    )

    try:
        # Sending SYN and waiting for the SYN ACK handshake
        if send_syn_and_wait_for_ack(destination_ip, receiver_port, flp, rto):
            # Entering established state hence starting data transfer
            send_thread.start()
            send_thread.join(timeout=1)

        # If no SYN-ACK handshake happened
        else:
            sys.exit(0)

        # Waiting to receive ACKS for all the data packets sent to the receiver
        while len(awaited_acks) > 0:
            time.sleep(0.0000001)

        # After all data packets transferred and ACKed
        need_fin_now = True

        # Sending FIN and waiting for the FIN ACK handshake
        if send_fin_and_wait_for_ack(destination_ip, receiver_port, flp, rto):
            print("Complete")
    except KeyboardInterrupt:
        # Handling in case keyboard interruption stops the code
        stop_event.set()
        print(
            "NOTE THE RECEIVER ONLY LISTENS TO EXTRA FIN REQUESTS AFTER FIRST FIN FOR 2sec HENCE FIN MIGHT HAVE NOT RECEIVED AN ACK DUE TO HIGH LOSS PROBABILITY"
        )
        # Gracefully closing the udp socket stopping all the threads
        if send_thread.is_alive():
            send_thread.join()
        close_udp_socket()
        stop_event.set()
        print("Interrupted by user, exiting...")
    finally:
        # Gracefully closing the udp socket stopping all the threads
        stop_event.set()
        if send_thread.is_alive():
            send_thread.join()
        if ack_listener_thread.is_alive():
            ack_listener_thread.join()
        close_udp_socket()
        # Logging the final transfer statistics to the end of the sender_log as well
        with open("sender_log.txt", "a") as file:
            text_width = 30
            file.write(
                f"\n\nOriginal data sent:{'':<{text_width - len('Original data sent')}} {original_data_sent}"
            )
            file.write(
                f"\nOriginal data acked:{'':<{text_width - len('Original data acked')}} {original_data_acked}"
            )
            file.write(
                f"\nOriginal segments sent:{'':<{text_width - len('Original segments sent')}} {original_segments_sent}"
            )
            file.write(
                f"\nRetransmitted segments:{'':<{text_width - len('Retransmitted segments')}} {retransmitted_segments}"
            )
            file.write(
                f"\nDup acks received:{'':<{text_width - len('Dup acks received')}} {dup_acks_received}"
            )
            file.write(
                f"\nData segments dropped:{'':<{text_width - len('Data segments dropped')}} {data_segments_dropped}"
            )
            file.write(
                f"\nAck segments dropped:{'':<{text_width - len('Ack segments dropped')}} {ack_segments_dropped}"
            )


if __name__ == "__main__":
    main()

