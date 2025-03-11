import os
import sys
import socket
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

def send_file(file_path, dest_ip, deleted=False):
    """Send the file to the destination IP using encoder.py."""
    print(f"Preparing to send file: {file_path}, deleted: {deleted}")
    if deleted:
        file_name = file_path + ".deleted"
    elif not os.path.isfile(file_path):
        print(f"File {file_path} does not exist.")
        return

    send_data(file_name if deleted else file_path, dest_ip)

def send_data(file_path, dest_ip):
    """Send the file to the destination IP using encoder.py."""
    print(f"Sending file {file_path} to {dest_ip}")
    command = f'python3 encoder.py FT:{dest_ip} "{file_path}"'
    os.system(command)
    print("File sent successfully.")

class CustomEventHandler(FileSystemEventHandler):
    def __init__(self, dest_ip):
        self.dest_ip = dest_ip

    def on_created(self, event):
        if not event.is_directory:
            print(f"File {event.src_path} created.")
            send_file(event.src_path, self.dest_ip)

    def on_modified(self, event):
        if not event.is_directory:
            print(f"File {event.src_path} modified.")
            send_file(event.src_path, self.dest_ip)

    def on_deleted(self, event):
        if not event.is_directory:
            print(f"File {event.src_path} deleted.")
            send_file(event.src_path, self.dest_ip, deleted=True)

def watch_path(path, dest_ip):
    """Watch the path for file events."""
    print(f"Starting to watch path: {path}")
    event_handler = CustomEventHandler(dest_ip)
    
    observer = Observer()
    observer.schedule(event_handler, path=path, recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
    print("Stopped watching path.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 watcher.py <file_path_or_directory> <dest_ip>")
        sys.exit(1)

    path = sys.argv[1]
    dest_ip = sys.argv[2]

    if not os.path.isdir(path):
        print(f"Error: {path} is not a directory.")
        sys.exit(1)

    print(f"Watching: {path}, Destination IP: {dest_ip}")
    watch_path(path, dest_ip)
