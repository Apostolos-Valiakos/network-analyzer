import time
import os

# Define the directory where PCAP files will be saved
# Ensure this directory exists and your Flask app has write permissions
PCAP_OUTPUT_DIR = "generated_pcaps" # Or any desired path, e.g., /tmp/pcaps

# Create the directory if it doesn't exist
os.makedirs(PCAP_OUTPUT_DIR, exist_ok=True)

def save_pcap_data(raw_binary_data):
    """
    Saves the provided raw binary data as a .pcap file in the designated directory.

    Args:
        raw_binary_data (bytes): The raw binary content of the PCAP file.

    Returns:
        tuple: (success (bool), message (str), filename (str))
    """
    try:
        # Generate a unique filename using a timestamp
        timestamp = int(time.time())
        filename = f"capture_{timestamp}.pcap"
        file_path = os.path.join(PCAP_OUTPUT_DIR, filename)

        # Write the binary data to the file
        with open(file_path, 'wb') as f:
            f.write(raw_binary_data)

        message = f"PCAP file '{filename}' saved successfully."
        print(message)
        return True, message, filename

    except Exception as e:
        message = f"Error saving PCAP file: {e}"
        print(f"Error: {e}")
        return False, message, None