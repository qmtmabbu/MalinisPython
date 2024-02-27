from scapy.all import *
import sys
import os
import numpy as np
from PIL import Image
from scapy.layers.http import HTTP
from tensorflow.keras.models import load_model
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO

# Load the trained model


# Resize the model input shape to match packet size
MODEL_INPUT_SHAPE = (150, 150, 3)

# Variable to store log file path
log_file_path = ""

# Function to preprocess packet payload as image
def preprocess_payload(payload):
    try:
        # Convert payload to image
        image = Image.open(BytesIO(payload))
        # Convert image to numpy array and normalize
        image_array = np.array(image) / 255.0  # Normalize pixel values
        return image_array
    except Exception as e:
        print(f"Error preprocessing payload as image: {e}")
        return None
    
def process_packet(packet):
    global log_file_path
    try:
        packetType = ""
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            if payload:
                # Preprocess payload as image
                image_array = preprocess_payload(payload)
                if image_array is not None:
                    # Use the loaded classifier to predict whether the image is malware or not
                    image_array = np.resize(image_array, MODEL_INPUT_SHAPE)
                    prediction = classifier.predict(np.expand_dims(image_array, axis=0))
                    # Display the prediction
                    if prediction[0][0] > 0.5:  # Adjust threshold as needed
                        print("The incoming packet is predicted as malware.")
                    else:
                        print("The incoming packet is predicted as non-malware.")
                    packetType = "Image"

                elif packet.haslayer(HTTP):  # Check for HTTP layer
                    http_payload = bytes(packet[HTTP])
                    if b'Content-Type: image' in http_payload:
                        packetType = "Image"
                    elif b'Content-Type: audio' in http_payload:
                        packetType = "Audio"
                    elif b'Content-Type: video' in http_payload:
                        packetType = "Video"
                    elif b'Host: unsplash.com' in http_payload:  # Check if the host is unsplash.com
                        packetType = "Image (From unsplash.com)"
                    elif b'images.unsplash.com.' in http_payload:  # Check if the host is unsplash.com
                        packetType = "Image"
                    else:
                        packetType = "Non-Image"
                else:
                    packetType = "Non-Image"
                    print("Packet payload could not be preprocessed as an image")
            else:
                packetType = "Empty"
                print("Packet does not contain payload data")
        else:
            packetType = "No Raw Layer"
            print("Packet does not contain a Raw layer")

        # Write packet details to the log file
        with open(log_file_path, "a") as log_file:
            log_file.write(f"Packet Type: {packetType}\t\t,Packet Details: {packet.summary()}\n\n")
    except Exception as e:
        print(f"Error processing packet: {e}")
        print(packet.summary())

# Callback function to handle each packet
def packet_callback(packet):
    # Submit packet processing to thread pool
    executor.submit(process_packet, packet)

try:
    current_id = sys.argv[1] if len(sys.argv) > 1 else 'default_id'
    log_file_path = f"./logs/{current_id}.txt"
    
    # Delete old log file if it exists
    if os.path.exists(log_file_path):
        os.remove(log_file_path)

    # Open the log file in append mode
    with open(log_file_path, "a") as log_file:
        classifier = load_model('ResNet_final.h5')
        # Create a ThreadPoolExecutor
        executor = ThreadPoolExecutor(max_workers=10)
        # Start packet capture
        sniff(iface='Wi-Fi', prn=packet_callback, timeout=10)

except Exception as e:
    print(f"Error: {e}")
