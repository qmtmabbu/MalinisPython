from scapy.all import *
import sys
import os
import numpy as np
from PIL import Image
from scapy.layers.http import HTTP
from tensorflow.keras.models import load_model
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
import mysql.connector

db_connection = mysql.connector.connect(
    host="localhost",
    user="root",
    password="local",
    database="malinisdb"
)


# Load the trained model
MODEL_INPUT_SHAPE = (150, 150, 3)
classifier = load_model('ResNet_final.h5')

# Variable to store log file path
log_file_path = ""

# Create directory to store images if not exists
current_id = ""
images_path = "./packet_images"

def create_images_directory(id):
    global images_path
    try:
        if not os.path.exists(f"{images_path}/{id}"):
            os.makedirs(f"{images_path}/{id}")
    except Exception as e:
        print(f"Error creating images directory: {e}")

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

# Function to convert packet data to image
def packet_to_image(packet):
    try:
        # Scale packet length to pixel intensity (0-255)
        pixel_intensity = min(int(packet.len / 10), 255)
        # Create a new grayscale image
        image = Image.new('L', (100, 100))
        # Set pixel values based on intensity
        pixels = [pixel_intensity] * (100 * 100)
        image.putdata(pixels)
        return image
    except Exception as e:
        print(f"Error converting packet to image: {e}")
        return None
    
def process_packet(packet):
    global log_file_path
    try:
         # Convert packet to image
        img = packet_to_image(packet)
        if img is None:
            print("Error converting packet to image.")
            return
        image_array = np.array(img) / 255.0
        
        packetType = "Unknown"

        if image_array is not None:
            # Use the loaded classifier to predict whether the image is malware or not
            image_array = np.resize(image_array, MODEL_INPUT_SHAPE)
            prediction = classifier.predict(np.expand_dims(image_array, axis=0))

           
            image_path = os.path.join(images_path, current_id, f"packet_{packet.time}.png")
            img.save(image_path)

            # Display the prediction
            if prediction[0][0] > 0.5:  # Adjust threshold as needed
                print("The incoming packet is predicted as malware.")
            else:
                print("The incoming packet is predicted as non-malware.")

        if packet.haslayer(HTTP):  # Check for HTTP layer
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
                print("Packet payload could not be preprocessed as an image")

        # Write packet details to the log file
        with open(log_file_path, "a") as log_file:
            log_file.write(f"Packet Type: {packetType}\t,Packet Details: {packet.summary()}\n")
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
    create_images_directory(current_id)
    # Delete old log file if it exists
    if os.path.exists(log_file_path):
        os.remove(log_file_path)

    # Open the log file in append mode
    with open(log_file_path, "a") as log_file:
        # Create a ThreadPoolExecutor
        executor = ThreadPoolExecutor(max_workers=5)
        # Start packet capture
        sniff(prn=packet_callback, timeout=5)

except Exception as e:
    print(f"Error: {e}")

finally:
    print("Saving ...")
    cursor = db_connection.cursor()
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute("INSERT INTO detections (userID, malwareName, affected, created_at, updated_at) VALUES (%s, %s, %s, %s, %s)",
    (current_id, f"None", "None", current_time,current_time))
    db_connection.commit()
    cursor.close()

    if db_connection.is_connected():
        db_connection.close()
