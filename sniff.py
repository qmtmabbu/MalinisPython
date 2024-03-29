from quart import Quart, jsonify, request, send_from_directory
from scapy.all import *
from scapy.layers.http import HTTP
import asyncio
import socket
import datetime
import numpy as np
from PIL import Image
from concurrent.futures import ThreadPoolExecutor
from quart_cors import cors
from io import BytesIO
import os

app = Quart(__name__)
app = cors(app)

ip_started = {}

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print(f"Error getting local IP: {e}")
        return None
    
def packet_callback(packet):
    # Submit packet processing to thread pool
    executor.submit(process_packet, packet)

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

# Function to handle packet processing
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
                    packetType = "Image"
                
                if packet.haslayer(HTTP):  # Check for HTTP layer
                    http_payload = bytes(packet[HTTP])
                    print(f'Payload: {http_payload}')
                    if b'youtube.com' in http_payload or b'googlevideo.com' in http_payload:
                        packetType = "YouTube Video"
                    elif b'Content-Type: image' in http_payload:
                        packetType = "Image"
                    elif b'Content-Type: audio' in http_payload:
                        packetType = "Audio"
                        if b'audio/mpeg' in http_payload:
                            packetType = "Audio (MP3)"
                        # Add more audio formats as needed
                    elif b'Content-Type: video' in http_payload:
                        packetType = "Video"
                        if b'video/mp4' in http_payload:
                            packetType = "Video (MP4)"
                        # Add more video formats as needed
                    elif b'rr1.sn-2aqu-jxcd.googlevideo.com.' in http_payload:
                        packetType = "Video"
                    elif b'youtube-ui.l.google.com.' in http_payload:
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
        current_time = datetime.datetime.now()
        log_file_path = f'sniff/packet_logs_{current_time.strftime("%Y-%m-%d")}.txt'
        with open(log_file_path, 'a') as f:
            packet_details = packet.summary()
            if "images" in packet_details:
                packetType = "Image"
                print("The packet summary contains 'images'.")
            elif 'rr1.sn-2aqu-jxcd.googlevideo.com.' in packet_details:
                packetType = "Video"
            elif 'youtube-ui.l.google.com.' in packet_details:
                packetType = "Video"  
            elif "play.google.com" in packet_details:
                packetType = "Video"
            elif "googlevideo.com" in packet_details:
                packetType = "Video"
            elif "image-scdn.cdn-gslb.spotify.com." in packet_details:
                packetType = "Data"
            elif "player.vimeo.com" in packet_details:
                packetType = "Audio"
            elif "124.106.174.89" in packet_details: #spotify
                packetType = "Audio" 
            elif "MP3" in packet_details: 
                packetType = "Audio"
            elif "mp3" in packet_details: 
                packetType = "Audio"  
            elif "MPEG4" in packet_details:
                packetType = "Video"
            elif "MP4" in packet_details:
                packetType = "Video"
            elif "HEVC" in packet_details:
                packetType = "Video"
            elif "MOV" in packet_details:
                packetType = "Video"
            elif "ProRes" in packet_details:
                packetType = "Video"
            elif "WMV" in packet_details:
                packetType = "Video"
            elif "AVI" in packet_details:
                packetType = "Video"
            elif "FV" in packet_details:
                packetType = "Video"
            elif "MPEG PS" in packet_details:
                packetType = "Video"
            elif "DNxHR" in packet_details:
                packetType = "Video"
            elif "3GPP" in packet_details:
                packetType = "Video"
            elif "CineForm" in packet_details:
                packetType = "Video"
            elif "WebM" in packet_details:
                packetType = "Video"
            elif "AVCHD" in packet_details:
                packetType = "Video"
            elif "MKV" in packet_details:
                packetType = "Video"

            f.write(f"Packet Type: {packetType}||| Packet Details: {packet.summary()} ;;{current_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    except Exception as e:
        print(f"Error processing packet: {e}")
        print(packet.summary())

# Function to sniff packets and store them in a file
async def packet_sniffer():
    while True:
        packets = sniff(count=100, prn=packet_callback, timeout=50)  # Adjust the count as per your requirement
        # await asyncio.sleep(60)

if __name__ == '__main__':
    local_ip = get_local_ip()  # Get the local IP address dynamically
    if local_ip:
        current_time = datetime.datetime.now()
        log_file_path = f'sniff/packet_logs_{current_time.strftime("%Y-%m-%d")}.txt'
        if os.path.exists(log_file_path):
            os.remove(log_file_path)
        # Start packet sniffing in a separate thread
        executor = ThreadPoolExecutor(max_workers=10)
        asyncio.run(packet_sniffer())
    else:
        print("Failed to retrieve local IP address.")
