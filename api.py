from quart import Quart, jsonify, request,send_from_directory
from scapy.all import *
import cv2
import asyncio
import subprocess
import socket  # Import the socket library
from quart_cors import cors
import datetime
import os
import uuid
import random
import string

app = Quart(__name__)
app = cors(app)

ip_started = {}
output_directory = "runs"
os.makedirs(output_directory, exist_ok=True)

def is_rtsp_accessible(rtsp_url):
    try:
        cap = cv2.VideoCapture(rtsp_url)
        if cap.isOpened():
            cap.release()
            return True
    except Exception as e:
        print(f"Error: {e}")
    return False

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
    
def generate_random_uuid(length):
    # Generate a random string of characters
    random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    return random_string

# Endpoint to retrieve users
@app.route('/detect', methods=['GET'])
async def start_camera():
    id = request.args.get('id')  # Get the 'ip' parameter from the request query string
    if not id:
        return jsonify({"message": "IP address is missing in the request parameters"}), 400
    
    muid=generate_random_uuid(6)

    if id:
        #command =  f"start cmd /k \"cd /dC:\\Users\\Mark\\Documents\\pythonMalwareDetectionApp-main && .\\Scripts\\activate && python detect4.py {id}\""
        command =  f"cd /dC:\\Users\\Mark\\Documents\\pythonMalwareDetectionApp-main && .\\Scripts\\activate && python detect4.py {id} {muid}\""
        subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout2_log = os.path.join(output_directory, f'detect_output_{muid}.txt')
        stderr2_log = os.path.join(output_directory, f"detecterr_{muid}.log")
        with open(stdout2_log, "w") as out, open(stderr2_log, "w") as err:
            # Execute the command
            subprocess.Popen(command, shell=True, stdout=out, stderr=err, creationflags=subprocess.CREATE_NO_WINDOW)

        return jsonify({"uuid": muid, "status": "success"}), 200
    else:
        return jsonify({"id": id, "status": "failed"}), 500
    

@app.route('/logs/<path:filename>', methods=['GET'])
async def get_logs(filename):
    isLog = request.args.get('isLog')  # Get the 'ip' parameter from the request query string
    if isLog:
        return await send_from_directory('./runs', filename)
    else:
        return await send_from_directory('./logs', filename)
    

@app.route('/get_image/<path:filename>/<path:userid>', methods=['GET'])
async def get_images(filename,userid):
    return await send_from_directory(f"./packet_images/{userid}", filename)

def packet_sniffer():
    while True:
        packets = sniff(count=100)  # Adjust the count as per your requirement
        with open(f'sniff/packet_logs_{datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}.txt', 'a') as f:
            f.write(str(packets) + '\n')

@app.route('/image/<path:userid>/<path:logid>')
async def serve_images(userid,logid):
    local_ip = get_local_ip()
    user_directory = os.path.join("./packet_images", str(userid))
    
    # Check if the user directory exists
    if not os.path.isdir(user_directory):
        return "User not found", 404
    
    # Get list of image files in the user directory
    image_files = [filename for filename in os.listdir(user_directory) if filename.endswith((f'{logid}.jpg', f'{logid}.jpeg', f'{logid}.png', f'{logid}.gif'))]
    
    # Create HTML grid to display the images
    html_content = '<div style="display: grid; grid-template-columns: repeat(3, 1fr); grid-gap: 5px;">'
    for image_file in image_files:
        # image_path = os.path.join(user_directory, image_file)
        html_content += f'<img src="http://{local_ip}:5000/get_image/{image_file}/{userid}">'
    html_content += '</div>'
    
    return html_content

@app.route('/sniff', methods=['GET'])
async def get_sniff_logs():
    # Define the directory where packet logs are stored
    sniff_directory = './sniff'
    try:
        # Get the list of files in the logs directory
        log_files = os.listdir(sniff_directory)
        # Sort the log files by modification time to get the latest one
        latest_log_file = max(log_files, key=lambda x: os.path.getmtime(os.path.join(sniff_directory, x)))
        # Read the content of the latest log file
        with open(os.path.join(sniff_directory, latest_log_file), 'r') as f:
            sniff_content = f.read()
        # Return the content of the latest log file
        return sniff_content
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/delete_file/<path:file_path>', methods=['GET'])
async def delete_file(file_path):
    
    try:
        directory = os.path.dirname(file_path)
        filename = os.path.basename(file_path)
        try:
            command =  f"cd /d{directory} && del {filename}\""
            stdout_log = os.path.join(output_directory, "removeout.log")
            stderr_log = os.path.join(output_directory, "removeerr.log")
            with open(stdout_log, "w") as out, open(stderr_log, "w") as err:
                # Execute the command
                subprocess.Popen(command, shell=True, stdout=out, stderr=err, creationflags=subprocess.CREATE_NO_WINDOW)
            return jsonify({'message': f'File {file_path} deleted successfully'}), 200
        except Exception as e2:
            print("")
            return jsonify({'error': str(e)}), 500
        # Check if the file exists
        # if os.path.exists(file_path):
        #     # Attempt to delete the file
        #     os.remove(file_path)
        # else:
        #     return jsonify({'message': f'File {file_path} does not exist'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/check', methods=['GET'])
async def checkscan():
    filename = request.args.get('filename')
    if not filename:
        return jsonify({'error': 'Filename not provided'}), 400

    try:
        with open(f'runs/detect_output_{filename}.txt', 'r') as file:
            content = file.read()
            if "SCANNING END" in content:
                return jsonify({'scan_ended': True}), 200
            else:
                return jsonify({'scan_ended': False}), 200
    except FileNotFoundError:
        return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500
        
async def schedule_packet_sniffer():
    await packet_sniffer()

if __name__ == '__main__':
    local_ip = get_local_ip()  # Get the local IP address dynamically
    if local_ip:
        # command =  f"start cmd /k \"cd /dC:\\Users\\Mark\\Documents\\pythonMalwareDetectionApp-main && .\\Scripts\\activate && python sniff.py\""
        command =  f"cd /d C:\\Users\\Mark\\Documents\\pythonMalwareDetectionApp-main && .\\Scripts\\activate && python sniff.py"
        #subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Redirecting stdout and stderr to files
        stdout_log = os.path.join(output_directory, "stdout.log")
        stderr_log = os.path.join(output_directory, "stderr.log")
        with open(stdout_log, "w") as out, open(stderr_log, "w") as err:
            # Execute the command
            subprocess.Popen(command, shell=True, stdout=out, stderr=err, creationflags=subprocess.CREATE_NO_WINDOW)
        app.run(host=local_ip, debug=True)
    else:
        print("Failed to retrieve local IP address.")
