import pyclamd
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/scan', methods=['POST'])
def scan_file():
    try:
        # Get the file path from the POST request
        file_path = request.form['file_path']
        
        # Initialize ClamAV scanner using pyclamd
        cd = pyclamd.ClamdAgnostic()
        
        # Scan the file for malware
        scan_result = cd.scan_file(file_path)
        
        # Check the scan result
        if scan_result and scan_result[file_path] == 'OK':
            return jsonify({'message': 'File is clean.'}), 200
        else:
            return jsonify({'message': 'Malware detected!','data':scan_result[file_path]}), 400
    
    except Exception as e:
        return jsonify({'error': 'Error occurred during scan: ' + str(e)}), 500

if __name__ == '__main__':
    app.run(host='localhost', port=5000, debug=True)
