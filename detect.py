import joblib
from scapy.all import sniff, Ether, IP, TCP
import sys
from tensorflow.keras.models import load_model

# Load the trained model
classifier = load_model('ResNet_final.h5')

# Define a function to process each captured packet
def process_packet(packet):
    if Ether in packet and IP in packet and TCP in packet:
        # Use the packet summary as input for the model
        # Adjust this based on the preprocessing done during model training
        packet_summary = packet.summary()
        # Use the loaded classifier to predict whether the packet is malware or not
        # Assuming the model is binary (malware vs non-malware)
        prediction = classifier.predict([packet_summary])  # Assuming your model expects input shape (1, n_features)
        # Display the prediction
        if prediction[0][0] > 0.5:  # Adjust threshold as needed
            print("The incoming packet is predicted as malware.")
        # Log packet details to a file
        current_id = sys.argv[1] if len(sys.argv) > 1 else 'default_id'
        with open(f"./logs/{current_id}.txt", "a") as log_file:
            log_file.write(f"Packet Details: {packet.summary()}\nPrediction: {prediction[0][0]}\n\n")

# Start capturing packets using scapy's sniff function
# Adjust the filter and count parameters as needed
sniff(filter="tcp and (port 80 or port 443)", prn=process_packet, count=30)  # Capture 30 TCP packets on ports 80 and 443
