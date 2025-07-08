import streamlit as st
import cv2
import numpy as np
import mediapipe as mp
from tensorflow.keras.models import load_model
import os
import face_recognition
import csv
import hashlib
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode, urlsafe_b64decode
import pandas as pd
from io import BytesIO
import random
import string
import json

# Set page config as the FIRST Streamlit command
st.set_page_config(page_title="Secure Face Verification", page_icon="🔒", layout="wide")

# CAPTCHA settings
CAPTCHA_LENGTH = 6

# Model URL (replace with your hosted TF.js model URL)
MODEL_URL = "https://your-server.com/models/model.json"
MODEL_HASH = "expected-sha256-hash-of-model-json"

# Custom CSS for professional styling
st.markdown("""
    <style>
    .main-container {
        background-color: #f5f7fa;
        padding: 20px;
        border-radius: 10px;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
    }
    .section-header {
        color: #2c3e50;
        font-size: 24px;
        font-weight: bold;
        margin-bottom: 10px;
    }
    .success-box {
        background-color: #e6ffe6;
        color: #2e7d32;
        padding: 10px;
        border-radius: 5px;
        border: 1px solid #4caf50;
    }
    .error-box {
        background-color: #ffebee;
        color: #c62828;
        padding: 10px;
        border-radius: 5px;
        border: 1px solid #ef5350;
    }
    .stButton>button {
        background-color: #3498db;
        color: white;
        border-radius: 5px;
        padding: 10px 20px;
        font-weight: bold;
    }
    .stButton>button:hover {
        background-color: #2980b9;
    }
    .progress-step {
        font-size: 18px;
        color: #7f8c8d;
        margin-bottom: 5px;
    }
    .active-step {
        color: #3498db;
        font-weight: bold;
    }
    .video-frame {
        border: 2px solid #3498db;
        border-radius: 5px;
    }
    </style>
""", unsafe_allow_html=True)

# CAPTCHA functions
def generate_captcha_text(length):
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def verify_captcha(user_input, captcha_text):
    return user_input == captcha_text

# Encryption key management
def generate_key():
    key = Fernet.generate_key()
    with open("encryption_key.key", "wb") as key_file:
        key_file.write(key)

if not os.path.exists("encryption_key.key"):
    generate_key()

def load_key():
    return open("encryption_key.key", "rb").read()

encryption_key = load_key()
fernet = Fernet(encryption_key)

# Model loading
model_path = "Desktop.h5"

def load_model_safely(model_path):
    if not os.path.exists(model_path):
        st.error(f"Model file not found at: {model_path}")
        return None
    try:
        model = load_model(model_path)
        return model
    except Exception as e:
        st.error(f"Error loading the model: {str(e)}")
        return None

if 'model' not in st.session_state:
    st.session_state['model'] = load_model_safely(model_path)

if st.session_state['model'] is None:
    st.stop()

server_model = st.session_state['model']

# MediaPipe initialization
mp_face_detection = mp.solutions.face_detection
mp_drawing = mp.solutions.drawing_utils

# Face detection and anti-spoofing
def detect_face_and_antispoof(frame, model):
    face_detection = mp_face_detection.FaceDetection(min_detection_confidence=0.5)
    result = face_detection.process(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))

    predictions = []
    frames_with_boxes = {"Real": [], "Spoof": []}

    if result.detections:
        for detection in result.detections:
            bboxC = detection.location_data.relative_bounding_box
            ih, iw, _ = frame.shape
            x, y, w, h = int(bboxC.xmin * iw), int(bboxC.ymin * ih), int(bboxC.width * iw), int(bboxC.height * ih)
            
            if x < 0 or y < 0 or x + w > iw or y + h > ih:
                continue

            face = frame[y:y+h, x:x+w]
            if face.size == 0:
                continue

            face = cv2.resize(face, (224, 224))
            face = face.astype("float32") / 255.0
            face = np.expand_dims(face, axis=0)

            prediction = model.predict(face)[0][0]
            predictions.append(prediction)

            label = "Real" if prediction >= 0.33 else "Spoof"
            color = (0, 255, 0) if label == "Real" else (0, 0, 255)
            
            cv2.rectangle(frame, (x, y), (x + w, y + h), color, 2)
            cv2.putText(frame, label, (x, y - 10), cv2.FONT_HERSHEY_SIMPLEX, 1, color, 3)

            frames_with_boxes[label].append(frame.copy())

    return frame, predictions, frames_with_boxes

# Face comparison
def compare_faces(uploaded_image_path, webcam_frame):
    if uploaded_image_path is None:
        st.error("No image uploaded for comparison.")
        return False
    uploaded_image = face_recognition.load_image_file(uploaded_image_path)
    webcam_face_encoding = face_recognition.face_encodings(webcam_frame)

    if len(webcam_face_encoding) > 0:
        uploaded_face_encoding = face_recognition.face_encodings(uploaded_image)
        if len(uploaded_face_encoding) > 0:
            match = face_recognition.compare_faces([uploaded_face_encoding[0]], webcam_face_encoding[0])
            return match[0]
    return False

# Encryption/Decryption functions
def encrypt_data(data, fernet):
    encoded_data = data.encode()
    encrypted_data = fernet.encrypt(encoded_data)
    base64_data = urlsafe_b64encode(encrypted_data)
    return base64_data.decode()

def decrypt_single_value(encrypted_data, fernet):
    try:
        base64_data = urlsafe_b64decode(encrypted_data.encode())
        decrypted_data = fernet.decrypt(base64_data)
        return decrypted_data.decode()
    except Exception as e:
        st.error(f"Decryption error: {str(e)}")
        return None

# Hash image
def hash_image(image_path):
    if image_path is None:
        return None
    with open(image_path, "rb") as f:
        img_data = f.read()
    return hashlib.sha256(img_data).hexdigest()

# Save to CSV
def save_to_csv(aadhaar_number, name, dob, gender, image_hash, csv_path):
    encrypted_aadhaar = encrypt_data(aadhaar_number, fernet)
    encrypted_name = encrypt_data(name, fernet)
    encrypted_dob = encrypt_data(str(dob), fernet)
    encrypted_gender = encrypt_data(gender, fernet)

    if os.path.exists(csv_path):
        os.remove(csv_path)

    with open(csv_path, 'w', newline='') as csvfile:
        fieldnames = ['Aadhaar Number', 'Name', 'DOB', 'Gender', 'Image Hash']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow({
            'Aadhaar Number': encrypted_aadhaar,
            'Name': encrypted_name,
            'DOB': encrypted_dob,
            'Gender': encrypted_gender,
            'Image Hash': image_hash
        })

# Convert DataFrame to CSV
@st.cache_data
def convert_df(df):
    return df.to_csv().encode('utf-8')

# Decrypt data and provide download
def decrypt_data():
    encrypted_csv_path = "encrypted_data.csv"
    if not os.path.exists(encrypted_csv_path):
        st.error(f"Encrypted data file not found at: {encrypted_csv_path}")
        return

    encrypted_df = pd.read_csv(encrypted_csv_path)
    decrypted_data = []

    for column in encrypted_df.columns:
        if column == "Image Hash":
            decrypted_data.extend(encrypted_df[column].tolist())
        else:
            for encrypted_value in encrypted_df[column]:
                decrypted_value = decrypt_single_value(encrypted_value, fernet)
                if decrypted_value is None:
                    return
                decrypted_data.append(decrypted_value)

    num_columns = len(encrypted_df.columns)
    try:
        decrypted_data = np.reshape(decrypted_data, (-1, num_columns))
        decrypted_df = pd.DataFrame(decrypted_data, columns=encrypted_df.columns)
        csv = convert_df(decrypted_df)
        st.download_button(
            label="Download Decrypted Data",
            data=csv,
            file_name='decrypted_data.csv',
            mime='text/csv',
        )
    except Exception as e:
        st.error(f"Error creating DataFrame: {str(e)}")

# Main app
def main():
    # Sidebar
    with st.sidebar:
        st.image("aadhar.png", use_container_width=True)
        st.title("Secure Face Verification")
        st.write("A secure system for face detection, anti-spoofing, and identity verification.")
        st.markdown("---")
        st.info("Steps:\n1. Enter details\n2. Capture video\n3. Verify & download")

    # Main container
    with st.container():
        st.markdown('<div class="main-container">', unsafe_allow_html=True)
        
        # Header
        st.title("🔒 Real-Time Face Verification System")
        st.write("Verify your identity securely with anti-spoofing and face matching.")

        # Progress indicators
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown(f'<p class="progress-step {"active-step" if not st.session_state.get("details_submitted", False) else ""}">Step 1: Enter Details</p>', unsafe_allow_html=True)
        with col2:
            st.markdown(f'<p class="progress-step {"active-step" if st.session_state.get("details_submitted", False) and not st.session_state.get("real_face_detected", False) else ""}">Step 2: Video Capture</p>', unsafe_allow_html=True)
        with col3:
            st.markdown(f'<p class="progress-step {"active-step" if st.session_state.get("real_face_detected", False) else ""}">Step 3: Verify & Download</p>', unsafe_allow_html=True)

        # Step 1: Details input
        with st.expander("Step 1: Enter Your Details", expanded=not st.session_state.get('details_submitted', False)):
            st.markdown('<p class="section-header">Personal Information</p>', unsafe_allow_html=True)
            
            captcha_text = st.session_state.get('captcha_text', generate_captcha_text(CAPTCHA_LENGTH))
            st.session_state['captcha_text'] = captcha_text
            st.write(f"CAPTCHA: **{captcha_text}**")
            captcha_input = st.text_input("Enter CAPTCHA", key="captcha")

            col_left, col_right = st.columns(2)
            with col_left:
                name = st.text_input("Name")
                aadhaar_number = st.text_input("Aadhaar Number")
            with col_right:
                dob = st.date_input("Date of Birth")
                gender = st.radio("Gender", ('Male', 'Female'))

            uploaded_file = st.file_uploader("Upload Photo", type=["jpg", "jpeg", "png"])
            if uploaded_file:
                temp_image_path = "temp_uploaded_image.jpg"
                with open(temp_image_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())
                st.image(temp_image_path, caption="Uploaded Photo", width=200)
                st.session_state['uploaded_file_path'] = temp_image_path

            if st.button("Submit Details"):
                if not verify_captcha(captcha_input, captcha_text):
                    st.markdown('<div class="error-box">❌ Incorrect CAPTCHA. Try again.</div>', unsafe_allow_html=True)
                elif name and aadhaar_number and dob and gender and uploaded_file:
                    st.session_state.update({
                        'name': name, 'aadhaar_number': aadhaar_number, 'dob': dob, 
                        'gender': gender, 'details_submitted': True
                    })
                    st.markdown('<div class="success-box">✅ Details submitted! Proceed to video capture.</div>', unsafe_allow_html=True)
                else:
                    st.markdown('<div class="error-box">⚠️ Please fill all fields and upload a photo.</div>', unsafe_allow_html=True)

        # Step 2: Video capture
        if st.session_state.get('details_submitted', False):
            with st.expander("Step 2: Video Capture", expanded=not st.session_state.get('real_face_detected', False)):
                st.markdown('<p class="section-header">Live Video Verification</p>', unsafe_allow_html=True)
                
                col_btn1, col_btn2 = st.columns(2)
                with col_btn1:
                    start_button = st.button("Start Video")
                with col_btn2:
                    stop_button = st.button("Stop Video")
                
                stframe = st.empty()

                if 'cap' not in st.session_state:
                    st.session_state['cap'] = None
                if 'captured_frames' not in st.session_state:
                    st.session_state['captured_frames'] = {"Real": [], "Spoof": []}
                if 'predictions' not in st.session_state:
                    st.session_state['predictions'] = []

                if start_button:
                    if st.session_state['cap'] is None or not st.session_state['cap'].isOpened():
                        st.session_state['cap'] = cv2.VideoCapture(0)
                        st.session_state['captured_frames'] = {"Real": [], "Spoof": []}
                        st.session_state['predictions'] = []

                if st.session_state['cap'] is not None and st.session_state['cap'].isOpened():
                    while True:
                        ret, frame = st.session_state['cap'].read()
                        if not ret:
                            st.write("No frame detected. Exiting...")
                            break

                        frame, predictions, frames_with_boxes = detect_face_and_antispoof(frame, server_model)
                        stframe.image(frame, channels="BGR", use_container_width=True)


                        if frames_with_boxes["Real"]:
                            st.session_state['captured_frames']["Real"].extend(frames_with_boxes["Real"])
                        if frames_with_boxes["Spoof"]:
                            st.session_state['captured_frames']["Spoof"].extend(frames_with_boxes["Spoof"])
                        st.session_state['predictions'].extend(predictions)

                        if stop_button:
                            st.session_state['cap'].release()
                            st.session_state['cap'] = None
                            stframe.empty()
                            break

                if stop_button and st.session_state['predictions']:
                    avg_prediction = sum(st.session_state['predictions']) / len(st.session_state['predictions'])
                    final_label = "Real" if avg_prediction >= 0.8 else "Spoof"

                    st.write(f"**Final Decision:** {final_label} (Confidence: {avg_prediction:.2f})")

                    if final_label == "Real" and st.session_state['captured_frames']["Real"]:
                        st.image(st.session_state['captured_frames']["Real"][:3],
                                 caption=["Real Face 1", "Real Face 2", "Real Face 3"],
                                 use_container_width=True)
                        st.session_state['real_face_detected'] = True

                        if st.session_state['uploaded_file_path'] and st.session_state['captured_frames']["Real"]:
                            frame_to_compare = st.session_state['captured_frames']["Real"][0]
                            match_found = compare_faces(st.session_state['uploaded_file_path'], frame_to_compare)
                            if match_found:
                                st.markdown('<div class="success-box">✅ Face match confirmed!</div>', unsafe_allow_html=True)
                            else:
                                st.markdown('<div class="error-box">❌ Face does not match uploaded photo.</div>', unsafe_allow_html=True)

                        if st.session_state['uploaded_file_path']:
                            csv_path = "encrypted_data.csv"
                            image_hash = hash_image(st.session_state['uploaded_file_path'])
                            if image_hash:
                                save_to_csv(st.session_state['aadhaar_number'], st.session_state['name'], 
                                            st.session_state['dob'], st.session_state['gender'], image_hash, csv_path)
                                st.markdown(f'<div class="success-box">✅ Data saved to {csv_path}</div>', unsafe_allow_html=True)
                            else:
                                st.markdown('<div class="error-box">❌ Failed to hash image.</div>', unsafe_allow_html=True)

                    elif final_label == "Spoof" and st.session_state['captured_frames']["Spoof"]:
                        st.image(st.session_state['captured_frames']["Spoof"][0], caption="Detected as Spoof", use_container_width=True)
                        st.session_state['real_face_detected'] = False

        # Step 3: Decrypt data
        if st.session_state.get('real_face_detected', False):
            with st.expander("Step 3: Download Decrypted Data", expanded=True):
                st.markdown('<p class="section-header">Secure Data Retrieval</p>', unsafe_allow_html=True)
                if st.button("Decrypt & Download"):
                    decrypt_data()

        st.markdown('</div>', unsafe_allow_html=True)

if __name__ == "__main__":
    main()
