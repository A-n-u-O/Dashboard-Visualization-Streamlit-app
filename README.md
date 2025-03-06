# Spyware & Spoofing Detection System

![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=Streamlit&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Machine Learning](https://img.shields.io/badge/Machine%20Learning-FF6F00?style=for-the-badge&logo=scikit-learn&logoColor=white)

This project is a **Streamlit-based web application** designed to detect **spyware and spoofing attacks** in network traffic data using a trained machine learning model. Users can either input feature values manually or upload a CSV file for batch processing.

---

## 🛡️ Features

- **Single Prediction**: Enter feature values manually to check for spyware/spoofing.
- **Batch Processing**: Upload a CSV file to analyze multiple records at once.
- **Visualization**: View a scatter plot of normal traffic vs. spyware/spoofing attacks.
- **Sample CSV**: Download a sample CSV file for testing.

---

## 🚀 How to Use

### 1. Single Prediction
- Input values for the 20 required features in the sidebar.
- Click **Check for Spyware/Spoofing** to get the prediction.

### 2. Batch Processing
- Upload a CSV file containing the required 20 features.
- The app will analyze the data and display predictions.
- Visualize the results using the scatter plot.

### 3. Download Sample CSV
- Click **Download Sample CSV** to get a sample file for testing.

---

## 📋 Required Features

The app requires the following 20 features for prediction:

| Feature Name         | Description                          |
|----------------------|--------------------------------------|
| `duration`           | Duration of the connection           |
| `protocol_type`      | Protocol type (e.g., TCP, UDP, ICMP) |
| `service`            | Network service (e.g., HTTP, FTP)    |
| `flag`               | Status flag of the connection        |
| `src_bytes`          | Bytes sent from source to destination|
| `dst_bytes`          | Bytes sent from destination to source|
| `land`               | Whether the connection is from/to the same host/port |
| `wrong_fragment`     | Number of wrong fragments            |
| `urgent`             | Number of urgent packets             |
| `hot`                | Number of "hot" indicators           |
| `num_failed_logins`  | Number of failed login attempts      |
| `logged_in`          | Whether the user is logged in        |
| `num_compromised`    | Number of compromised conditions     |
| `root_shell`         | Whether a root shell was obtained    |
| `su_attempted`       | Whether `su root` command was attempted |
| `num_root`           | Number of root accesses              |
| `num_file_creations` | Number of file creation operations   |
| `num_shells`         | Number of shell prompts              |
| `num_access_files`   | Number of operations on access control files |
| `num_outbound_cmds`  | Number of outbound commands in an FTP session |