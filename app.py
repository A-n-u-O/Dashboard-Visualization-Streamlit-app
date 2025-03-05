
import streamlit as st
import pandas as pd
import joblib
import matplotlib.pyplot as plt

# Load the saved model
model = joblib.load('best_model.pkl')

# Load feature names (ensure this matches the training data)
feature_names = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate'
]

# Function to predict anomalies
def predict_anomaly(features):
    df = pd.DataFrame([features], columns=feature_names)
    prediction = model.predict(df)
    return "Anomaly Detected" if prediction == 1 else "Normal Traffic"

# Function to plot anomalies
def plot_anomalies(data):
    anomalies = data[data['prediction'] == 1]
    normal = data[data['prediction'] == 0]

    plt.figure(figsize=(10, 5))
    plt.scatter(normal.index, normal.iloc[:, 0], color='blue', label="Normal")
    plt.scatter(anomalies.index, anomalies.iloc[:, 0], color='red', label="Anomaly")
    plt.legend()
    plt.xlabel("Samples")
    plt.ylabel("Feature Value")
    st.pyplot(plt)

# Streamlit app
st.title("Network Anomaly Detection System")

# Sidebar for single prediction
st.sidebar.header("Single Prediction")
features = []
for feature in feature_names:
    value = st.sidebar.number_input(f"Enter {feature}", value=0.0)
    features.append(value)

# Predict anomaly for single input
if st.sidebar.button("Check for Anomaly"):
    result = predict_anomaly(features)
    st.sidebar.write(f"Prediction: **{result}**")

# Main section for batch processing
st.header("Batch Processing")
uploaded_file = st.file_uploader("Upload CSV", type=["csv"])
if uploaded_file:
    data = pd.read_csv(uploaded_file)
    if set(data.columns) == set(feature_names):
        predictions = model.predict(data)
        data['prediction'] = predictions
        st.write("Predictions:")
        st.write(data)

        # Visualize anomalies
        st.header("Anomaly Visualization")
        plot_anomalies(data)
    else:
        st.error("Uploaded CSV does not match the required feature set.")
