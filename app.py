"""
Network Anomaly Detection System

This Streamlit app uses a trained machine learning model to detect anomalies in network traffic data.
Users can either enter feature values manually or upload a CSV file for batch processing.
"""
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
st.set_page_config(page_title="Network Anomaly Detection", page_icon="🛡️", layout="wide")

# Custom CSS for styling
st.markdown(
    """
    <style>
    .stButton button {
        background-color: #4CAF50;
        color: white;
        font-weight: bold;
        border-radius: 5px;
        padding: 10px 20px;
    }
    .stButton button:hover {
        background-color: #45a049;
    }
    .stHeader {
        color: #4CAF50;
    }
    .stSidebar {
        background-color: #f0f2f6;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# App title and description
st.title("🛡️ Network Anomaly Detection System")
st.markdown("""
    Welcome to the Network Anomaly Detection System! This app uses a trained machine learning model to detect anomalies in network traffic data.
    You can either enter feature values manually or upload a CSV file for batch processing.
""")

# Display the required feature set
st.sidebar.header("📋 Required Features")
st.sidebar.write("The following features are required for prediction:")
st.sidebar.write(feature_names)

# Sidebar for single prediction
st.sidebar.header("🔍 Single Prediction")
features = []
for feature in feature_names:
    value = st.sidebar.number_input(f"Enter {feature}", value=0.0)
    features.append(value)

# Predict anomaly for single input
if st.sidebar.button("Check for Anomaly"):
    result = predict_anomaly(features)
    if result == "Anomaly Detected":
        st.sidebar.error(f"Prediction: **{result}** 🚨")
    else:
        st.sidebar.success(f"Prediction: **{result}** ✅")

# Main section for batch processing
st.header("📂 Batch Processing")
uploaded_file = st.file_uploader("Upload CSV", type=["csv"])
if uploaded_file:
    data = pd.read_csv(uploaded_file)
    missing_features = set(feature_names) - set(data.columns)
    extra_features = set(data.columns) - set(feature_names)

    if not missing_features:
        predictions = model.predict(data[feature_names])
        data['prediction'] = predictions
        st.success("✅ Uploaded CSV matches the required feature set.")
        st.write("Predictions:")
        st.write(data)

        # Visualize anomalies
        st.header("📊 Anomaly Visualization")
        plot_anomalies(data)
    else:
        st.error("❌ Uploaded CSV does not match the required feature set.")
        st.write("The following features are missing:")
        st.write(list(missing_features))
        if extra_features:
            st.warning("⚠️ The following extra features were found in the CSV:")
            st.write(list(extra_features))