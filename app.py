"""
Network Anomaly Detection System

This Streamlit app uses a trained machine learning model to detect spyware and spoofing in network traffic data.
Users can either enter feature values manually or upload a CSV file for batch processing.
"""
import streamlit as st
import pandas as pd
import joblib
import matplotlib.pyplot as plt

# Load the saved model
model = joblib.load('best_model.pkl')

# Define categorical feature categories
categorical_categories = {
    'protocol_type': ['tcp', 'udp', 'icmp'],
    'service': ['http', 'smtp', 'ftp', 'ssh', 'dns', 'other'],
    'flag': ['SF', 'S0', 'S1', 'S2', 'S3', 'OTH']
}

# Load feature names (ensure this matches the training data)
feature_names = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds'
]

# Function to preprocess input data
def preprocess_input(data):
    # Encode categorical features using predefined categories
    for feature, categories in categorical_categories.items():
        data[feature] = data[feature].map({cat: idx for idx, cat in enumerate(categories)})
    
    # Skip scaling numerical features
    return data

# Function to predict anomalies
def predict_anomaly(features):
    df = pd.DataFrame([features], columns=feature_names)
    df = preprocess_input(df)  # Preprocess input data
    prediction = model.predict(df)
    return "Spyware/Spoofing Detected" if prediction == 1 else "Normal Traffic"

# Function to plot anomalies
def plot_anomalies(data):
    anomalies = data[data['prediction'] == 1]
    normal = data[data['prediction'] == 0]

    plt.figure(figsize=(10, 5))
    plt.scatter(normal.index, normal.iloc[:, 0], color='blue', label="Normal")
    plt.scatter(anomalies.index, anomalies.iloc[:, 0], color='red', label="Spyware/Spoofing")
    plt.legend()
    plt.xlabel("Samples")
    plt.ylabel("Feature Value")
    st.pyplot(plt)

# Streamlit app
st.set_page_config(page_title="Spyware & Spoofing Detection", page_icon="🛡️", layout="wide")

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
st.title("🛡️ Spyware & Spoofing Detection System")
st.markdown("""
    Welcome to the Spyware & Spoofing Detection System! This app uses a trained machine learning model to detect spyware and spoofing in network traffic data.
    You can either enter feature values manually or upload a CSV file for batch processing.
""")

# Display the required feature set
st.header("📋 Required Features")
st.write("The following **20 features** are required for prediction:")
st.write(feature_names)

# Sidebar for single prediction
st.sidebar.header("🔍 Single Prediction")
features = []
for feature in feature_names:
    if feature in categorical_categories:  # Categorical features
        value = st.sidebar.selectbox(f"Select {feature}", options=categorical_categories[feature])
    else:  # Numerical features
        value = st.sidebar.number_input(f"Enter {feature}", value=0.0)
    features.append(value)

# Predict anomaly for single input
if st.sidebar.button("Check for Spyware/Spoofing"):
    result = predict_anomaly(features)
    if result == "Spyware/Spoofing Detected":
        st.sidebar.error(f"Prediction: **{result}** 🚨")
    else:
        st.sidebar.success(f"Prediction: **{result}** ✅")

# Main section for batch processing
st.header("📂 Batch Processing")

# File uploader
uploaded_file = st.file_uploader("Upload CSV", type=["csv"])

# Process uploaded file
if uploaded_file is not None:
    try:
        data = pd.read_csv(uploaded_file)
        missing_features = set(feature_names) - set(data.columns)
        extra_features = set(data.columns) - set(feature_names)

        if not missing_features:
            # Preprocess the uploaded data
            data_preprocessed = preprocess_input(data[feature_names])
            
            # Make predictions
            predictions = model.predict(data_preprocessed)
            data['prediction'] = predictions
            st.success("✅ Your CSV file is ready for analysis!")
            st.write("Predictions:")
            st.write(data)

            # Visualize anomalies
            st.header("📊 Spyware/Spoofing Visualization")
            plot_anomalies(data)

            # Explanation for the visualization
            st.markdown("""
                ### Understanding the Visualization
                - **Blue Dots**: Represent **normal traffic**.
                - **Red Dots**: Represent **spyware/spoofing attacks**.
                - The x-axis represents the **sample index** (row number in the dataset).
                - The y-axis represents the **value of the first feature** (`duration` in this case).
                - The plot helps you visualize the distribution of normal traffic and spyware/spoofing attacks in your dataset.
            """)
        else:
            st.error("❌ Oops! Your CSV file doesn't have all the required features.")
            st.write("Here’s what’s missing:")
            st.write(list(missing_features))
            st.write("Please make sure your CSV file includes all the required features listed above.")
        
        if extra_features:
            st.warning("⚠️ Your CSV file has some extra features that aren't needed:")
            st.write(list(extra_features))
            st.write("You can ignore these extra features, but make sure all the required features are included.")
    except Exception as e:
        st.error(f"❌ Error reading the CSV file: {e}")

# Generate a sample CSV file for testing
st.header("📥 Generate a Sample CSV File")
if st.button("Download Sample CSV"):
    # Create a sample DataFrame with the required 20 features and some extra features
    sample_data = {
        'duration': [0, 1, 2],
        'protocol_type': ['tcp', 'udp', 'icmp'],
        'service': ['http', 'smtp', 'ftp'],
        'flag': ['SF', 'S0', 'S1'],
        'src_bytes': [100, 200, 300],
        'dst_bytes': [500, 600, 700],
        'land': [0, 0, 0],
        'wrong_fragment': [0, 0, 0],
        'urgent': [0, 0, 0],
        'hot': [0, 0, 0],
        'num_failed_logins': [0, 0, 0],
        'logged_in': [1, 1, 1],
        'num_compromised': [0, 0, 0],
        'root_shell': [0, 0, 0],
        'su_attempted': [0, 0, 0],
        'num_root': [0, 0, 0],
        'num_file_creations': [0, 0, 0],
        'num_shells': [0, 0, 0],
        'num_access_files': [0, 0, 0],
        'num_outbound_cmds': [0, 0, 0],
        'extra_feature_1': [1, 2, 3],  # Extra feature
        'extra_feature_2': [4, 5, 6]   # Extra feature
    }
    sample_df = pd.DataFrame(sample_data)
    
    # Save the sample DataFrame to a CSV file
    sample_df.to_csv("sample_data.csv", index=False)
    
    # Provide the CSV file for download
    with open("sample_data.csv", "rb") as file:
        st.download_button(
            label="Download Sample CSV",
            data=file,
            file_name="sample_data.csv",
            mime="text/csv"
        )