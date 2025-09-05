import streamlit as st
st.set_page_config(page_title="Real-Time Anomaly Detection", layout="wide")  # MUST be first

import pandas as pd
import joblib
import time
import os
from utils import preprocess, FEATURE_COLUMNS
from flow_builder import build_flows_from_packets

@st.cache_resource
def load_models():
    return {
        "Local Outlier Factor": joblib.load("models/lof_model.pkl"),
        "One-Class SVM": joblib.load("models/ocsvm_model.pkl"),
        "Isolation Forest": joblib.load("models/isolation_forest_model.pkl"),
        "K-Means": joblib.load("models/kmeans_model.pkl"),
        "Gaussian Mixture": joblib.load("models/gmm_model.pkl"),
        "Elliptic Envelope": joblib.load("models/elliptic_model.pkl"),
    }

models = load_models()

st.title("🚨 Real-Time Network Anomaly Detection Dashboard")
st.markdown("Using **Snort (Tshark) + ML Models** for live threat prediction.")

log_path = "live_logs/snort_live.csv"
refresh_interval = st.sidebar.slider("🔁 Refresh every (seconds)", 1, 10, 5)

if not FEATURE_COLUMNS:
    st.error("Feature list is empty.")
    st.stop()

# STEP 1: Check if log file exists
if not os.path.exists(log_path):
    st.warning("Waiting for snort_live.csv to be created...")
    st.stop()

# STEP 2: Load data
df_raw = pd.read_csv(log_path)

if df_raw.empty:
    st.warning("Waiting for new packet data...")
    st.stop()

st.sidebar.success(f"🧾 {len(df_raw)} total packets loaded")

# STEP 3: Convert packets to flows
flow_df = build_flows_from_packets(df_raw)

# STEP 4: Preprocess
processed_data = preprocess(flow_df)
st.sidebar.info(f"📊 Features shape: {processed_data.shape}")

# STEP 5: Run predictions
results = {}
for name, model in models.items():
    preds = model.predict(processed_data)
    results[name] = ["🟢 Normal" if p != -1 else "🔴 Anomaly" for p in preds]

# STEP 6: Display results
display_df = flow_df.copy()
for model_name, pred_list in results.items():
    display_df[model_name] = pred_list

st.dataframe(display_df, use_container_width=True)

# STEP 7: Show anomaly count
st.sidebar.subheader("🚩 Anomaly Counts")
for model_name, pred_list in results.items():
    st.sidebar.write(f"{model_name}: {pred_list.count('🔴 Anomaly')}")

# STEP 8: Refresh after delay
time.sleep(refresh_interval)
st.rerun()
