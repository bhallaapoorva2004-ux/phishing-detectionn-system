import streamlit as st
import joblib
import pandas as pd
from urllib.parse import urlparse
import re

# ==========================
# LOAD MODELS
# ==========================

model = joblib.load("phishing_detector.pkl")
pca = joblib.load("pca.pkl")
scaler = joblib.load("scaler.pkl")

st.title(" Phishing Detection System with Behavioral Analysis")

# ==========================
# FEATURE ENGINEERING
# ==========================

def extract_features(url):

    parsed = urlparse(url)

    return [
        len(url),                              # URL length
        url.count("."),                        # subdomains
        url.count("/"),                        # slashes
        url.count("-"),                        # hyphen
        len(parsed.netloc),                    # domain length
        len(re.findall(r'[?&=%@]', url)),     # special chars
        1 if parsed.scheme == "https" else 0  # HTTPS
    ]

# ==========================
# BEHAVIORAL ANALYSIS FUNCTION
# ==========================

def behavioral_analysis(url):

    analysis = []

    if len(url) > 75:
        analysis.append("⚠️ Very Long URL (Suspicious)")

    if url.count(".") > 3:
        analysis.append("⚠️ Too Many Subdomains")

    if "@" in url:
        analysis.append("⚠️ '@' symbol used (Phishing technique)")

    if "http://" in url:
        analysis.append("⚠️ Non-secure HTTP detected")

    if re.search(r'login|verify|secure|bank|update', url.lower()):
        analysis.append("⚠️ Sensitive keyword detected")

    if len(analysis) == 0:
        analysis.append("✅ No major suspicious behavior detected")

    return analysis

# ==========================
# INPUT
# ==========================

url = st.text_input("🔗 Enter URL to Analyze")

# ==========================
# PREDICTION
# ==========================

if st.button("Predict"):

    if url == "":
        st.warning("Please enter a URL")
    else:

        # Feature extraction
        features = extract_features(url)

        sample = pd.DataFrame([features], columns=[
            "URLLength",
            "DotCount",
            "SlashCount",
            "HyphenCount",
            "DomainLength",
            "SpecialCharCount",
            "HTTPS"
        ])

        # Scaling + PCA
        sample_scaled = scaler.transform(sample)
        sample_pca = pca.transform(sample_scaled)

        # Prediction
        prediction = model.predict(sample_pca)[0]
        risk_score = model.predict_proba(sample_pca)[0][1]

        # ==========================
        # RESULTS
        # ==========================

        st.subheader("📊 Prediction Result")

        st.write("URL:", url)
        st.write("Risk Score:", round(risk_score * 100, 2), "%")

        if prediction == 1:
            st.error("🚨 PHISHING URL DETECTED")
            action = "BLOCK"
        else:
            st.success("✅ LEGITIMATE URL")
            action = "ALLOW"

        st.write("Recommended Action:", action)

        # ==========================
        # BEHAVIOURAL ANALYSIS
        # ==========================

        st.subheader("🧠 Behavioral Analysis")

        results = behavioral_analysis(url)

        for r in results:
            st.write(r)

        # ==========================
        # FEATURE VIEW
        # ==========================

        st.subheader("📌 Extracted Features")
        st.dataframe(sample.T)

        # ==========================
        # INPUT URL SHOW
        # ==========================

        st.subheader("🌐 Input URL")
        st.code(url)
