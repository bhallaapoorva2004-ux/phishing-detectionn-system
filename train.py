
import re
from urllib.parse import urlparse

def extract_features(url):

    parsed = urlparse(url)

    return [
        len(url),                                   # URLLength
        url.count("."),                             # DotCount
        url.count("/"),                             # SlashCount
        url.count("-"),                             # HyphenCount
        len(parsed.netloc),                         # DomainLength
        len(re.findall(r'[?&=%@]', url)),          # SpecialCharCount
        1 if parsed.scheme == "https" else 0       # HTTPS
    ]

import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from xgboost import XGBClassifier

# LOAD DATA
df = pd.read_csv("PhiUSIIL_Phishing_URL_Dataset.csv")

# FEATURE ENGINEERING (URL → FEATURES)
X = df["URL"].apply(extract_features)
X = pd.DataFrame(X.tolist(), columns=[
    "URLLength",
    "DotCount",
    "SlashCount",
    "HyphenCount",
    "DomainLength",
    "SpecialCharCount",
    "HTTPS"
])

y = df["label"]

# TRAIN TEST SPLIT
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# SCALING
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# PCA
pca = PCA(n_components=0.95)
X_train_pca = pca.fit_transform(X_train_scaled)
X_test_pca = pca.transform(X_test_scaled)

# MODEL
model = XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.05,
    random_state=42
)

model.fit(X_train_pca, y_train)

# SAVE EVERYTHING
joblib.dump(model, "phishing_detector.pkl")
joblib.dump(scaler, "scaler.pkl")
joblib.dump(pca, "pca.pkl")

print("MODEL TRAINED & SAVED SUCCESSFULLY 🚀")

import streamlit as st
import joblib
import pandas as pd
from urllib.parse import urlparse
import re

# LOAD MODELS
model = joblib.load("phishing_detector.pkl")
pca = joblib.load("pca.pkl")
scaler = joblib.load("scaler.pkl")

st.title("🔐 Real-Time Phishing Detection System")

# FEATURE FUNCTION
def extract_features(url):

    parsed = urlparse(url)

    return [
        len(url),
        url.count("."),
        url.count("/"),
        url.count("-"),
        len(parsed.netloc),
        len(re.findall(r'[?&=%@]', url)),
        1 if parsed.scheme == "https" else 0
    ]

# INPUT
url = st.text_input("Enter URL")

if st.button("Predict"):

    if url == "":
        st.warning("Enter a URL")
    else:

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

        sample_scaled = scaler.transform(sample)
        sample_pca = pca.transform(sample_scaled)

        prediction = model.predict(sample_pca)[0]
        prob = model.predict_proba(sample_pca)[0][1]

        st.write("Risk Score:", round(prob*100,2), "%")

        if prediction == 1:
            st.error("🚨 PHISHING URL")
        else:
            st.success("✅ LEGITIMATE URL")
            import re
from urllib.parse import urlparse

def extract_features(url):

    parsed = urlparse(url)

    return [
        len(url),                                   # URLLength
        url.count("."),                             # DotCount
        url.count("/"),                             # SlashCount
        url.count("-"),                             # HyphenCount
        len(parsed.netloc),                         # DomainLength
        len(re.findall(r'[?&=%@]', url)),          # SpecialCharCount
        1 if parsed.scheme == "https" else 0       # HTTPS
    ]