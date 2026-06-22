# 🔐 Phishing Detection System (Machine Learning + Streamlit)

A real-time phishing URL detection system built using Machine Learning (XGBoost), Feature Engineering, and Streamlit.

This project detects whether a given URL is **SAFE or PHISHING** based on extracted behavioral and structural features.

---

## 🚀 Live Demo
(If deployed on Streamlit Cloud, add link here)

👉 https://your-app-link.streamlit.app

---

## 📌 Features

- 🔗 Real-time URL input system
- 🧠 Machine Learning prediction (XGBoost)
- 📊 Risk score calculation
- 🧠 Behavioral analysis of URLs
- ⚡ Feature extraction from raw URL
- 📉 PCA + Scaling pipeline
- 🌐 Streamlit web interface

---

## 🧠 How It Works

1. User enters a URL
2. System extracts features like:
   - URL length
   - Number of dots
   - Special characters
   - HTTPS usage
   - Domain length
3. Features are scaled and reduced using PCA
4. XGBoost model predicts:
   - Phishing (🚨)
   - Legitimate (✅)
5. Risk score is displayed

---

## 📂 Project Structure
