# 🛡️ Hybrid Intrusion Detection System (Snort + Machine Learning)

## 📖 About This Project
This project is a **Hybrid Intrusion Detection System (IDS)** that integrates **Snort**, a signature-based intrusion detection tool, with **Machine Learning anomaly detection**.  

- **Snort Setup** → Configured with community, local, and custom rules to detect intrusions. Preprocessor rules were applied for protocols like DNS, SSL, SMTP, and Modbus. Snort was used to capture traffic, generate alerts, and log activity in multiple formats (`.log`, `.csv`, `.pcap`).  
- **ML Analyzer** → Python scripts and a Jupyter notebook were developed to parse Snort outputs into structured datasets. Several unsupervised models were trained — **Isolation Forest, One-Class SVM, Local Outlier Factor, KMeans, Gaussian Mixture Model, and Elliptic Envelope** — to detect anomalies and potential zero-day threats.  

➡️ This system demonstrates an end-to-end IDS workflow:  
**Capture traffic → Generate Snort alerts → Parse logs → Apply ML models → Detect known and unknown threats.**

---

## 🚀 Key Features
- Rule-based detection using Snort (community, local, and custom rules).  
- Preprocessor rules for protocol-specific traffic analysis.  
- Automatic log parsing and feature extraction with Python.  
- Multiple unsupervised ML models for anomaly detection.  
- Hybrid IDS design that combines signature-based and anomaly-based detection.  

---

## 📊 Outputs
- **Snort alerts** → alert files, logs, and PCAP captures.  
- **Structured CSVs** → parsed Snort outputs for ML analysis.  
- **ML Results** → anomaly detection predictions from multiple models.  

---

## 🧑‍💻 Skills Demonstrated
- **Network Security** → IDS configuration, rule writing, traffic analysis.  
- **Python Development** → log parsing, feature engineering, data pipelines.  
- **Machine Learning** → unsupervised anomaly detection techniques.  
- **System Design** → complete IDS pipeline from traffic monitoring to ML-based detection.  

---

## 📌 Future Enhancements
- Real-time visualization dashboard (Flask/Streamlit).  
- Integration with ELK stack (Elasticsearch, Logstash, Kibana).  
- Exploration of deep learning models (Autoencoders, LSTMs) for advanced anomaly detection.  
