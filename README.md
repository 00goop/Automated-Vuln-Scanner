# Automated Vulnerability Scanner (AI-Assisted)

An end-to-end **AI-assisted vulnerability scanner** that detects Python security issues and predicts their exploitability using machine learning. Integrated into a **CI/CD pipeline** with GitHub Actions for fully automated testing.


## 🚀 Project Overview

This project demonstrates a complete DevSecOps workflow:

1. **Phase 1: Basic Python CI**
   - Runs a simple Python script to confirm CI is functional.
   - Demonstrates GitHub Actions integration and automated testing.

2. **Phase 2: Security Scan CI**
   - Detects common Python vulnerabilities using [Bandit](https://bandit.readthedocs.io/).
   - Automates vulnerability scanning for each push to the repository.
   - Includes a deliberately insecure demo application (`vulnerable_app.py`) to show real findings.

3. **Phase 3: AI-Assisted Exploitability Prediction**
   - Trains a small machine learning model on sample historical vulnerability data.
   - Predicts the **exploitability of each finding** from Bandit.
   - Prioritizes high-risk issues automatically in the CI/CD pipeline.

## ⚙️ Tech Stack

- **Language:** Python 3.10  
- **CI/CD:** GitHub Actions  
- **Security Scanning:** Bandit  
- **Machine Learning:** scikit-learn, pandas, joblib  
- **Dataset:** Sample CVE-inspired dataset (`ml_data.csv`)  

## 🗂️ Folder Structure

.
├── demos/
│   └── vulnerable_app/
│       └── vulnerable_app.py
├── .github/
│   └── workflows/
│       ├── python-test.yml
│       ├── security-scan.yml
│       └── ai-vuln-scan.yml
├── test.py
├── requirements.txt
├── ml_data.csv
├── ml_model.py
└── predict_exploit.py

## 🛠️ How to Run Locally

1. Clone the repository:

```bash
git clone https://github.com/00goop/Automated-Vuln-Scanner.git
cd Automated-Vuln-Scanner

pip install -r requirements.txt
pip install pandas scikit-learn joblib

python test.py

bandit -r ./demos/vulnerable_app

python ml_model.py
python predict_exploit.py


---

## **6. Features**

```markdown
## 🎯 Features

- ✅ Automated Python CI workflow  
- ✅ Security scanning with Bandit  
- ✅ AI-assisted exploitability prediction  
- ✅ Fully integrated CI/CD pipeline with GitHub Actions  
- ✅ Prioritization of high-risk vulnerabilities  

## 📈 CI/CD Integration

Three workflows are included:

1. **Python Test CI:** Ensures basic scripts run on push.  
2. **Security Scan CI:** Detects Python security issues automatically.  
3. **AI-Assisted Security Scan:** Runs Bandit, trains ML model, and predicts exploitability in a single workflow.  
