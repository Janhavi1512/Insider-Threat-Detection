#  ML-Based Insider Threat Detection with Alert Prioritization

![Status](https://img.shields.io/badge/Status-In%20Progress-yellow) ![Python](https://img.shields.io/badge/Python-3.x-blue) ![Flask](https://img.shields.io/badge/Backend-Flask-lightgrey) ![React](https://img.shields.io/badge/Frontend-React-61DAFB) ![ML](https://img.shields.io/badge/ML-Random%20Forest%20%7C%20SVM-orange)

A full-stack cybersecurity system that detects anomalous insider behavior using ML and presents actionable intelligence through a SOC-style dashboard.

##  Features
- ML anomaly detection — Random Forest & SVM
-  3-level alert prioritization: 🔴 High / 🟠 Medium / 🟢 Low
-  SOC dashboard — Alerts, Behavior, Investigation, Timeline, Reports
-  Risk score + financial impact estimation per user

## Tech Stack
| Layer | Tech |
|---|---|
| Backend | Python, Flask |
| Frontend | React, Recharts |
| ML / Data | Scikit-learn, Pandas, Matplotlib, Seaborn |

## ⚙️ Setup
```bash
# Backend
pip install flask pandas numpy scikit-learn matplotlib seaborn
python train_model.py
python app.py          # http://localhost:5000

# Frontend
cd frontend && npm install && npm start   # http://localhost:3000
```

## Alert Logic
```
Risk 75–100 → 🔴 HIGH    Immediate investigation
Risk 40–74  → 🟠 MEDIUM  Review within 24 hrs
Risk 0–39   → 🟢 LOW     Monitor and log
```

##  Planned
- [ ] Real-time log ingestion
- [ ] LSTM sequential behavior model
- [ ] SIEM integration (Splunk / ELK)
- [ ] PDF report export

##  Team
| Name | Role |
|---|---|
| Janhavi Naik | ML Model, Alert Prioritization, Data Analysis |
| Aney Shravani | Frontend, Flask Backend |
| Vedant Thakre | Data Preprocessing, Model Evaluation |
| Bhagyalaxmi Soitkar | Dataset Collection, Testing & Documentation |

> Final Year Project — B.Tech Computer Technology, YCCE Nagpur (2023–2027)
