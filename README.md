# 🛡️ ShieldMe — AI-Powered Cybersecurity Awareness Platform

> **Defense through Education.** ShieldMe combines machine learning, YARA signature detection, and generative AI to protect users from phishing, scams, malware, and social engineering attacks — and explain *why* something is dangerous in plain language.

---

## 📌 Table of Contents

- [About the Project](#-about-the-project)
- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
- [Environment Variables](#-environment-variables)
- [Running the App](#-running-the-app)
- [How It Works](#-how-it-works)
- [Threat Coverage](#-threat-coverage)
- [Deployment](#-deployment)
- [Team](#-team)

---

## 📖 About the Project

ShieldMe is a full-stack cybersecurity platform built to help everyday users identify and understand digital threats. It provides a **Unified Threat Scanner** with three independent detection engines operating simultaneously:

1. **Email / Text Scanner** — ML-based spam and phishing classifier
2. **URL Scanner** — Structural feature analysis to detect malicious links
3. **File Scanner** — YARA signature engine for malware and web shell detection

Every scan result is enhanced by **Google Gemini 2.5 Flash**, which translates the machine's verdict into a clear, structured explanation with actionable advice — bridging the gap between technical detection and user understanding.

---

## ✨ Features

| Feature | Description |
|---|---|
| 📧 Email / Text Analysis | Classifies phishing, financial fraud, prize scams, and general spam using a stacking ensemble ML model |
| 🌐 URL Analysis | Extracts 10 structural URL features to detect malicious links without relying on blocklists |
| 📁 File Scanning | YARA-based signature matching for malware, web shells, Office macros, and malicious PDFs |
| 🤖 AI Explanation | Gemini 2.5 Flash provides a human-readable breakdown of every scan result |
| 🧠 Educational Modules | Learn about social engineering, phishing, vishing, smishing, and more |
| 🎯 Interactive Quiz | Test your cybersecurity awareness with real-world scenario questions |
| 🎭 Scam Simulator | Experience simulated attack scenarios to recognize them before they happen |
| 👥 Team Page | Meet the people behind ShieldMe |

---

## 🛠️ Tech Stack

**Backend**
- Python 3.x
- Flask + Flask-CORS
- scikit-learn (Stacking Ensemble Model, TF-IDF Vectorizer)
- YARA (file signature scanning)
- Google Generative AI SDK (`google-generativeai`)
- joblib / pickle (model serialization)
- python-dotenv
- markdown

**Frontend**
- HTML5 / CSS3 / Vanilla JavaScript
- Firebase Hosting

**AI**
- Google Gemini 2.5 Flash

---

## 📁 Project Structure

```
ShieldMe/
│
├── app.py                  # Main Flask application & unified /scan endpoint
├── predict.py              # Email/text ML inference logic
├── url_predict.py          # URL feature extraction & inference logic
├── chatbot.py              # Prompt builder & routing to Gemini
├── gemini_service.py       # Gemini API client
│
├── stacking_model.pkl      # Trained stacking ensemble for email classification
├── tfidf_vectorizer.pkl    # TF-IDF vectorizer for email features
├── url_model.pkl           # Trained ML model for URL classification
├── url_columns.pkl         # Feature column order for URL model
│
├── rules.yar               # YARA rules for file threat detection
│
├── index.html              # Frontend entry point
├── style.css               # Stylesheet
├── script.js               # Frontend logic & API calls
│
├── firebase.json           # Firebase Hosting configuration
├── .env                    # API keys (not committed — see below)
└── URLs_Clean.csv          # Clean URL dataset used for training
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- pip
- A [Google Gemini API Key](https://ai.google.dev/)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-username/shieldme.git
cd shieldme

# 2. Install Python dependencies
pip install flask flask-cors yara-python joblib scikit-learn pandas \
            google-generativeai python-dotenv markdown

# 3. Set up your environment variables (see below)
```

---

## 🔑 Environment Variables

Create a `.env` file in the root directory:

```env
GEMINI_API_KEY=your_gemini_api_key_here
```

> ⚠️ **Never commit your `.env` file.** Make sure it is listed in your `.gitignore`.

---

## ▶️ Running the App

```bash
# Start the Flask backend
python app.py
```

The backend will start on **http://localhost:5000**

For the frontend, either open `index.html` directly in your browser, or deploy it to Firebase (see [Deployment](#-deployment)).

---

## ⚙️ How It Works

### `/scan` — Unified Endpoint

All threat detection is routed through a single `POST /scan` endpoint:

```
Frontend → POST /scan
             │
             ├── Text / URL input?
             │     ├── Starts with http:// or www.? → URL Model → Gemini Explanation
             │     └── Plain text?                  → Email Model → Gemini Explanation
             │
             └── File upload?
                   └── YARA Engine → Threat Description (Arabic + English)
```

### Gemini AI Integration

After every local model prediction, the result is passed to `chatbot.py`, which constructs a structured cybersecurity prompt combining the original input and the ML verdict. Gemini returns a response with:

1. A direct answer (safe or dangerous)
2. A "Why?" explanation
3. A numbered breakdown of suspicious indicators
4. An "Advice:" section with actionable steps

The Markdown response is converted to HTML using Python's `markdown` library before being sent to the frontend.

---

## 🧨 Threat Coverage

### Email / Text Threats
| Threat Type | Trigger Keywords |
|---|---|
| Phishing Attack | password, login, verify, account |
| Prize Scam | winner, prize, lottery, reward |
| Financial Fraud | bank, payment, credit card |
| General Spam | any other spam pattern |

### File Threats (YARA Rules)
| Rule | Description |
|---|---|
| `Suspicious_PDF_With_JS` | PDF with hidden auto-executing JavaScript |
| `Suspicious_PDF_External_Launch` | PDF that launches external programs |
| `Malicious_Office_Macro` | Office document with suspicious VBA macros |
| `PHP_WebShell_Commands` | PHP web shell for server compromise |
| `Suspicious_Memory_Injection` | Code injection into running processes |
| `InfoStealer_Browser_Data` | Credential harvesting from browsers |
| `Hidden_PowerShell_Execution` | Obfuscated PowerShell bypass attempts |

### URL Features Analyzed
`url_length` · `count_dots` · `count_slash` · `count_digits` · `digit_ratio` · `is_https` · `has_ip` · `path_length` · `hostname_length` · `count_subdomains`

---

## 🌐 Deployment

The frontend is deployed via **Firebase Hosting**.

```bash
# Install Firebase CLI (if not already installed)
npm install -g firebase-tools

# Login and deploy
firebase login
firebase deploy
```

Firebase is configured to route all paths to `index.html` (SPA mode), as defined in `firebase.json`.

The Flask backend should be deployed separately (e.g., on a cloud VM, Railway, or Render) and the frontend `script.js` updated to point to the live backend URL.

---

## 👥 Team

Built by students of the Faculty of Computers and Information as a graduation project.

| Name | Role |
|---|---|
| [Team Member 1] | Backend & ML Engineering |
| [Team Member 2] | Frontend Development |
| [Team Member 3] | Cybersecurity & YARA Rules |
| [Team Member 4] | AI Integration & Documentation |

**Supervised by:** Dr. Eman Nassar

---

## 📄 License

This project is for academic purposes. All rights reserved © 2025 ShieldMe Team.

---

<p align="center">
  <strong>🛡️ ShieldMe — Stay Safe. Stay Smart.</strong>
</p>
