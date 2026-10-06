# CyberSentinel Pro — Setup Guide

Restructured backend: each model (SMS / Email / URL) now trains on its own
dataset in its own folder under `backend/detection/`, and `train_all.py`
trains all three in one run. Frontend and everything else is unchanged.

## 1. Prerequisites
- Python 3.10+
- MongoDB running locally (or a MongoDB Atlas connection string)
- A Gemini API key (for the LLM link/page-content check)

## 2. Get the code
Unzip this project anywhere, then open a terminal in the project's root
folder (the one containing `backend/` and `frontend/`).

## 3. Create a virtual environment
```
python -m venv venv
```
Activate it:
- Windows: `venv\Scripts\activate`
- macOS/Linux: `source venv/bin/activate`

## 4. Install dependencies
```
pip install -r backend/requirements.txt
```

## 5. Configure environment variables
Open `backend/.env` and fill in your own values (it already has the
right variable names):
```
SECRET_KEY=...
MONGO_URI=...
MONGO_DB_NAME=cyber_sentinel
VIRUSTOTAL_API_KEY=...
GOOGLE_SAFE_BROWSING_API_KEY=...
GOOGLE_API_KEY=...           # Gemini key, used for the LLM page-content check
GEMINI_MODEL=gemini-3.8-flash
ADMIN_EMAIL=...
ADMIN_PASSWORD=...
```
Make sure MongoDB is running and `MONGO_URI` points to it.

## 6. Train the models (first time only)
```
cd backend
python train_all.py
```
This trains and saves all three models:
- `backend/models/sms_model.pkl`
- `backend/models/email_body_model.pkl`
- `backend/models/url_model.pkl`

You can retrain a single model on its own without touching the others,
e.g.:
```
python detection/sms/train_sms.py
python detection/email/train_email.py
python detection/url/train_url.py
```

## 7. Run the backend
```
python app.py
```
Server starts at: **http://127.0.0.1:5000**

On Windows, you can instead just double-click `start.bat` from the
project root — it checks whether models exist, trains them if missing,
then starts the server.

## 8. Open the frontend
The Flask server serves the frontend automatically — just open
**http://127.0.0.1:5000** in your browser. (The `frontend/` folder can
also be opened directly for static preview, but API calls need the
backend running.)

## Project layout
```
CyberSentinel-Pro/
├── frontend/                 # HTML/CSS/JS, unchanged
├── backend/
│   ├── app.py                 # Flask entry point
│   ├── train_all.py           # trains all 3 models in one run
│   ├── config.py, database.py
│   ├── auth/                  # login, JWT
│   ├── api/                   # route blueprints (detect/user/admin)
│   ├── detection/
│   │   ├── sms/                # data + train_sms.py + sms_detector.py
│   │   ├── email/               # data + train_email.py + email_detector.py
│   │   ├── url/                 # data + features.py + train_url.py + url_detector.py
│   │   └── link/                # link_inspector.py + llm_inspector.py (Gemini)
│   └── models/                 # trained .pkl files land here
├── tests/
└── requirements.txt
```
