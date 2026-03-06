import os
os.environ["PATH"] += os.pathsep + r"C:\ffmpeg\ffmpeg-8.0.1-essentials_build\bin"

import re
import uuid
import torch
import joblib
import shutil
import subprocess
import email
from email import policy
from email.parser import BytesParser
from datetime import datetime
from fastapi import FastAPI, UploadFile, File
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from PIL import Image
import pytesseract
import pdfplumber
import docx
import whisper

# ----------------------------
# APP INIT
# ----------------------------
app = FastAPI(title="FraudLink Guard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

# ----------------------------
# MONGODB
# ----------------------------
client = MongoClient("mongodb://localhost:27017/")
db = client["fraudlink_guard"]
reports_collection = db["reports"]

# ----------------------------
# LOAD ML MODEL
# ----------------------------
ml_model = joblib.load(os.path.join(BASE_DIR, "scam_model.pkl"))
ml_vectorizer = joblib.load(os.path.join(BASE_DIR, "vectorizer.pkl"))

device = "cuda" if torch.cuda.is_available() else "cpu"
whisper_model = whisper.load_model("base", device=device)

print(f"🔥 Whisper running on: {device}")

def ml_predict(text: str) -> str:
    vector = ml_vectorizer.transform([text])
    return ml_model.predict(vector)[0]

# ----------------------------
# RULE DATA
# ----------------------------
SCAM_KEYWORDS = ["bank","kyc","otp","urgent","click here","account blocked","verify","prize","lottery"]
SHORT_URL_DOMAINS = ["bit.ly","tinyurl.com","goo.gl","t.co","ow.ly","is.gd","buff.ly"]
SUSPICIOUS_DOMAIN_WORDS = ["bank","login","secure","verify","update","account","reward","prize"]

# ----------------------------
# HELPER FUNCTIONS
# ----------------------------
def contains_url(text):
    return bool(re.search(r"(https?://|www\.)", text))

def contains_short_url(text):
    return any(domain in text for domain in SHORT_URL_DOMAINS)

def contains_ip_url(text):
    return bool(re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))

def contains_suspicious_domain(text):
    matches = re.findall(r"(https?://)?([a-zA-Z0-9\-]+\.[a-zA-Z]{2,})", text)
    for _, domain in matches:
        for word in SUSPICIOUS_DOMAIN_WORDS:
            if word in domain.lower():
                return True
    return False

# ----------------------------
# OCR FUNCTIONS
# ----------------------------
def extract_text_from_image(path):
    return pytesseract.image_to_string(Image.open(path))

def extract_text_from_pdf(path):
    text = ""
    with pdfplumber.open(path) as pdf:
        for page in pdf.pages:
            text += page.extract_text() or ""
    return text

def extract_text_from_docx(path):
    doc = docx.Document(path)
    return "\n".join(p.text for p in doc.paragraphs)

def extract_text_from_txt(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()

# ----------------------------
# CORE TEXT ANALYSIS
# ----------------------------
def analyze_text(text: str):

    original_text = text
    text = text.lower()

    matched_keywords = [w for w in SCAM_KEYWORDS if w in text]
    url_found = contains_url(text)
    short_url = contains_short_url(text)
    ip_url = contains_ip_url(text)
    suspicious_domain = contains_suspicious_domain(text)
    ml_result = ml_predict(text)

    risk_score = (
        len(matched_keywords)
        + (1 if short_url else 0)
        + (1 if ip_url else 0)
        + (1 if suspicious_domain else 0)
        + (1 if ml_result == "scam" else 0)
    )

    if risk_score >= 4:
        risk_level = "HIGH"
    elif risk_score >= 2:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    status = "FAKE" if risk_level != "LOW" else "SAFE"

    report = {
        "text": original_text,
        "status": status,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "keywords": matched_keywords,
        "url_detected": url_found,
        "short_url_detected": short_url,
        "ip_url_detected": ip_url,
        "suspicious_domain_detected": suspicious_domain,
        "ml_prediction": ml_result,
        "created_at": datetime.utcnow()
    }

    inserted = reports_collection.insert_one(report)

    report["_id"] = str(inserted.inserted_id)
    report["created_at"] = report["created_at"].isoformat()

    return report

# ----------------------------
# EMAIL ANALYSIS
# ----------------------------
def analyze_email(file_path):

    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    sender = msg["from"] or ""
    subject = msg["subject"] or ""
    body = ""

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain" and part.get_content_disposition() != "attachment":
                body += part.get_payload(decode=True).decode(errors="ignore")
    else:
        body = msg.get_payload(decode=True).decode(errors="ignore")

    attachments = [
        part.get_filename()
        for part in msg.walk()
        if part.get_content_disposition() == "attachment"
    ]

    suspicious_sender = False
    if sender and "@" in sender:
        domain = sender.split("@")[-1].lower()
        if any(word in domain for word in SUSPICIOUS_DOMAIN_WORDS):
            suspicious_sender = True

    received_headers = msg.get_all("Received", [])
    spoofing_detected = len(received_headers) <= 1

    text_analysis = analyze_text(body)
    risk_score = text_analysis["risk_score"]

    if suspicious_sender:
        risk_score += 2
    if spoofing_detected:
        risk_score += 2
    if attachments:
        risk_score += 1

    if risk_score >= 6:
        gmail_label = "DANGEROUS"
    elif risk_score >= 3:
        gmail_label = "SUSPICIOUS"
    else:
        gmail_label = "SAFE"

    return {
        "sender": sender,
        "subject": subject,
        "attachments": attachments,
        "gmail_label": gmail_label,
        "risk_score": risk_score,
        "body_analysis": text_analysis
    }

# ----------------------------
# REQUEST MODEL
# ----------------------------
class MessageRequest(BaseModel):
    text: str

# ----------------------------
# ROUTES
# ----------------------------
@app.get("/")
def home():
    return {"message": "FraudLink Guard Backend Running"}

@app.post("/detect")
def detect_message(data: MessageRequest):
    return analyze_text(data.text)

@app.post("/upload-detect")
def upload_and_detect(file: UploadFile = File(...)):

    upload_dir = os.path.join(BASE_DIR, "uploads")
    os.makedirs(upload_dir, exist_ok=True)

    file_path = os.path.join(upload_dir, file.filename)

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    name = file.filename.lower()

    if name.endswith((".png",".jpg",".jpeg")):
        text = extract_text_from_image(file_path)
        return analyze_text(text)

    elif name.endswith(".pdf"):
        text = extract_text_from_pdf(file_path)
        return analyze_text(text)

    elif name.endswith(".docx"):
        text = extract_text_from_docx(file_path)
        return analyze_text(text)

    elif name.endswith(".txt"):
        text = extract_text_from_txt(file_path)
        return analyze_text(text)

    elif name.endswith(".eml"):
        return analyze_email(file_path)

    else:
        return {"error":"Unsupported file type"}

# ----------------------------
# VOICE DETECT
# ----------------------------
@app.post("/voice-detect")
def voice_detect(audio: UploadFile = File(...)):

    upload_dir = os.path.join(BASE_DIR, "uploads")
    os.makedirs(upload_dir, exist_ok=True)

    unique_id = str(uuid.uuid4())
    original_ext = audio.filename.split(".")[-1]

    input_path = os.path.join(upload_dir, f"{unique_id}.{original_ext}")
    output_path = os.path.join(upload_dir, f"{unique_id}.wav")

    with open(input_path, "wb") as f:
        f.write(audio.file.read())

    subprocess.run([
        "ffmpeg","-y","-i",input_path,
        "-ar","16000","-ac","1",output_path
    ], check=True)

    result = whisper_model.transcribe(
        output_path,
        fp16=torch.cuda.is_available()
    )

    text = result.get("text","").strip()

    if not text:
        return {"status":"ERROR","message":"No speech detected"}

    report = analyze_text(text)
    report["transcribed_text"] = text

    return report

# ----------------------------
# HISTORY
# ----------------------------
@app.get("/history")
def get_scan_history(limit: int = 10):

    reports = reports_collection.find({}).sort("created_at",-1).limit(limit)

    history = []

    for r in reports:
        history.append({
            "text": r["text"][:80] + "..." if len(r["text"])>80 else r["text"],
            "status": r["status"],
            "risk_level": r["risk_level"],
            "created_at": r["created_at"].isoformat()
        })

    return history