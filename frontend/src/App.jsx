import { useState } from "react";
import "./App.css";

/* ================= TRANSLATIONS ================= */
const MESSAGES = {
  SAFE: {
    en: "✅ This content is safe.",
    te: "✅ ఈ కంటెంట్ సురక్షితంగా ఉంది.",
    hi: "✅ यह सुरक्षित है।",
  },
  FAKE: {
    en: "🚨 This is a scam message. Do not click links or share OTP.",
    te: "🚨 ఇది మోసపూరిత సందేశం. దయచేసి లింక్‌లు లేదా OTP పంచుకోవద్దు.",
    hi: "🚨 यह धोखाधड़ी संदेश है। लिंक या OTP साझा न करें।",
  },
  SUSPICIOUS: {
    en: "⚠️ This looks suspicious. Please verify carefully.",
    te: "⚠️ ఇది అనుమానాస్పదంగా ఉంది. దయచేసి జాగ్రత్తగా పరిశీలించండి.",
    hi: "⚠️ यह संदिग्ध लग रहा है। कृपया सावधानी से जांचें।",
  },
  DANGEROUS: {
    en: "🚨 Dangerous email detected. High scam risk!",
    te: "🚨 ప్రమాదకరమైన ఇమెయిల్ గుర్తించబడింది. అధిక మోసం ప్రమాదం!",
    hi: "🚨 खतरनाक ईमेल पाया गया। उच्च धोखाधड़ी जोखिम!",
  }
};

function speakText(text, lang) {
  window.speechSynthesis.cancel();
  const msg = new SpeechSynthesisUtterance(text);
  msg.lang = lang === "te" ? "te-IN" : lang === "hi" ? "hi-IN" : "en-US";
  window.speechSynthesis.speak(msg);
}

function App() {
  const [message, setMessage] = useState("");
  const [file, setFile] = useState(null);
  const [audioFile, setAudioFile] = useState(null);
  const [lang, setLang] = useState("en");
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [showHistory, setShowHistory] = useState(false);
  const [loading, setLoading] = useState(false);

  const checkMessage = async () => {
    let response;

    try {
      setLoading(true);

      if (file) {
        const formData = new FormData();
        formData.append("file", file);

        response = await fetch("http://localhost:8000/upload-detect", {
          method: "POST",
          body: formData,
        });
      } else {
        if (!message.trim()) {
          alert("Please paste text or upload a file.");
          setLoading(false);
          return;
        }

        response = await fetch("http://localhost:8000/detect", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text: message }),
        });
      }

      const data = await response.json();
      const translatedText = MESSAGES[data.status]?.[lang] || MESSAGES[data.status]?.en;

      setResult({ ...data, translatedText });
      speakText(translatedText, lang);

    } catch {
      alert("Backend not reachable");
    } finally {
      setLoading(false);
    }
  };

  const checkAudio = async () => {
    if (!audioFile) {
      alert("Please upload audio");
      return;
    }

    setLoading(true);

    const formData = new FormData();
    formData.append("audio", audioFile);

    try {
      const response = await fetch("http://localhost:8000/voice-detect", {
        method: "POST",
        body: formData,
      });

      const data = await response.json();
      const translatedText = MESSAGES[data.status]?.[lang] || MESSAGES[data.status]?.en;

      setResult({ ...data, translatedText });
      speakText(translatedText, lang);

    } finally {
      setLoading(false);
    }
  };

  const loadHistory = async () => {
    const response = await fetch("http://localhost:8000/history");
    const data = await response.json();
    setHistory(data);
    setShowHistory(true);
    setResult(null);
  };

  return (
    <>
      {/* FULL SCREEN LOADING OVERLAY */}
      {loading && (
        <div className="loading-screen">
          <div className="scanner">
            <div className="emoji">🕵️‍♂️</div>
            <h2>Analyzing Message...</h2>
            <p>Checking links, domains & fraud patterns</p>
            <div className="scan-bar"></div>
          </div>
        </div>
      )}

      <div className="app-wrapper">
        <div className="card">
          <h1 className="title">🛡️ <span>FraudLink Guard</span></h1>
          <p className="subtitle">Real-Time Scam Link & Message Detection</p>

          {!showHistory && (
            <>
              <div className="input-box">
                <textarea
                  placeholder="Paste suspicious message..."
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                />
              </div>

              <div className="upload-box">
                <label>📂 Upload Image / PDF / DOC / TXT Files & Emails (.eml)</label>
                <input
                  type="file"
                  accept=".png,.jpg,.jpeg,.pdf,.docx,.txt,.eml"
                  onChange={(e) => setFile(e.target.files[0])}
                />
              </div>

              <div className="upload-box">
                <label>🎵 Upload Audio (MP3 / WAV / MP4 / M4A)</label>
                <input
                  type="file"
                  accept="audio/*,video/*"
                  onChange={(e) => setAudioFile(e.target.files[0])}
                />
              </div>

              <select className="language-select" value={lang} onChange={(e) => setLang(e.target.value)}>
                <option value="en">English</option>
                <option value="te">తెలుగు</option>
                <option value="hi">हिंदी</option>
              </select>

              <div className="button-group">
                <button className="check-btn" onClick={checkMessage}>🔍 Check Text / File</button>
                <button className="check-btn" onClick={checkAudio}>🔊 Check Audio</button>
                <button className="check-btn history-btn" onClick={loadHistory}>📜 View History</button>
              </div>
            </>
          )}

          {result && (
            <div className={`result-box ${
              result.status === "FAKE" || result.status === "DANGEROUS"
                ? "fake"
                : result.status === "SUSPICIOUS"
                ? "warning"
                : "safe"
            }`}>
              <h2>
                {result.status === "SAFE" && "✅ SAFE"}
                {result.status === "FAKE" && "🚨 SCAM"}
                {result.status === "SUSPICIOUS" && "⚠️ SUSPICIOUS"}
                {result.status === "DANGEROUS" && "🚨 HIGH RISK"}
              </h2>

              <p>{result.translatedText || "No message returned"}</p>

              {result.risk_level && (
                <p><strong>Risk Level:</strong> {result.risk_level}</p>
              )}
            </div>
          )}

          {showHistory && (
            <div className="result-box safe">
              <h2>📜 Scan History</h2>
              {history.map((item, i) => <p key={i}>{item.text}</p>)}
              <button className="check-btn" onClick={() => setShowHistory(false)}>⬅ Back</button>
            </div>
          )}
        </div>
      </div>
    </>
  );
}

export default App;