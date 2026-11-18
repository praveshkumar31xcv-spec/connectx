# ConnectX – Private Chat & Video Calling

A complete, professional real-time messaging and video calling web application built with **Flask + Socket.IO + WebRTC + SQLite**.

## ✨ Features

- 🔐 Secure authentication (bcrypt password hashing)
- 💬 Real-time private messaging with typing indicators, delivery receipts, edit/delete
- 📎 Image & file sharing
- 👥 Friend request system (send, accept, reject, block)
- 📞 1-on-1 audio calls (WebRTC)
- 📹 1-on-1 video calls (WebRTC, peer-to-peer)
- 🟢 Live online/offline presence
- 🔔 Real-time notifications
- 📊 Call history
- 🌓 Dark/Light theme
- 🛡️ Admin panel
- 📱 Fully responsive

## 🚀 Installation (Windows)

### Prerequisites
- Python 3.10+
- A modern browser (Chrome, Edge, Firefox)

### Step 1 — Install dependencies
```bash
cd connectx
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt