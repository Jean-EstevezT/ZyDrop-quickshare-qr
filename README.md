# ⚡ ZyDrop (QuickSecure Share)

**ZyDrop** is a modern, ultra-secure LAN file sharing tool designed to make transferring files, folders, and clipboard content between devices as easy as scanning a QR code.

Built with **Python**, it runs a local HTTPS server protected by dynamic token authentication, ensuring your data is encrypted and safe even on public Wi-Fi networks.

---

## ✨ Features

- **🔒 Maximum Security (HTTPS + Token)**
  - Uses **SSL/HTTPS** encryption (self-signed) to prevent data eavesdropping.
  - Generates a **random access token** for every session.
  - Token rotates automatically with every new share.

- **📤 Universal Sharing**
  - **Files:** Share individual files of any size.
  - **Folders:** Automatically zips folders on-the-fly for single-click downloads.
  - **Clipboard:** Share text or images directly from your clipboard.

- **📥 Receive Mode**
  - Allow others to upload files *to* your computer via a secure web page.

- **🎨 Modern UI**
  - sleek, dark/light mode interface built with `CustomTkinter`.

- **🖱️ OS Integration**
  - Right-click Context Menu support for **Windows** and **Linux**.
  - "Share with ZyDrop" straight from your file explorer.

---

## 🚀 Installation & Setup

### 1. Requirements
- Python 3.10+
- Dependencies: `customtkinter`, `cryptography`, `qrcode`, `Pillow`

### 2. Quick Start
Clone the repo and install dependencies:

```bash
git clone https://github.com/Jean-EstevezT/ZyDrop-quickshare-qr.git
cd ZyDrop-quickshare-qr

# Create virtual environment (optional but recommended)
python -m venv .venv
# Activate it:
# Windows: .venv\Scripts\activate
# Linux/Mac: source .venv/bin/activate

# Install requirements
pip install -r requirements.txt
```

### 3. Run the App
Can be run in two modes:

- **Modern Mode (Recommended):**
  ```bash
  python modern_script.py
  ```
- **Classic/Legacy Mode:**
  ```bash
  python script.pyw
  ```

---

## 🔧 Context Menu Integration (Right-Click)

Make ZyDrop a part of your OS for instant access.

**Run the installer:**
```bash
python install_script.py
```

- Select **Option 1 (Install)**.
- **Windows:** Grants "Share with ZyDrop" in right-click menu (Requires Admin).
- **Linux:** Adds a Desktop Entry for "Open with..." integration.

*(To remove, simply run the script again and select Uninstall)*

---

## 📱 How to Use

1. **Select what to share:** File, Folder, Clipboard, or Activate Receive Mode.
2. **Scan the QR Code:** Use your phone camera or visit the link on another PC.
3. **Accept validity warning:** Since we use a self-signed secure certificate to protect your data without internet, browsers will warn you.
   - Click **"Advanced"** -> **"Proceed to (unsafe)"**.
   - Your connection **IS encrypted** and safe from local sniffers.
4. **Download/Upload:** Transfer your files instantly.
5. **Stop:** Closing the app kills the server and cleans up all temporary files immediately.

---

## 🛠️ Technologies
- **Python 3**
- **CustomTkinter** (UI)
- **Cryptography** (SSL/TLS Generation)
- **HTTPS.server** (Core implementation)