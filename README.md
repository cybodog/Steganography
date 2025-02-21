# 🔒 AES-DCT Steganography

## 📌 Problem Statement
Traditional encryption methods secure data but make it obvious that encryption is being used. This project implements AES encryption with Discrete Cosine Transform (DCT)-based steganography to **hide encrypted data within an image**, making it undetectable while ensuring security.

## 🚀 Features
✅ **AES Encryption**: Ensures secure message encryption.  
✅ **DCT-Based Steganography**: Hides encrypted data within image frequency components.  
✅ **Drag & Drop Support**: Easily select files via GUI.  
✅ **Lossless Extraction**: Recovers original message without data loss.  
✅ **GUI-Based Interface**: Simple & interactive user experience using Tkinter.  
✅ **Optimized Performance**: Efficient encoding & decoding for real-time applications.  

## 🛠️ Technologies Used
- **Python** (Core programming language)
- **AES Encryption** (PyCryptodome for encryption & decryption)
- **DCT Steganography** (Image processing with OpenCV & NumPy)
- **OpenCV** (Image processing & transformation)
- **Tkinter & tkinterdnd2** (GUI & drag-and-drop support)
- **PIL (Pillow)** (Image manipulation)
- **zlib** (Compression to optimize message embedding)

---

## 📥 Installation

### 1️⃣ Clone the Repository  
```sh
git clone https://github.com/cybodog/Steganography.git
cd Steganography
###Install Dependencies
Make sure you have Python installed (Recommended: Python 3.8+). Then, install the required packages using:
pip install opencv-python numpy matplotlib pillow pycryptodome tkinterdnd2
### 3️⃣ Run the Application
python stegno.py
## ✨ Wow Factor
- Combines **encryption (AES)** and **steganography (DCT)** for double-layer security.
- Hidden data remains visually undetectable.
- Secure transmission of sensitive information via images.
- Efficient implementation using optimized mathematical techniques.

## 🎯 End Users
- **Cybersecurity Enthusiasts**: To learn and implement secure communication techniques.
- **Journalists & Activists**: For securely transmitting confidential data.
- **Military & Intelligence Agencies**: For covert communication.
- **Data Privacy Advocates**: Ensuring secure personal data exchange.

## 🚀 Result
- AES encryption secures the message.
- DCT transforms the image into frequency components to embed encrypted data.
- The modified image contains the encrypted data while appearing unchanged.
- The hidden data is extracted and decrypted successfully.

## 🔚 Conclusion
This project successfully demonstrates the combination of encryption and steganography for secure and undetectable data transmission. It enhances cybersecurity applications by ensuring confidentiality and integrity while keeping the data visually hidden.

## 🔮 Future Scope
- Implementing **Deep Learning** for enhanced steganalysis resistance.
- Extending to **video steganography** for larger data embedding.
- Optimizing the algorithm for **real-time communication systems**.
- Implementing a **GUI-based tool** for user-friendly operation.

---
🔒 **Stay Secure, Stay Hidden!** 🔒
