import sys
import os
import socket
import tempfile
import shutil
import threading
import secrets
import urllib.parse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import tkinter as tk
from tkinter import messagebox, filedialog
import customtkinter as ctk # New UI
import qrcode
from PIL import Image, ImageTk, ImageGrab
import email
import ssl
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# --- Configuration ---
ctk.set_appearance_mode("System")  # Modes: system (default), light, dark
ctk.set_default_color_theme("blue")  # Themes: blue (default), dark-blue, green

class SecureHandler(SimpleHTTPRequestHandler):
    auth_token = None

    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(parsed_path.query)
        received_token = query_params.get('key', [None])[0]

        if received_token != self.auth_token:
            self.send_error(403, "Forbidden")
            return

        if parsed_path.path == '/upload':
            self.handle_upload_page()
            return
            
        self.path = parsed_path.path
        return super().do_GET()

    def handle_upload_page(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>ZyDrop Upload</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; text-align: center; padding: 20px; background: #f5f5f7; color: #333; }}
                .container {{ background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); max-width: 400px; margin: 40px auto; }}
                h2 {{ margin-top: 0; color: #111; }}
                input[type=file] {{ margin: 20px 0; display: block; width: 100%; }}
                input[type=submit] {{ background: #0071e3; color: white; border: none; padding: 12px 24px; border-radius: 8px; cursor: pointer; font-size: 16px; font-weight: 500; transition: background 0.2s; }}
                input[type=submit]:hover {{ background: #0077ed; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h2>📤 Send File</h2>
                <form action="/upload?key={self.auth_token}" method="post" enctype="multipart/form-data">
                    <input type="file" name="file" multiple required>
                    <br>
                    <input type="submit" value="Upload">
                </form>
            </div>
        </body>
        </html>
        """
        self.wfile.write(html.encode("utf-8"))

    def do_POST(self):
        try:
            parsed_path = urllib.parse.urlparse(self.path)
            query_params = urllib.parse.parse_qs(parsed_path.query)
            
            if query_params.get('key', [None])[0] != self.auth_token:
                self.send_error(403, "Forbidden")
                return
            
            content_type = self.headers.get('Content-Type')
            if not content_type:
                self.send_error(400, "Content-Type missing")
                return

            content_len = int(self.headers.get('Content-Length', 0))
            if content_len == 0:
                 self.send_error(400, "Content-Length missing")
                 return
            
            body = self.rfile.read(content_len)
            
            # Construct a dummy email message headers + body to parse multipart
            msg = email.message_from_bytes(
                b'Content-Type: ' + content_type.encode() + b'\r\n\r\n' + body
            )
            
            if not msg.is_multipart():
                self.send_error(400, "Not multipart content")
                return

            saved_files = []
            for part in msg.walk():
                if part.get_content_maintype() == 'multipart':
                    continue
                
                filename = part.get_filename()
                if not filename:
                    continue
                
                # Security: basic sanitization
                filename = os.path.basename(filename)
                
                with open(filename, 'wb') as f:
                    f.write(part.get_payload(decode=True))
                saved_files.append(filename)

            # Success
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"""
            <html><body style='font-family:-apple-system, sans-serif;text-align:center;padding:50px;background:#f5f5f7;'>
            <h1 style='color:#28a745'>✅ Upload Complete</h1>
            <p>Saved: {', '.join(saved_files)}</p>
            <a href='/upload?key={self.auth_token}' style='background:#e1e1e1;padding:10px 20px;text-decoration:none;border-radius:6px;color:#333;'>Upload Another</a>
            </body></html>
            """.encode('utf-8'))
            
        except Exception as e:
            self.send_error(500, f"Server Error: {str(e)}")

    def log_message(self, format, *args):
        pass

def get_best_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def generate_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"zydrop.local"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]), critical=False
    ).sign(key, hashes.SHA256())

    t_dir = tempfile.mkdtemp()
    cert_path = os.path.join(t_dir, "cert.pem")
    key_path = os.path.join(t_dir, "key.pem")

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        
    return cert_path, key_path, t_dir

class ServerThread(threading.Thread):
    def __init__(self, directory):
        super().__init__()
        self.directory = directory
        self.server = None
        self.port = 0
        self.ip = get_best_ip()
        self.daemon = True 

    def run(self):
        os.chdir(self.directory)
        # self.cert_file, self.key_file, self.ssl_dir = generate_cert() # SSL Disabled
        self.server = ThreadingHTTPServer(('0.0.0.0', 0), SecureHandler)
        # context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
        # self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_port
        self.server.serve_forever()

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        
        # if hasattr(self, 'ssl_dir') and self.ssl_dir:
        #      try:
        #         shutil.rmtree(self.ssl_dir)
        #      except:
        #         pass

class App:
    def __init__(self, target_path):
        self.root = ctk.CTk()
        self.root.resizable(False, False)
        # self.root.configure(bg="#f0f0f0") # CTk handles bg automatically
        self.server_thread = None
        self.temp_dir = None 

        self.root.title("ZyDrop - Secure Share")
        
        if target_path:
            self.start_sharing(target_path)
        else:
            self.create_selection_ui()

    def start_sharing(self, target_path, mode="share"):
        for widget in self.root.winfo_children():
            widget.destroy()

        self.root.geometry("400x520")

        if not os.path.exists(target_path):
            messagebox.showerror("Error", f"Path not found: {target_path}")
            if self.temp_dir:
                self.stop_sharing()
            else:
                sys.exit(1)
        
        current_token = secrets.token_urlsafe(8)
        SecureHandler.auth_token = current_token

        if mode == "upload":
            self.serve_dir = target_path
            display_text = f"Receive Mode: {os.path.basename(target_path)}"
            url_path = "/upload"
        elif os.path.isfile(target_path):
            self.serve_dir = os.path.dirname(target_path)
            filename = os.path.basename(target_path)
            display_text = f"File: {filename}"
            if filename == "clipboard_content.txt":
                display_text = "Clipboard Text"
            elif filename == "clipboard_image.png":
                display_text = "Clipboard Image"
            url_path = f"/{urllib.parse.quote(filename)}"
        else:
            try:
                self.temp_dir = tempfile.mkdtemp()
                folder_name = os.path.basename(target_path)
                base_name = os.path.join(self.temp_dir, folder_name)
                shutil.make_archive(base_name, 'zip', target_path)
                zip_filename = f"{folder_name}.zip"
                self.serve_dir = self.temp_dir
                display_text = f"Folder (Zipped): {zip_filename}"
                url_path = f"/{urllib.parse.quote(zip_filename)}"
            except Exception as e:
                messagebox.showerror("Error", f"Failed to zip folder: {e}")
                if self.temp_dir:
                    shutil.rmtree(self.temp_dir)
                sys.exit(1)

        self.server_thread = ServerThread(self.serve_dir)
        self.server_thread.start()
        
        self.check_server_ready(url_path, display_text, current_token)

    def check_server_ready(self, url_path, display_text, current_token):
        if self.server_thread.port == 0:
            self.root.after(100, lambda: self.check_server_ready(url_path, display_text, current_token))
            return

        if hasattr(self, 'loading_label') and self.loading_label:
            self.loading_label.destroy()

        # Build HTTP URL
        full_url = f"http://{self.server_thread.ip}:{self.server_thread.port}{url_path}?key={current_token}"
        self.build_sharing_ui(full_url, display_text)

    def build_sharing_ui(self, full_url, display_text):
        # --- Modern UI ---
        main_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        main_frame.pack(expand=True, fill="both", padx=20, pady=20)

        btn_back = ctk.CTkButton(main_frame, text="← Back", command=self.stop_sharing, width=60, height=24, fg_color="transparent", text_color=("blue", "#4da6ff"))
        btn_back.place(x=-10, y=-10)

        ctk.CTkLabel(main_frame, text="Scan to Download", font=("Helvetica", 18, "bold")).pack(pady=(20, 5))
        ctk.CTkLabel(main_frame, text=display_text, font=("Consolas", 12), text_color="gray").pack(pady=(0, 20))

        qr = qrcode.QRCode(box_size=10, border=2)
        qr.add_data(full_url)
        qr.make(fit=True)
        # Using white/black strictly for QR readability even in dark mode
        qr_img = qr.make_image(fill_color="black", back_color="white")
        
        # CTkImage for High DPI scaling
        self.qr_photo = ctk.CTkImage(light_image=qr_img.get_image(), dark_image=qr_img.get_image(), size=(250, 250))
        
        # QR Display
        qr_label = ctk.CTkLabel(main_frame, image=self.qr_photo, text="")
        qr_label.pack(pady=10)

        ctk.CTkLabel(main_frame, text="Network Connection (HTTP)", font=("Arial", 12), text_color="blue").pack(pady=5)
        
        ctk.CTkButton(main_frame, text="Copy Link", command=lambda: self.copy_to_clipboard(full_url)).pack(fill="x", pady=10)
        ctk.CTkButton(main_frame, text="Stop Server", command=self.on_close, fg_color="red", hover_color="#cc0000").pack(fill="x", pady=5)

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def create_selection_ui(self):
        self.root.geometry("400x420")
        
        selection_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        selection_frame.pack(expand=True, fill="both", padx=30, pady=30)

        ctk.CTkLabel(selection_frame, text="ZyDrop", font=("Helvetica", 24, "bold")).pack(pady=(0, 5))
        ctk.CTkLabel(selection_frame, text="Secure LAN Sharing", font=("Arial", 14), text_color="gray").pack(pady=(0, 30))

        # Buttons
        ctk.CTkButton(selection_frame, text="Share File", command=self.select_file, height=40).pack(fill="x", pady=8)
        ctk.CTkButton(selection_frame, text="Share Folder", command=self.select_folder, height=40).pack(fill="x", pady=8)
        ctk.CTkButton(selection_frame, text="Clipboard", command=self.share_from_clipboard, height=40, fg_color="gray").pack(fill="x", pady=8)
        ctk.CTkButton(selection_frame, text="Receive Files", command=self.receive_files, height=40, fg_color="orange", text_color="black").pack(fill="x", pady=8)

    def receive_files(self):
        folderpath = filedialog.askdirectory(title="Select folder to save received files")
        if folderpath:
            self.start_sharing(folderpath, mode="upload")

    def select_file(self):
        filepath = filedialog.askopenfilename(title="Select a file to share")
        if filepath:
            self.start_sharing(filepath)

    def select_folder(self):
        folderpath = filedialog.askdirectory(title="Select a folder to share")
        if folderpath:
            self.start_sharing(folderpath)

    def share_from_clipboard(self):
        clipboard_image = ImageGrab.grabclipboard()
        if isinstance(clipboard_image, Image.Image):
            self.temp_dir = tempfile.mkdtemp()
            temp_file_path = os.path.join(self.temp_dir, "clipboard_image.png")
            clipboard_image.save(temp_file_path, "PNG")
            self.start_sharing(temp_file_path)
            return

        try:
            clipboard_content = self.root.clipboard_get()
            if not clipboard_content.strip():
                messagebox.showinfo("Empty", "Clipboard is empty.")
                return
            
            self.temp_dir = tempfile.mkdtemp()
            temp_file_path = os.path.join(self.temp_dir, "clipboard_content.txt")
            with open(temp_file_path, "w", encoding="utf-8") as f:
                f.write(clipboard_content)
            self.start_sharing(temp_file_path)
        except tk.TclError:
            messagebox.showinfo("Empty", "Clipboard is empty.")

    def copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Copied", "Link copied!")

    def stop_sharing(self):
        if self.server_thread:
            self.server_thread.stop()
            self.server_thread = None
        
        if self.temp_dir:
            try:
                shutil.rmtree(self.temp_dir)
            except:
                pass
            self.temp_dir = None
            
        for widget in self.root.winfo_children():
            widget.destroy()
            
        self.create_selection_ui()

    def on_close(self):
        if self.server_thread:
            self.server_thread.stop()
        if self.temp_dir:
            try:
                shutil.rmtree(self.temp_dir)
            except:
                pass
        try:
            self.root.destroy()
        except:
            pass
        finally:
            sys.exit(0)

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    path_arg = sys.argv[1] if len(sys.argv) > 1 else None
    app = App(path_arg)
    app.run()
