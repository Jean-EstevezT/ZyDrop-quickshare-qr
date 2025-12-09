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
# AUTH_TOKEN moved to SecureHandler class for rotation capability

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
                
                # Write file to current working directory (which is set to serve_dir)
                # Ensure unique name if exists? For simplicity, overwrite or append.
                # Let's simple write.
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
        # Silenciar logs en consola para mejorar rendimiento y limpieza
        pass

def get_best_ip():
    """
    Tries to get the real LAN IP by connecting to a public DNS.
    It doesn't send real data, just opens the socket to see which interface the OS uses.
    """
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
    """Runs the server in the background without freezing the GUI."""
    def __init__(self, directory):
        super().__init__()
        self.directory = directory
        self.server = None
        self.port = 0
        self.ip = get_best_ip()
        self.daemon = True # The thread dies if the main program dies

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
        self.root = tk.Tk()
        self.root.resizable(False, False)
        self.root.configure(bg="#f0f0f0")
        self.server_thread = None
        self.temp_dir = None # To store the path of a temporary directory if created

        if target_path:
            self.root.title("Secure LAN Share")
            self.start_sharing(target_path)
        else:
            self.root.title("ZyDrop - Select to Share")
            self.create_selection_ui()

    def start_sharing(self, target_path, mode="share"):
        """Initializes the server and QR code UI for the given path.
           mode: "share" (default) or "upload"
        """
        # Clear previous widgets if any
        for widget in self.root.winfo_children():
            widget.destroy()

        self.root.geometry("380x500")

        # Validate path
        if not os.path.exists(target_path):
            messagebox.showerror("Error", f"Path not found: {target_path}")
            # If it's a temp file that failed, we might not want to exit
            # but for now, this is safe.
            if self.temp_dir:
                self.stop_sharing()
            else:
                sys.exit(1)
        
        
        # Security: Rotate token
        current_token = secrets.token_urlsafe(8)
        SecureHandler.auth_token = current_token

        # File vs. Folder vs. Upload Logic
        if mode == "upload":
            # Target path is where we save files
            self.serve_dir = target_path
            display_text = f"Receive Mode: {os.path.basename(target_path)}"
            url_path = "/upload"
        elif os.path.isfile(target_path):
            self.serve_dir = os.path.dirname(target_path)
            filename = os.path.basename(target_path)
            display_text = f"File: {filename}"
            # URL points directly to the file
            # Special case for clipboard text
            if filename == "clipboard_content.txt":
                display_text = "Clipboard Text"
            elif filename == "clipboard_image.png":
                display_text = "Clipboard Image"
            url_path = f"/{urllib.parse.quote(filename)}"
        else:
            # Folder Logic: Zip it first
            try:
                self.temp_dir = tempfile.mkdtemp()
                folder_name = os.path.basename(target_path)
                
                # We save the zip file inside our temp directory
                # base_name doesn't include extension
                base_name = os.path.join(self.temp_dir, folder_name)
                
                # Create the zip archive
                # root_dir=target_path means we zip the CONTENTS of the folder
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

        # Start Server
        self.server_thread = ServerThread(self.serve_dir)
        self.server_thread.start()
        
        self.check_server_ready(url_path, display_text, current_token)

    def check_server_ready(self, url_path, display_text, current_token):
        if self.server_thread.port == 0:
            self.root.after(100, lambda: self.check_server_ready(url_path, display_text, current_token))
            return

        # Build HTTP URL
        full_url = f"http://{self.server_thread.ip}:{self.server_thread.port}{url_path}?key={current_token}"
        self.build_sharing_ui(full_url, display_text)

    def build_sharing_ui(self, full_url, display_text):
        # --- UI ---
        # main
        main_frame = tk.Frame(self.root, bg="#f0f0f0", padx=20, pady=20)
        main_frame.pack(expand=True, fill="both")

        # Back Button (Top Left)
        btn_back = tk.Button(main_frame, text="← Back", command=self.stop_sharing, bg="#f0f0f0", bd=0, fg="blue", font=("Arial", 10, "underline"), cursor="hand2")
        btn_back.place(x=-15, y=-15) # Simple absolute positioning for back button

        # Title
        tk.Label(main_frame, text="Scan to download", font=("Helvetica", 14, "bold"), bg="#f0f0f0").pack(pady=(15, 10))
        tk.Label(main_frame, text=display_text, font=("Consolas", 9), bg="#f0f0f0", fg="#555").pack(pady=(0, 15))

        # QR Code
        qr = qrcode.QRCode(box_size=10, border=2) # Increased size
        qr.add_data(full_url)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white")
        # Resize manually if needed to ensure large enough but for standard TK, box_size=10 usually yields a big enough image.
        self.photo = ImageTk.PhotoImage(qr_img)
        
        qr_label = tk.Label(main_frame, image=self.photo, bd=2, relief="solid")
        qr_label.pack(pady=10)

        # Security Info
        tk.Label(main_frame, text="Network Connection (HTTP)", font=("Arial", 8), fg="blue", bg="#f0f0f0").pack(pady=5)
        
        # Copy URL Button
        btn_copy = tk.Button(main_frame, text="Copy URL to Clipboard", command=lambda: self.copy_to_clipboard(full_url), bg="#e1e1e1")
        btn_copy.pack(fill="x", pady=5)

        # Close Button
        btn_stop = tk.Button(main_frame, text="Stop and Exit", command=self.on_close, bg="#ffcccc", fg="#cc0000", font=("Arial", 10, "bold"))
        btn_stop.pack(fill="x", pady=10)

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def create_selection_ui(self):
        """Creates the initial UI to ask the user to select a file or folder."""
        self.root.geometry("380x350")
        
        selection_frame = tk.Frame(self.root, bg="#f0f0f0", padx=20, pady=20)
        selection_frame.pack(expand=True, fill="both")

        tk.Label(selection_frame, text="What do you want to share?", font=("Helvetica", 14, "bold"), bg="#f0f0f0").pack(pady=(0, 20))

        btn_select_file = tk.Button(selection_frame, text="Share a File", command=self.select_file, font=("Arial", 11), bg="#d0e0f0", height=2)
        btn_select_file.pack(fill="x", pady=5)

        btn_select_folder = tk.Button(selection_frame, text="Share a Folder", command=self.select_folder, font=("Arial", 11), bg="#d0f0d0", height=2)
        btn_select_folder.pack(fill="x", pady=5)

        btn_share_clipboard = tk.Button(selection_frame, text="Share from Clipboard", command=self.share_from_clipboard, font=("Arial", 11), bg="#f0e0d0", height=2)
        btn_share_clipboard.pack(fill="x", pady=5)

        btn_receive = tk.Button(selection_frame, text="Receive Files", command=self.receive_files, font=("Arial", 11), bg="#ffecb3", height=2)
        btn_receive.pack(fill="x", pady=5)

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
        """Gets text or an image from clipboard, saves it to a temp file, and shares it."""
        clipboard_image = ImageGrab.grabclipboard()

        if isinstance(clipboard_image, Image.Image):
            # An image was found in the clipboard
            self.temp_dir = tempfile.mkdtemp()
            temp_file_path = os.path.join(self.temp_dir, "clipboard_image.png")
            clipboard_image.save(temp_file_path, "PNG")
            self.start_sharing(temp_file_path)
            return

        # If no image, try to get text
        try:
            clipboard_content = self.root.clipboard_get()
            if not clipboard_content.strip():
                messagebox.showinfo("Clipboard Empty", "The clipboard is empty or contains no text/image.")
                return
            
            # Create a temporary directory and file to serve the content
            self.temp_dir = tempfile.mkdtemp()
            temp_file_path = os.path.join(self.temp_dir, "clipboard_content.txt")
            with open(temp_file_path, "w", encoding="utf-8") as f:
                f.write(clipboard_content)
            self.start_sharing(temp_file_path)
        except tk.TclError:
            # This happens if clipboard is empty or doesn't contain text
            messagebox.showinfo("Clipboard Empty", "The clipboard is empty or contains no text/image.")

    def copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Copied", "URL copied to clipboard")

    def stop_sharing(self):
        """Stops the server, cleans temp vars, and returns to selection."""
        # Stop Server
        if self.server_thread:
            self.server_thread.stop()
            self.server_thread = None
        
        # Clean Temp
        if self.temp_dir:
            try:
                shutil.rmtree(self.temp_dir)
            except Exception as e:
                print(f"Error cleaning up temp directory: {e}")
            self.temp_dir = None
            
        # Clear UI
        for widget in self.root.winfo_children():
            widget.destroy()
            
        # Return to menu
        self.create_selection_ui()

    def on_close(self):
        if self.server_thread:
            self.server_thread.stop()
        # Clean up temporary directory if it was used
        if self.temp_dir:
            try:
                shutil.rmtree(self.temp_dir)
            except Exception as e:
                print(f"Error cleaning up temp directory: {e}")
        try:
            self.root.destroy()
        except tk.TclError:
            pass # Window might already be destroyed
        finally:
            sys.exit(0)

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    # If a path is passed as an argument, use it. Otherwise, show the selection UI.
    path_arg = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    # If no argument is passed, show the selection UI
    path_arg = sys.argv[1] if len(sys.argv) > 1 else None
    app = App(path_arg)
    app.run()