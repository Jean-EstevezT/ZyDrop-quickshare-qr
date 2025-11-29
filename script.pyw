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

# --- Configuration ---
AUTH_TOKEN = secrets.token_urlsafe(8)  # Generate a random security token

class SecureHandler(SimpleHTTPRequestHandler):
    """
    Custom HTTP handler (security and route management)
    """
    def do_GET(self):
        # Security: Verify the token in the URL
        # The URL is: http://ip:port/file?key=TOKEN
        parsed_path = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(parsed_path.query)
        
        received_token = query_params.get('key', [None])[0]

        if received_token != AUTH_TOKEN:
            self.send_error(403, "Forbidden: Invalid security token.")
            return

        # Cleanup: Remove the query param so SimpleHTTPRequestHandler can find the file
        # We modify self.path to point to the actual file on disk
        self.path = parsed_path.path
        
        return super().do_GET()

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
        # Change to the directory we want to serve
        os.chdir(self.directory)
        
        # Port 0 allows the OS to assign a free port automatically
        self.server = ThreadingHTTPServer((self.ip, 0), SecureHandler)
        self.port = self.server.server_port
        self.server.serve_forever()

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()

class App:
    def __init__(self, target_path):
        self.root = tk.Tk()
        self.root.resizable(False, False)
        self.root.configure(bg="#1a1a1a") # Dark background
        self.server_thread = None
        self.temp_dir = None # To store the path of a temporary directory if created

        if target_path:
            self.root.title("Secure LAN Share")
            self.start_sharing(target_path)
        else:
            self.root.title("ZyDrop - Select to Share")
            self.create_selection_ui()

    def start_sharing(self, target_path):
        """Initializes the server and QR code UI for the given path."""
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
                self.on_close()
            else:
                sys.exit(1)

        # File and Folder Logic
        if os.path.isfile(target_path):
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
            self.serve_dir = target_path
            display_text = f"Folder: {os.path.basename(target_path)}"
            url_path = "/"

        # Start Server
        self.server_thread = ServerThread(self.serve_dir)
        self.server_thread.start()
        
        # Wait a moment for the port to be assigned
        while self.server_thread.port == 0:
            pass

        # Build Secure URL
        full_url = f"http://{self.server_thread.ip}:{self.server_thread.port}{url_path}?key={AUTH_TOKEN}"

        # --- UI ---
        # main
        main_frame = tk.Frame(self.root, bg="#1a1a1a", padx=20, pady=20)
        main_frame.pack(expand=True, fill="both")

        # Title
        tk.Label(main_frame, text="[ CONNECTION ESTABLISHED ]", font=("Consolas", 16, "bold"), bg="#1a1a1a", fg="#00ff00").pack(pady=(0, 10))
        tk.Label(main_frame, text=display_text, font=("Consolas", 10), bg="#1a1a1a", fg="#00cc00", wraplength=320).pack(pady=(0, 20))

        # QR Code
        qr = qrcode.QRCode(box_size=8, border=2)
        qr.add_data(full_url)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="#00ff00", back_color="#1e1e1e")
        self.photo = ImageTk.PhotoImage(qr_img)
        
        qr_label = tk.Label(main_frame, image=self.photo, bd=0)
        qr_label.pack(pady=10, padx=10)

        # Security Info
        tk.Label(main_frame, text="> STATUS: ONLINE | MODE: SECURE", font=("Consolas", 8), fg="#00b300", bg="#1a1a1a").pack(pady=(15, 5))
        
        # Copy URL Button
        btn_copy = tk.Button(main_frame, text="Copy Link", font=("Consolas", 11), command=lambda: self.copy_to_clipboard(full_url), bg="#2b2b2b", fg="#00ff00", relief="flat", activebackground="#3c3c3c", activeforeground="#ffffff", bd=0, pady=5)
        btn_copy.pack(fill="x", pady=(10, 5))

        # Close Button
        btn_stop = tk.Button(main_frame, text="Terminate", command=self.on_close, bg="#1a1a1a", fg="#ff4444", font=("Consolas", 10), relief="flat", activebackground="#770000", bd=0)
        btn_stop.pack(fill="x", pady=10)

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def create_selection_ui(self):
        """Creates the initial UI to ask the user to select a file or folder."""
        self.root.geometry("380x300")
        
        selection_frame = tk.Frame(self.root, bg="#1a1a1a", padx=20, pady=20)
        selection_frame.pack(expand=True, fill="both")

        tk.Label(selection_frame, text="[ SELECT TARGET ]", font=("Consolas", 16, "bold"), bg="#1a1a1a", fg="#00ff00").pack(pady=(0, 25))

        btn_style = {"font": ("Consolas", 12), "bg": "#2b2b2b", "fg": "#00ff00", "relief": "flat", "activebackground": "#3c3c3c", "activeforeground": "#ffffff", "bd": 0, "pady": 8}

        btn_select_file = tk.Button(selection_frame, text="Share File", command=self.select_file, **btn_style)
        btn_select_file.pack(fill="x", pady=5)

        btn_select_folder = tk.Button(selection_frame, text="Share Folder", command=self.select_folder, **btn_style)
        btn_select_folder.pack(fill="x", pady=5)

        btn_share_clipboard = tk.Button(selection_frame, text="Share from Clipboard", command=self.share_from_clipboard, **btn_style)
        btn_share_clipboard.pack(fill="x", pady=5)

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

    def on_close(self):
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
    path_arg = sys.argv[1] if len(sys.argv) > 1 else None
    app = App(path_arg)
    app.run()