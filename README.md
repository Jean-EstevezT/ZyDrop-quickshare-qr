# ZyDrop-quickshare-qr - Secure LAN File Sharing

ZyDrop is a simple script and secure application for sharing files, folders, and clipboard content across your local network. It generates a unique QR code and a secure link, allowing you to instantly transfer data to any device with a camera or web browser on the same network.

## Features

*   **Share Anything:** Transfer individual files, entire folders, or text and images from your clipboard.
*   **Secure by Default:** Each sharing session is protected by a randomly generated, single-use security token.
*   **Simple Discovery:** A QR code makes it incredibly easy to access shared files from a mobile device.
*   **Cross-Platform:** Works on both Windows and Linux.
*   **GUI and Context Menu Integration:** Use the user-friendly interface or right-click any file/folder to share it instantly.
*   **Lightweight:** No complex setup or heavy dependencies.

## How It Works

ZyDrop starts a temporary, local HTTP server on your machine. It automatically detects your LAN IP address and assigns a random, available port. Access to the shared files is protected by a security token embedded in the generated URL. When you stop the application, the server shuts down, and all temporary files are cleaned up.

## Requirements

To run ZyDrop, you need Python 3 and the following libraries:

*   `qrcode`
*   `Pillow`

You can install them using pip:

```bash
pip install -r requirements.txt
```

## Installation

An installation script is provided to integrate ZyDrop with your operating system's context menu, making it easier to use.

1.  **Install Dependencies:**
    
    ```bash
    pip install -r requirements.txt
    ```
    
2.  **Run the Installer:**
    
    Open a terminal or command prompt in the ZyDrop directory and run:
    
    ```bash
    python install_script.py
    ```
    
    The script will present you with two options:
    
    *   **Install:** This will add a "Share with ZyDrop (QR)" option to your right-click context menu.
        *   **On Windows:** This requires administrator privileges to modify the Windows Registry. The script will automatically request these permissions.
        *   **On Linux:** This will create a `.desktop` file in `~/.local/share/applications/`, integrating ZyDrop with your file manager.
    *   **Uninstall:** This will safely remove the context menu integration.

## Usage

There are two ways to use ZyDrop:

1.  **From the Context Menu (Recommended):**
    
    *   Right-click on any file or folder.
    *   Select "Share with ZyDrop (QR)" from the menu.
    *   The ZyDrop window will appear with a QR code.
    *   Scan the QR code with another device on the same network to download the file/folder.
2.  **Standalone Application:**
    
    *   Run the `script.pyw` file directly.
    *   A window will appear, allowing you to choose to share a file, a folder, or the content of your clipboard.
    *   After your selection, the QR code window will be displayed.

To stop sharing, simply close the QR code window or click the "Stop and Exit" button.

## Uninstallation

To remove the context menu entries created during installation:

1.  Run the installation script again:
    
    ```bash
    python install_script.py
    ```
    
2.  Select the "Uninstall" option.
    
    *   **On Windows:** This requires administrator privileges to remove the registry entries.
    *   **On Linux:** This will remove the `.desktop` file.

This will not delete the application files, only the OS integration.