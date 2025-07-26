# Cyberdudebivash Remote Administration Tool

A modern, secure remote administration tool inspired by TeamViewer and VNCViewer, featuring a colorful PyQt5 GUI and advanced cybersecurity measures.

## Overview

The Cyberdudebivash Remote Administration Tool (RAT) allows users to remotely control desktops, transfer files, and manage sessions securely. Built with Python, it includes AES-256 encryption, multi-factor authentication (MFA), and session logging. The tool is designed to be cross-platform with a stylish, customizable GUI.

## Features

- **Remote Desktop Access**: View and control a remote computer's desktop.
- **File Transfer**: Securely transfer files between local and remote systems.
- **Screen Sharing**: Capture and view remote screenshots.
- **Multi-Factor Authentication**: TOTP-based MFA for secure access.
- **End-to-End Encryption**: AES-256 encryption for all communications.
- **Session Logging**: Audit logs for all actions.
- **Customizable GUI**: Change button colors for a personalized experience.
- **Cross-Platform**: Compatible with Windows, macOS, and Linux (with dependencies installed).

## Prerequisites

- Python 3.8 or higher
- An authenticator app (e.g., Google Authenticator) for MFA
- A network environment allowing TCP connections (default port: 5000)

## Installation

1. **Clone the Repository** (if applicable):
   ```bash
   git clone <repository-url>
   cd cyberdudebivash-rat
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Application**:
   ```bash
   python cyberdudebivash_rat.py
   ```

## Usage

1. **Start the Server**:
   - The server automatically starts on `0.0.0.0:5000` when you run the script.
   - Ensure port 5000 is open or configure your firewall.

2. **MFA Setup**:
   - On first run, a QR code is printed in the console.
   - Scan it with an authenticator app to set up MFA.

3. **Connect to a Server**:
   - Open the GUI, go to the "Connect" tab.
   - Enter the server IP (e.g., `127.0.0.1` for localhost) and port (e.g., `5000`).
   - Input the MFA code from your authenticator app.
   - Click "Connect" to establish a session.

4. **Remote Control**:
   - Go to the "Control" tab.
   - Click "Capture Screenshot" to view the remote desktop.
   - Click "Send File" to transfer a file (currently uses a placeholder file).

5. **View Logs**:
   - Check the "Logs" tab for session activity.

6. **Customize Theme**:
   - Click "Change Theme" to select a new button color.

## Security Features

- **AES-256 Encryption**: All communications are encrypted.
- **MFA**: Requires TOTP-based authentication for connections.
- **Session Logging**: Activities are logged in `cyberdudebivash.log` for auditing.
- **Intrusion Detection**: Basic framework included (expandable for production).

## Dependencies

See `requirements.txt` for a full list of Python packages required.

## Limitations

- This is a prototype; features like audio/video support, remote printing, and advanced intrusion detection are placeholders.
- File transfer uses a hardcoded file (`sample.txt`) for demonstration.
- Wake-on-LAN and AR support require additional implementation.

## Future Enhancements

- Add audio and video streaming.
- Implement remote printing and Wake-on-LAN.
- Integrate advanced intrusion detection systems (e.g., Suricata).
- Support IoT device control and AR collaboration.
- Enhance file transfer with a file dialog.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for bugs, features, or improvements.

## License

This project is licensed under the MIT License.

## Disclaimer

This tool is for educational and authorized use only. Unauthorized access to systems is illegal and unethical. Ensure you have permission before using this tool on any system.

## Copyright 

Copyright@cyberdudebivash  2025   