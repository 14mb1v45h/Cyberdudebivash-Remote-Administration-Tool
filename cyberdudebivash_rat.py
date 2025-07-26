import sys
import socket
import threading
import pyautogui
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QPushButton, QTabWidget, QLineEdit, QLabel, QTextEdit, QColorDialog)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QPalette, QColor
from cryptography.fernet import Fernet
import pyotp
import qrcode
import base64
import time
import logging
import os
from PIL import Image
import io

# Configure logging for session auditing
logging.basicConfig(filename='cyberdudebivash.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Generate encryption key
key = Fernet.generate_key()
cipher = Fernet(key)

# Server class for handling remote connections
class RATServer:
    def __init__(self, host='0.0.0.0', port=5000):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((host, port))
        self.server_socket.listen(5)
        self.clients = []
        logging.info("Server started on {}:{}".format(host, port))

    def handle_client(self, client_socket, address):
        logging.info(f"New connection from {address}")
        self.clients.append(client_socket)
        while True:
            try:
                # Receive and decrypt data
                data = client_socket.recv(4096)
                if not data:
                    break
                decrypted_data = cipher.decrypt(data).decode()
                command, *args = decrypted_data.split('|')
                
                if command == 'MOUSE':
                    x, y = map(int, args)
                    pyautogui.moveTo(x, y)
                elif command == 'CLICK':
                    pyautogui.click()
                elif command == 'FILE':
                    filename = args[0]
                    file_data = base64.b64decode(args[1])
                    with open(f"received_{filename}", 'wb') as f:
                        f.write(file_data)
                    logging.info(f"File received: {filename}")
                elif command == 'SCREEN':
                    # Send screenshot
                    screenshot = pyautogui.screenshot()
                    img_byte_arr = io.BytesIO()
                    screenshot.save(img_byte_arr, format='PNG')
                    img_data = img_byte_arr.getvalue()
                    encrypted_data = cipher.encrypt(img_data)
                    client_socket.send(encrypted_data)
            except Exception as e:
                logging.error(f"Error handling client {address}: {e}")
                break
        client_socket.close()
        self.clients.remove(client_socket)
        logging.info(f"Connection closed for {address}")

    def start(self):
        while True:
            client_socket, address = self.server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_socket, address)).start()

# Client class for connecting to remote server
class RATClient:
    def __init__(self, host, port):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((host, port))
        logging.info(f"Connected to server {host}:{port}")

    def send_command(self, command):
        encrypted_command = cipher.encrypt(command.encode())
        self.client_socket.send(encrypted_command)

    def request_screenshot(self):
        self.send_command('SCREEN')
        data = self.client_socket.recv(1024 * 1024)
        decrypted_data = cipher.decrypt(data)
        img = Image.open(io.BytesIO(decrypted_data))
        img.save('remote_screenshot.png')
        return img

    def send_file(self, filepath):
        with open(filepath, 'rb') as f:
            file_data = f.read()
        encoded_data = base64.b64encode(file_data).decode()
        filename = os.path.basename(filepath)
        self.send_command(f'FILE|{filename}|{encoded_data}')
        logging.info(f"File sent: {filename}")

# GUI class
class CyberdudebivashGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cyberdudebivash Remote Administration Tool")
        self.setGeometry(100, 100, 800, 600)
        self.client = None
        self.setup_ui()
        self.setup_mfa()

    def setup_ui(self):
        # Set colorful theme
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(30, 30, 30))
        palette.setColor(QPalette.WindowText, Qt.white)
        palette.setColor(QPalette.Button, QColor(100, 149, 237))
        palette.setColor(QPalette.ButtonText, Qt.white)
        self.setPalette(palette)

        # Main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout()
        main_widget.setLayout(layout)

        # Tabs for different functionalities
        tabs = QTabWidget()
        layout.addWidget(tabs)

        # Connection Tab
        connection_tab = QWidget()
        connection_layout = QVBoxLayout()
        self.ip_input = QLineEdit("127.0.0.1")
        self.port_input = QLineEdit("5000")
        self.mfa_input = QLineEdit()
        self.connect_button = QPushButton("Connect")
        self.connect_button.clicked.connect(self.connect_to_server)
        connection_layout.addWidget(QLabel("Server IP:"))
        connection_layout.addWidget(self.ip_input)
        connection_layout.addWidget(QLabel("Port:"))
        connection_layout.addWidget(self.port_input)
        connection_layout.addWidget(QLabel("MFA Code:"))
        connection_layout.addWidget(self.mfa_input)
        connection_layout.addWidget(self.connect_button)
        connection_tab.setLayout(connection_layout)
        tabs.addTab(connection_tab, "Connect")

        # Remote Control Tab
        control_tab = QWidget()
        control_layout = QVBoxLayout()
        self.screenshot_button = QPushButton("Capture Screenshot")
        self.screenshot_button.clicked.connect(self.capture_screenshot)
        self.file_button = QPushButton("Send File")
        self.file_button.clicked.connect(self.send_file)
        control_layout.addWidget(self.screenshot_button)
        control_layout.addWidget(self.file_button)
        control_tab.setLayout(control_layout)
        tabs.addTab(control_tab, "Control")

        # Log Tab
        log_tab = QWidget()
        log_layout = QVBoxLayout()
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        log_layout.addWidget(self.log_display)
        log_tab.setLayout(log_layout)
        tabs.addTab(log_tab, "Logs")

        # Theme Button
        self.theme_button = QPushButton("Change Theme")
        self.theme_button.clicked.connect(self.change_theme)
        layout.addWidget(self.theme_button)

        # Update logs periodically
        self.log_timer = QTimer()
        self.log_timer.timeout.connect(self.update_logs)
        self.log_timer.start(1000)

    def setup_mfa(self):
        # Generate MFA secret and QR code
        self.mfa_secret = pyotp.random_base32()
        totp = pyotp.TOTP(self.mfa_secret)
        qr = qrcode.QRCode()
        qr.add_data(totp.provisioning_uri("Cyberdudebivash", issuer_name="Cyberdudebivash RAT"))
        qr.print_ascii()
        logging.info("MFA QR code generated. Scan with an authenticator app.")

    def verify_mfa(self, code):
        totp = pyotp.TOTP(self.mfa_secret)
        return totp.verify(code)

    def connect_to_server(self):
        if not self.verify_mfa(self.mfa_input.text()):
            self.log_display.append("Invalid MFA code!")
            logging.warning("MFA verification failed")
            return
        try:
            self.client = RATClient(self.ip_input.text(), int(self.port_input.text()))
            self.log_display.append("Connected to server!")
            logging.info("Client connected to server")
        except Exception as e:
            self.log_display.append(f"Connection failed: {e}")
            logging.error(f"Connection failed: {e}")

    def capture_screenshot(self):
        if self.client:
            img = self.client.request_screenshot()
            self.log_display.append("Screenshot captured!")
            logging.info("Screenshot captured")

    def send_file(self):
        if self.client:
            # Placeholder for file dialog (simplified)
            filepath = "sample.txt"  # Replace with QFileDialog in production
            self.client.send_file(filepath)
            self.log_display.append(f"File sent: {filepath}")
            logging.info(f"File sent: {filepath}")

    def change_theme(self):
        color = QColorDialog.getColor()
        if color.isValid():
            palette = self.palette()
            palette.setColor(QPalette.Button, color)
            self.setPalette(palette)
            logging.info(f"Theme changed to color: {color.name()}")

    def update_logs(self):
        with open('cyberdudebivash.log', 'r') as f:
            self.log_display.setText(f.read())

# Main application
def start_server():
    server = RATServer()
    server.start()

if __name__ == '__main__':
    # Start server in a separate thread
    threading.Thread(target=start_server, daemon=True).start()
    
    # Start GUI
    app = QApplication(sys.argv)
    window = CyberdudebivashGUI()
    window.show()
    sys.exit(app.exec_())