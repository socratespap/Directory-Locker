import sys
import os
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QPushButton, QLabel, QFileDialog, QMessageBox, QLineEdit,
                           QProgressBar)
from PyQt6.QtCore import Qt, QMimeData, QThread, pyqtSignal
from PyQt6.QtGui import QDragEnterEvent, QDropEvent, QFont
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import json
import shutil
from PyQt6.QtGui import QIcon



class EncryptionWorker(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal()
    error = pyqtSignal(str)
    
    def __init__(self, directory, fernet, encrypt=True):
        super().__init__()
        self.directory = directory
        self.fernet = fernet
        self.encrypt = encrypt
        self.total_files = 0
        self.processed_files = 0
        
    def count_files(self):
        count = 0
        for _, _, files in os.walk(self.directory):
            for file in files:
                if self.encrypt and not file.endswith('.encrypted'):
                    count += 1
                elif not self.encrypt and file.endswith('.encrypted'):
                    count += 1
        return count
    
    def run(self):
        try:
            self.total_files = self.count_files()
            if self.total_files == 0:
                self.progress.emit(100)
                self.finished.emit()
                return
                
            for root, _, files in os.walk(self.directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        if self.encrypt:
                            if not file_path.endswith('.encrypted'):
                                self.encrypt_file(file_path)
                                self.processed_files += 1
                                progress = int((self.processed_files / self.total_files) * 100)
                                self.progress.emit(progress)
                        else:
                            if file_path.endswith('.encrypted'):
                                self.decrypt_file(file_path)
                                self.processed_files += 1
                                progress = int((self.processed_files / self.total_files) * 100)
                                self.progress.emit(progress)
                    except Exception as e:
                        self.error.emit(f"Error processing file {file}: {str(e)}")
                        return
            
            self.finished.emit()
            
        except Exception as e:
            self.error.emit(str(e))
    
    def encrypt_file(self, file_path):
        with open(file_path, 'rb') as file:
            file_data = file.read()
        
        encrypted_data = self.fernet.encrypt(file_data)
        with open(file_path + '.encrypted', 'wb') as file:
            file.write(encrypted_data)
        
        os.remove(file_path)
    
    def decrypt_file(self, file_path):
        with open(file_path, 'rb') as file:
            encrypted_data = file.read()
        
        decrypted_data = self.fernet.decrypt(encrypted_data)
        original_path = file_path[:-10]  # Remove '.encrypted'
        
        with open(original_path, 'wb') as file:
            file.write(decrypted_data)
        
        os.remove(file_path)

class DirectoryLocker(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowIcon(QIcon('logo.png'))
        self.setWindowTitle("Directory Locker")
        self.setMinimumSize(500, 400)
        self.selected_directory = None
        self.config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "locked_dirs.json")
        self.load_locked_directories()
        
        # Set up the main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout()
        main_widget.setLayout(layout)
        
        # Style
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 5px;
                font-size: 14px;
                min-width: 200px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QLineEdit {
                padding: 8px;
                border: 2px solid #ddd;
                border-radius: 5px;
                font-size: 14px;
            }
            QLabel {
                font-size: 14px;
                color: #333;
            }
        """)
        
        # Create drag & drop area
        self.drop_label = QLabel("Drag and Drop Directory Here\nor")
        self.drop_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.drop_label.setFont(QFont('Arial', 14))
        self.drop_label.setStyleSheet("""
            QLabel {
                border: 2px dashed #999;
                border-radius: 10px;
                padding: 50px;
                background-color: white;
            }
        """)
        self.drop_label.setAcceptDrops(True)
        
        # Create select directory button
        self.select_btn = QPushButton("Select Directory")
        self.select_btn.clicked.connect(self.select_directory)
        
        # Create password input
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        
        # Create lock/unlock buttons
        self.lock_btn = QPushButton("Lock Directory")
        self.lock_btn.clicked.connect(self.lock_directory)
        self.unlock_btn = QPushButton("Unlock Directory")
        self.unlock_btn.clicked.connect(self.unlock_directory)
        
        # Create progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Add widgets to layout
        layout.addWidget(self.drop_label)
        layout.addWidget(self.select_btn)
        layout.addWidget(self.password_input)
        layout.addWidget(self.lock_btn)
        layout.addWidget(self.unlock_btn)
        
        # Set up drag and drop
        self.setAcceptDrops(True)
        
    def load_locked_directories(self):
        """Load the list of locked directories and their salts"""
        self.locked_dirs = {}
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    self.locked_dirs = json.load(f)
            except:
                self.locked_dirs = {}

    def save_locked_directories(self):
        """Save the list of locked directories and their salts"""
        with open(self.config_file, 'w') as f:
            json.dump(self.locked_dirs, f)

    def get_encryption_key(self, password, salt=None):
        """Generate an encryption key from password and salt"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key), salt

    def update_progress(self, value):
        self.progress_bar.setValue(value)
    
    def process_finished(self):
        self.progress_bar.setVisible(False)
        self.lock_btn.setEnabled(True)
        self.unlock_btn.setEnabled(True)
        self.select_btn.setEnabled(True)
        
        if hasattr(self, 'current_operation'):
            if self.current_operation == 'lock':
                QMessageBox.information(self, "Success", f"Directory '{os.path.basename(self.selected_directory)}' has been locked!")
            else:
                QMessageBox.information(self, "Success", f"Directory '{os.path.basename(self.selected_directory)}' has been unlocked!")
    
    def process_error(self, error_msg):
        self.progress_bar.setVisible(False)
        self.lock_btn.setEnabled(True)
        self.unlock_btn.setEnabled(True)
        self.select_btn.setEnabled(True)
        QMessageBox.critical(self, "Error", error_msg)
        
        if hasattr(self, 'current_operation') and self.current_operation == 'unlock':
            # Restore the locked directory entry if unlock failed
            self.locked_dirs[self.selected_directory] = self.temp_dir_info
    
    def lock_directory(self):
        if not self.selected_directory:
            QMessageBox.warning(self, "Error", "Please select a directory first.")
            return
            
        password = self.password_input.text()
        if not password:
            QMessageBox.warning(self, "Error", "Please enter a password.")
            return

        try:
            # Generate encryption key and salt
            fernet, salt = self.get_encryption_key(password)
            
            # Store directory info
            self.locked_dirs[self.selected_directory] = {
                'salt': base64.b64encode(salt).decode('utf-8')
            }
            
            # Set up the worker thread
            self.current_operation = 'lock'
            self.worker = EncryptionWorker(self.selected_directory, fernet, encrypt=True)
            self.worker.progress.connect(self.update_progress)
            self.worker.finished.connect(self.process_finished)
            self.worker.error.connect(self.process_error)
            
            # Disable buttons and show progress bar
            self.lock_btn.setEnabled(False)
            self.unlock_btn.setEnabled(False)
            self.select_btn.setEnabled(False)
            self.progress_bar.setValue(0)
            self.progress_bar.setVisible(True)
            
            # Start the worker thread
            self.worker.start()
            
            # Save locked directories info
            self.save_locked_directories()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to lock directory: {str(e)}")
        
    def unlock_directory(self):
        if not self.selected_directory:
            QMessageBox.warning(self, "Error", "Please select a directory first.")
            return
            
        if self.selected_directory not in self.locked_dirs:
            QMessageBox.warning(self, "Error", "This directory is not locked!")
            return
            
        password = self.password_input.text()
        if not password:
            QMessageBox.warning(self, "Error", "Please enter a password.")
            return

        try:
            # Get stored salt and generate key
            stored_salt = base64.b64decode(self.locked_dirs[self.selected_directory]['salt'])
            fernet, _ = self.get_encryption_key(password, stored_salt)
            
            # Store directory info temporarily in case of failure
            self.temp_dir_info = self.locked_dirs[self.selected_directory]
            del self.locked_dirs[self.selected_directory]
            
            # Set up the worker thread
            self.current_operation = 'unlock'
            self.worker = EncryptionWorker(self.selected_directory, fernet, encrypt=False)
            self.worker.progress.connect(self.update_progress)
            self.worker.finished.connect(self.process_finished)
            self.worker.error.connect(self.process_error)
            
            # Disable buttons and show progress bar
            self.lock_btn.setEnabled(False)
            self.unlock_btn.setEnabled(False)
            self.select_btn.setEnabled(False)
            self.progress_bar.setValue(0)
            self.progress_bar.setVisible(True)
            
            # Start the worker thread
            self.worker.start()
            
            # Save locked directories info
            self.save_locked_directories()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", "Invalid password or directory is corrupted!")
            
    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()
            
    def dropEvent(self, event: QDropEvent):
        urls = event.mimeData().urls()
        if urls:
            directory = urls[0].toLocalFile()
            if os.path.isdir(directory):
                self.selected_directory = directory
                self.drop_label.setText(f"Selected: {os.path.basename(directory)}")
            else:
                QMessageBox.warning(self, "Error", "Please drop a directory, not a file.")
                
    def select_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Directory")
        if directory:
            self.selected_directory = directory
            self.drop_label.setText(f"Selected: {os.path.basename(directory)}")
            
def main():
    app = QApplication(sys.argv)
    window = DirectoryLocker()
    window.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
