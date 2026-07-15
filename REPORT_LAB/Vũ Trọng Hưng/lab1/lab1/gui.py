#!/usr/bin/env python3
# gui.py - PyQt6 GUI for Lab 1 Crypto Tool

import os
import sys
import subprocess
import tempfile
import secrets

from PyQt6.QtWidgets import (
    QApplication,
    QWidget,
    QLabel,
    QPushButton,
    QComboBox,
    QCheckBox,
    QLineEdit,
    QTextEdit,
    QFileDialog,
    QMessageBox,
    QGroupBox,
    QHBoxLayout,
    QVBoxLayout,
    QGridLayout,
    QStatusBar,
)
from PyQt6.QtCore import Qt


class CryptoGUI(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Crypto Tool - AES Encryption")
        self.resize(900, 700)

        self.exe_path = self.find_encrypt_tool()
        self.last_metadata_json = None

        if not self.exe_path:
            QMessageBox.critical(
                self,
                "Error",
                "Cannot find encrypt_tool executable.\n\n"
                "Please build the project first or copy the binary into:\n"
                "  bin/windows/encrypt_tool.exe\n"
                "or:\n"
                "  bin/linux/encrypt_tool"
            )
            sys.exit(1)

        self.setup_ui()

    def find_encrypt_tool(self):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        exe_name = "encrypt_tool.exe" if os.name == "nt" else "encrypt_tool"
        exe_dir = os.path.dirname(sys.executable)
        possible_paths = [
            os.path.join(exe_dir, exe_name),
            os.path.join(base_dir, exe_name),
            os.path.join(base_dir, "build", exe_name),
            os.path.join(base_dir, "build", "Release", exe_name),
            os.path.join(base_dir, "build_linux", exe_name),
            os.path.join(base_dir, "bin", "windows", "encrypt_tool.exe"),
            os.path.join(base_dir, "bin", "linux", "encrypt_tool"),
            os.path.join(base_dir, "..", exe_name),
            os.path.join(base_dir, "..", "build", exe_name),
            os.path.join(base_dir, "..", "build", "Release", exe_name),
            os.path.join(base_dir, "..", "build_linux", exe_name),
            os.path.join(base_dir, "..", "bin", "windows", "encrypt_tool.exe"),
            os.path.join(base_dir, "..", "bin", "linux", "encrypt_tool"),
        ]

        for path in possible_paths:
            norm_path = os.path.normpath(path)
            if os.path.exists(norm_path):
                return norm_path

        return None

    def setup_ui(self):
        main_layout = QVBoxLayout(self)

        title = QLabel("AES Encryption Tool")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 18px; font-weight: bold;")
        main_layout.addWidget(title)

        # Mode group
        mode_group = QGroupBox("Encryption Mode")
        mode_layout = QHBoxLayout()

        mode_layout.addWidget(QLabel("Mode:"))

        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["ecb", "cbc", "ofb", "cfb", "ctr", "xts", "ccm", "gcm"])
        self.mode_combo.setCurrentText("gcm")
        mode_layout.addWidget(self.mode_combo)

        self.allow_ecb_checkbox = QCheckBox("Allow ECB (insecure)")
        mode_layout.addWidget(self.allow_ecb_checkbox)

        mode_layout.addStretch()
        mode_group.setLayout(mode_layout)
        main_layout.addWidget(mode_group)

        # Key group
        key_group = QGroupBox("Key (256-bit = 64 hex chars)")
        key_layout = QHBoxLayout()

        self.key_entry = QLineEdit()
        self.key_entry.setText(
            "00112233445566778899AABBCCDDEEFF"
            "00112233445566778899AABBCCDDEEFF"
        )
        key_layout.addWidget(self.key_entry)

        generate_key_btn = QPushButton("Generate")
        generate_key_btn.clicked.connect(self.generate_key)
        key_layout.addWidget(generate_key_btn)

        load_key_btn = QPushButton("Load File")
        load_key_btn.clicked.connect(self.load_key_file)
        key_layout.addWidget(load_key_btn)

        key_group.setLayout(key_layout)
        main_layout.addWidget(key_group)

        # IV group
        iv_group = QGroupBox("IV/Nonce (optional)")
        iv_layout = QHBoxLayout()

        self.iv_entry = QLineEdit()
        iv_layout.addWidget(self.iv_entry)

        generate_iv_btn = QPushButton("Generate")
        generate_iv_btn.clicked.connect(self.generate_iv)
        iv_layout.addWidget(generate_iv_btn)

        iv_group.setLayout(iv_layout)
        main_layout.addWidget(iv_group)

        # Input group
        input_group = QGroupBox("Input")
        input_layout = QVBoxLayout()

        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Enter plaintext for encryption or hex ciphertext for decryption...")
        self.input_text.setStyleSheet("font-family: Consolas, monospace; font-size: 10pt;")
        input_layout.addWidget(self.input_text)

        input_group.setLayout(input_layout)
        main_layout.addWidget(input_group, stretch=1)

        # Buttons
        button_layout = QHBoxLayout()

        load_file_btn = QPushButton("Load File")
        load_file_btn.clicked.connect(self.load_file)
        button_layout.addWidget(load_file_btn)

        encrypt_btn = QPushButton("ENCRYPT")
        encrypt_btn.clicked.connect(self.encrypt)
        button_layout.addWidget(encrypt_btn)

        decrypt_btn = QPushButton("DECRYPT")
        decrypt_btn.clicked.connect(self.decrypt)
        button_layout.addWidget(decrypt_btn)

        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear)
        button_layout.addWidget(clear_btn)

        button_layout.addStretch()

        save_output_btn = QPushButton("Save Output")
        save_output_btn.clicked.connect(self.save_output)
        button_layout.addWidget(save_output_btn)

        main_layout.addLayout(button_layout)

        # Output group
        output_group = QGroupBox("Output")
        output_layout = QVBoxLayout()

        self.output_text = QTextEdit()
        self.output_text.setStyleSheet("font-family: Consolas, monospace; font-size: 10pt;")
        output_layout.addWidget(self.output_text)

        output_group.setLayout(output_layout)
        main_layout.addWidget(output_group, stretch=1)

        # Status bar
        self.status_bar = QStatusBar()
        self.status_bar.showMessage(f"Ready | Executable: {self.exe_path}")
        main_layout.addWidget(self.status_bar)

    def show_error(self, title, message):
        QMessageBox.critical(self, title, message)

    def show_info(self, title, message):
        QMessageBox.information(self, title, message)

    def generate_key(self):
        key = secrets.token_hex(32).upper()
        self.key_entry.setText(key)
        self.status_bar.showMessage("Generated new 256-bit key")

    def generate_iv(self):
        mode = self.mode_combo.currentText()

        if mode in ["ccm", "gcm"]:
            iv_len = 12
        else:
            iv_len = 16

        iv = secrets.token_hex(iv_len).upper()
        self.iv_entry.setText(iv)
        self.status_bar.showMessage(f"Generated {iv_len}-byte IV/nonce")

    def load_key_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Select Key File")

        if not filename:
            return

        try:
            with open(filename, "rb") as f:
                key_bytes = f.read()

            self.key_entry.setText(key_bytes.hex().upper())
            self.status_bar.showMessage(f"Loaded key from {filename}")

        except Exception as e:
            self.show_error("Error", f"Failed to load key:\n{e}")

    def load_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Select Input File")

        if not filename:
            return

        try:
            with open(filename, "rb") as f:
                data = f.read()

            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                text = data.hex().upper()

            self.input_text.setPlainText(text)
            self.status_bar.showMessage(f"Loaded {len(data)} bytes from {filename}")

        except Exception as e:
            self.show_error("Error", f"Failed to load file:\n{e}")

    def save_output(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Save Output")

        if not filename:
            return

        try:
            data = self.output_text.toPlainText().strip()

            with open(filename, "w", encoding="utf-8") as f:
                f.write(data)

            self.status_bar.showMessage(f"Saved output to {filename}")

        except Exception as e:
            self.show_error("Error", f"Failed to save output:\n{e}")

    def clear(self):
        self.input_text.clear()
        self.output_text.clear()
        self.last_metadata_json = None
        self.status_bar.showMessage("Cleared")

    def get_command_args(self, is_encrypt):
        key_hex = self.key_entry.text().strip()

        if not key_hex:
            self.show_error("Error", "Key is required.")
            return None

        mode = self.mode_combo.currentText()

        cmd = [self.exe_path]
        cmd.append("encrypt" if is_encrypt else "decrypt")

        cmd.extend(["--mode", mode])
        cmd.extend(["--key-hex", key_hex])

        iv_hex = self.iv_entry.text().strip()
        if iv_hex:
            cmd.extend(["--iv-hex", iv_hex])

        if mode == "ecb" and self.allow_ecb_checkbox.isChecked():
            cmd.append("--allow-ecb")

        return cmd

    def encrypt(self):
        input_data = self.input_text.toPlainText().strip()

        if not input_data:
            self.show_error("Error", "No input data.")
            return

        try:
            data_bytes = bytes.fromhex(input_data.replace(" ", "").replace("\n", ""))
        except ValueError:
            data_bytes = input_data.encode("utf-8")

        temp_in = None
        temp_out = None

        try:
            with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".in") as infile:
                infile.write(data_bytes)
                temp_in = infile.name

            temp_out = tempfile.NamedTemporaryFile(delete=False, suffix=".enc").name

            cmd = self.get_command_args(True)
            if not cmd:
                return

            cmd.extend(["--in", temp_in])
            cmd.extend(["--out", temp_out])

            self.status_bar.showMessage("Running encryption...")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                encoding="utf-8",
                errors="replace",
            )

            if result.returncode != 0:
                error_msg = result.stderr if result.stderr else "Unknown error"
                self.status_bar.showMessage("Encryption failed")
                self.show_error("Error", f"Encryption failed:\n{error_msg}")
                return

            with open(temp_out, "rb") as f:
                output_data = f.read()

            sidecar = temp_out + ".json"
            if os.path.exists(sidecar):
                with open(sidecar, "r", encoding="utf-8") as f:
                    self.last_metadata_json = f.read()
            else:
                self.last_metadata_json = None

            self.output_text.setPlainText(output_data.hex().upper())
            self.status_bar.showMessage("Encryption completed successfully")
            self.show_info("Success", "Encryption completed successfully.")

        except subprocess.TimeoutExpired:
            self.status_bar.showMessage("Encryption timeout")
            self.show_error("Error", "Encryption timeout.")

        except Exception as e:
            self.status_bar.showMessage("Encryption error")
            self.show_error("Error", str(e))

        finally:
            self.cleanup_temp_files(temp_in, temp_out)

    def decrypt(self):
        input_data = self.input_text.toPlainText().strip()

        if not input_data:
            self.show_error("Error", "No input data.")
            return

        try:
            data_bytes = bytes.fromhex(input_data.replace(" ", "").replace("\n", ""))
        except ValueError:
            self.show_error("Error", "Input must be a hex string for decryption.")
            return

        temp_in = None
        temp_out = None

        try:
            with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".enc") as infile:
                infile.write(data_bytes)
                temp_in = infile.name

            temp_out = tempfile.NamedTemporaryFile(delete=False, suffix=".dec").name

            if self.last_metadata_json:
                with open(temp_in + ".json", "w", encoding="utf-8") as f:
                    f.write(self.last_metadata_json)

            cmd = self.get_command_args(False)
            if not cmd:
                return

            cmd.extend(["--in", temp_in])
            cmd.extend(["--out", temp_out])

            self.status_bar.showMessage("Running decryption...")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                encoding="utf-8",
                errors="replace",
            )

            if result.returncode != 0:
                error_msg = result.stderr if result.stderr else "Unknown error"
                self.status_bar.showMessage("Decryption failed")
                self.show_error("Error", f"Decryption failed:\n{error_msg}")
                return

            with open(temp_out, "rb") as f:
                output_data = f.read()

            try:
                output_text = output_data.decode("utf-8")
            except UnicodeDecodeError:
                output_text = output_data.hex().upper()

            self.output_text.setPlainText(output_text)
            self.status_bar.showMessage("Decryption completed successfully")
            self.show_info("Success", "Decryption completed successfully.")

        except subprocess.TimeoutExpired:
            self.status_bar.showMessage("Decryption timeout")
            self.show_error("Error", "Decryption timeout.")

        except Exception as e:
            self.status_bar.showMessage("Decryption error")
            self.show_error("Error", str(e))

        finally:
            self.cleanup_temp_files(temp_in, temp_out)

    def cleanup_temp_files(self, temp_in, temp_out):
        for path in [temp_in, temp_out]:
            if not path:
                continue

            try:
                if os.path.exists(path):
                    os.unlink(path)
            except OSError:
                pass

            try:
                if os.path.exists(path + ".json"):
                    os.unlink(path + ".json")
            except OSError:
                pass


def main():
    app = QApplication(sys.argv)
    window = CryptoGUI()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()