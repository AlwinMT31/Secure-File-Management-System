import os
import hashlib
import random
import getpass
from cryptography.fernet import Fernet
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, scrolledtext, Entry, Label, Button, Frame

# 📂 File Paths (Local Machine)
base_path = "./SecureFileManagement"
key_path = os.path.join(base_path, "secret.key")
audit_log_path = os.path.join(base_path, "audit_log.txt")
backup_log_path = os.path.join(base_path, "audit_log_backup.txt")

# 🎭 User Credentials and Roles
users = {
    "admin": {"password": "admin123", "role": "admin"},
    "Bablu": {"password": "1234", "role": "user"},
    "user1": {"password": "user123", "role": "user"}
}

# 🚀 Generate Encryption Key
def generate_key():
    if not os.path.exists(base_path):
        os.makedirs(base_path)
    if not os.path.exists(key_path):
        key = Fernet.generate_key()
        with open(key_path, 'wb') as key_file:
            key_file.write(key)

# 🔐 Load Encryption Key
def load_key():
    with open(key_path, 'rb') as key_file:
        return Fernet(key_file.read())

# 📂 Backup Audit Log
def backup_audit_log():
    if os.path.exists(audit_log_path):
        with open(audit_log_path, "r") as original_log:
            content = original_log.read()
        with open(backup_log_path, "w") as backup_log:
            backup_log.write(content)

# 📝 Log Activity
def log_activity(username, action, filename):
    with open(audit_log_path, "a") as log_file:
        log_file.write(f"[{datetime.now()}] - User: {username} - Action: {action} - File: {filename}\n")
    backup_audit_log()

# 🦠 Enhanced Malware Detection
def check_for_malware(content):
    content_lower = content.lower()
    suspicious_count = 0
    harmless_phrases = ["story about a virus", "learning about malware", "discussing an attack"]
    malware_signatures = ["malware", "virus", "trojan", "drop table", "select * from"]

    if len(content.split()) > 100:
        return True
    for phrase in harmless_phrases:
        if phrase in content_lower:
            return False
    for signature in malware_signatures:
        if signature in content_lower:
            suspicious_count += 1
    return suspicious_count >= 2

# 🎭 Authentication
def authenticate(username, password):
    if username in users and users[username]["password"] == password:
        return users[username]["role"]
    return None

# 🔢 Generate OTP
def generate_otp():
    return str(random.randint(1000, 9999))

# GUI Class
class SecureFileApp:
    def _init_(self, root):
        self.root = root
        self.root.title("Secure File Management System")
        self.root.geometry("600x400")
        self.username = None
        self.role = None
        self.fernet = load_key()
        
        self.show_login_screen()

    def show_login_screen(self):
        self.clear_window()
        Label(self.root, text="Welcome to Secure File Management", font=("Arial", 14)).pack(pady=10)

        frame = Frame(self.root)
        frame.pack(pady=10)

        Label(frame, text="Username:").grid(row=0, column=0, padx=5, pady=5)
        self.username_entry = Entry(frame)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)

        Label(frame, text="Password:").grid(row=1, column=0, padx=5, pady=5)
        self.password_entry = Entry(frame, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        Button(frame, text="Login", command=self.login).grid(row=2, columnspan=2, pady=10)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        self.role = authenticate(username, password)

        if not self.role:
            messagebox.showerror("Error", "Invalid username or password!")
            return

        self.username = username
        self.otp = generate_otp()
        messagebox.showinfo("OTP", f"Your OTP is: {self.otp}")
        self.show_otp_screen()

    def show_otp_screen(self):
        self.clear_window()
        Label(self.root, text="Enter OTP", font=("Arial", 14)).pack(pady=10)

        frame = Frame(self.root)
        frame.pack(pady=10)

        Label(frame, text="OTP:").grid(row=0, column=0, padx=5, pady=5)
        self.otp_entry = Entry(frame)
        self.otp_entry.grid(row=0, column=1, padx=5, pady=5)

        Button(frame, text="Verify", command=self.verify_otp).grid(row=1, columnspan=2, pady=10)

    def verify_otp(self):
        if self.otp_entry.get() == self.otp:
            messagebox.showinfo("Success", "2FA Verification Successful!")
            self.show_main_menu()
        else:
            messagebox.showerror("Error", "Invalid OTP!")

    def show_main_menu(self):
        self.clear_window()
        Label(self.root, text=f"Welcome, {self.username} ({self.role})", font=("Arial", 14)).pack(pady=10)

        frame = Frame(self.root)
        frame.pack(pady=10)

        Button(frame, text="Create File", command=self.create_file_window).grid(row=0, column=0, padx=5, pady=5)
        Button(frame, text="Read File", command=self.read_file_window).grid(row=0, column=1, padx=5, pady=5)
        Button(frame, text="Delete File", command=self.delete_file_window).grid(row=1, column=0, padx=5, pady=5)
        Button(frame, text="View Audit Log", command=self.view_audit_log).grid(row=1, column=1, padx=5, pady=5)
        Button(frame, text="Exit", command=self.root.quit).grid(row=2, columnspan=2, pady=10)

    def create_file_window(self):
        self.clear_window()
        Label(self.root, text="Create and Encrypt File", font=("Arial", 14)).pack(pady=10)

        frame = Frame(self.root)
        frame.pack(pady=10)

        Label(frame, text="Filename:").grid(row=0, column=0, padx=5, pady=5)
        self.filename_entry = Entry(frame)
        self.filename_entry.grid(row=0, column=1, padx=5, pady=5)

        Label(frame, text="Content:").grid(row=1, column=0, padx=5, pady=5)
        self.content_entry = scrolledtext.ScrolledText(frame, width=40, height=10)
        self.content_entry.grid(row=1, column=1, padx=5, pady=5)

        Button(frame, text="Save", command=self.create_file).grid(row=2, column=0, pady=10)
        Button(frame, text="Back", command=self.show_main_menu).grid(row=2, column=1, pady=10)

    def create_file(self):
        filename = self.filename_entry.get()
        content = self.content_entry.get("1.0", tk.END).strip()

        if check_for_malware(content):
            messagebox.showerror("Error", "Malware or Buffer Overflow Detected!")
            log_activity(self.username, "Malware/Overflow Detected", filename)
            return

        encrypted_content = self.fernet.encrypt(content.encode())
        file_path = os.path.join(base_path, filename)

        with open(file_path, 'wb') as file:
            file.write(encrypted_content)

        messagebox.showinfo("Success", f"File '{filename}' encrypted and saved!")
        log_activity(self.username, "Created & Encrypted", filename)
        self.show_main_menu()

    def read_file_window(self):
        self.clear_window()
        Label(self.root, text="Read and Decrypt File", font=("Arial", 14)).pack(pady=10)

        frame = Frame(self.root)
        frame.pack(pady=10)

        Label(frame, text="Filename:").grid(row=0, column=0, padx=5, pady=5)
        self.read_filename_entry = Entry(frame)
        self.read_filename_entry.grid(row=0, column=1, padx=5, pady=5)

        Button(frame, text="Read", command=self.read_file).grid(row=1, column=0, pady=10)
        Button(frame, text="Back", command=self.show_main_menu).grid(row=1, column=1, pady=10)

    def read_file(self):
        filename = self.read_filename_entry.get()
        file_path = os.path.join(base_path, filename)

        if os.path.exists(file_path):
            with open(file_path, 'rb') as file:
                encrypted_content = file.read()
            decrypted_content = self.fernet.decrypt(encrypted_content).decode()
            messagebox.showinfo("File Content", f"Decrypted Content:\n{decrypted_content}")
            log_activity(self.username, "Read File", filename)
        else:
            messagebox.showerror("Error", f"File '{filename}' not found!")
            log_activity(self.username, "File Not Found", filename)

    def delete_file_window(self):
        if self.role != "admin":
            messagebox.showerror("Error", "Only Admin can delete files!")
            return

        self.clear_window()
        Label(self.root, text="Delete File", font=("Arial", 14)).pack(pady=10)

        frame = Frame(self.root)
        frame.pack(pady=10)

        Label(frame, text="Filename:").grid(row=0, column=0, padx=5, pady=5)
        self.delete_filename_entry = Entry(frame)
        self.delete_filename_entry.grid(row=0, column=1, padx=5, pady=5)

        Button(frame, text="Delete", command=self.delete_file).grid(row=1, column=0, pady=10)
        Button(frame, text="Back", command=self.show_main_menu).grid(row=1, column=1, pady=10)

    def delete_file(self):
        filename = self.delete_filename_entry.get()
        file_path = os.path.join(base_path, filename)

        if os.path.exists(file_path):
            os.remove(file_path)
            messagebox.showinfo("Success", f"File '{filename}' deleted!")
            log_activity(self.username, "Deleted File", filename)
        else:
            messagebox.showerror("Error", f"File '{filename}' not found!")
            log_activity(self.username, "File Not Found (Delete)", filename)

    def view_audit_log(self):
        if self.role != "admin":
            messagebox.showerror("Error", "Only Admin can view the audit log!")
            return

        if os.path.exists(audit_log_path):
            with open(audit_log_path, "r") as log_file:
                logs = log_file.read()
            messagebox.showinfo("Audit Log", logs)
        else:
            messagebox.showwarning("Warning", "No audit log found!")

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

# Run the GUI
if _name_ == "_main_":
    generate_key()
    root = tk.Tk()
    app = SecureFileApp(root)
    root.mainloop()
