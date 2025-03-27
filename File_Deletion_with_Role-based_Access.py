import os
import getpass
import random
from cryptography.fernet import Fernet

# 📂 File Paths
base_path = "SecureFileManagement"
key_path = os.path.join(base_path, "secret.key")

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
        print("✅ Encryption Key Generated and Saved.")
    else:
        print("🔑 Encryption Key Already Exists.")

# 🔐 Load Encryption Key
def load_key():
    with open(key_path, 'rb') as key_file:
        return Fernet(key_file.read())

# 🎭 Authentication System
def authenticate(username, password):
    if username in users and users[username]["password"] == password:
        return users[username]["role"]
    return None

# 🔢 Generate OTP for 2FA
def generate_otp():
    return str(random.randint(1000, 9999))

# 🔐 2FA Verification
def verify_otp(correct_otp):
    otp_input = input("Enter the OTP to proceed: ")
    return otp_input == correct_otp

# 📚 File Operations
def create_file(username, fernet):
    filename = input("Enter filename: ")
    content = input("Enter content: ")
    
    encrypted_content = fernet.encrypt(content.encode())
    file_path = os.path.join(base_path, filename)

    with open(file_path, 'wb') as file:
        file.write(encrypted_content)
    
    print(f"🔐 File '{filename}' encrypted and saved successfully.")

def read_file(username, fernet):
    filename = input("Enter filename to read: ")
    file_path = os.path.join(base_path, filename)
    
    if os.path.exists(file_path):
        with open(file_path, 'rb') as file:
            encrypted_content = file.read()
        decrypted_content = fernet.decrypt(encrypted_content).decode()
        print(f"📄 Decrypted Content:\n{decrypted_content}")
    else:
        print(f"❌ File '{filename}' not found.")

# 🗑 Delete File (Admin Only)
def delete_file(username, role):
    if role != "admin":
        print("❌ Only Admin can delete files.")
        return
    
    filename = input("Enter filename to delete: ")
    file_path = os.path.join(base_path, filename)
    
    if os.path.exists(file_path):
        os.remove(file_path)
        print(f"🗑 File '{filename}' deleted successfully.")
    else:
        print(f"❌ File '{filename}' not found.")

# 🎮 Main Menu
def main():
    print("🔐 Welcome to Secure File Management System!")
    
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    
    role = authenticate(username, password)
    
    if not role:
        print("❌ Invalid username or password. Access Denied!")
        return
    
    print("✅ Authentication Successful!")

    # 🔢 OTP for 2FA
    otp = generate_otp()
    print(f"🔢 Your OTP is: {otp}")
    
    if not verify_otp(otp):
        print("❌ 2FA Verification Failed!")
        return
    
    print("✅ 2FA Verification Successful!")
    
    # 🔐 Load the Encryption Key
    fernet = load_key()

    while True:
        print("\n📚 File Operations:")
        print("1. Create and Encrypt File")
        print("2. Read and Decrypt File")
        print("3. Delete File")
        print("4. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            create_file(username, fernet)
        elif choice == '2':
            read_file(username, fernet)
        elif choice == '3':
            delete_file(username, role)
        elif choice == '4':
            print("👋 Exiting the system. Goodbye!")
            break
        else:
            print("❌ Invalid choice. Please try again.")

# 🔥 Run the System
if _name_ == "_main_":
    generate_key()
    main()
