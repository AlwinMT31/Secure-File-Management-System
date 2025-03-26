import os
import getpass
from cryptography.fernet import Fernet

# 📂 File Paths
base_path = "/content/drive/MyDrive/SecureFileManagement"
key_path = os.path.join(base_path, "secret.key")

# 🎭 User Credentials
users = {
    "admin": {"password": "admin123", "role": "admin"},
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
        print("✅ Encryption Key Generated.")
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

# 📚 File Operations with Encryption
def create_file(fernet):
    filename = input("Enter filename: ")
    content = input("Enter content: ")

    encrypted_content = fernet.encrypt(content.encode())
    file_path = os.path.join(base_path, filename)

    with open(file_path, 'wb') as file:
        file.write(encrypted_content)
    
    print(f"✅ File '{filename}' encrypted and saved successfully.")

def read_file(fernet):
    filename = input("Enter filename to read: ")
    file_path = os.path.join(base_path, filename)

    if os.path.exists(file_path):
        with open(file_path, 'rb') as file:
            encrypted_content = file.read()
        decrypted_content = fernet.decrypt(encrypted_content).decode()
        print(f"📄 Decrypted Content:\n{decrypted_content}")
    else:
        print(f"❌ File '{filename}' not found.")

# 🎮 Main Menu
def main():
    generate_key()
    fernet = load_key()

    print("🔐 Welcome to Secure File Management System!")
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")

    role = authenticate(username, password)
    
    if not role:
        print("❌ Invalid username or password. Access Denied!")
        return

    print(f"✅ Authentication Successful! Role: {role}")

    while True:
        print("\n📚 File Operations:")
        print("1. Create and Encrypt File")
        print("2. Read and Decrypt File")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            create_file(fernet)
        elif choice == '2':
            read_file(fernet)
        elif choice == '3':
            print("👋 Exiting. Goodbye!")
            break
        else:
            print("❌ Invalid choice. Try again.")

# 🔥 Run the system
if _name_ == "_main_":
    main()
