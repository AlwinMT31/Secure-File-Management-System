import os

# 📂 File Paths
base_path = "/content/drive/MyDrive/SecureFileManagement"

# 📚 File Operations
def create_file():
    filename = input("Enter filename: ")
    content = input("Enter content: ")

    if not os.path.exists(base_path):
        os.makedirs(base_path)

    file_path = os.path.join(base_path, filename)

    with open(file_path, 'w') as file:
        file.write(content)
    
    print(f"✅ File '{filename}' created successfully.")

def read_file():
    filename = input("Enter filename to read: ")
    file_path = os.path.join(base_path, filename)

    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            content = file.read()
        print(f"📄 File Content:\n{content}")
    else:
        print(f"❌ File '{filename}' not found.")

# 🎮 Main Menu
def main():
    while True:
        print("\n📚 File Operations:")
        print("1. Create File")
        print("2. Read File")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            create_file()
        elif choice == '2':
            read_file()
        elif choice == '3':
            print("👋 Exiting the system. Goodbye!")
            break
        else:
            print("❌ Invalid choice. Try again.")

# 🔥 Run the system
if _name_ == "_main_":
    main()
