🔐 Secure File Management System
A highly secure and feature-rich File Management System that implements encryption, role-based access, malware detection, buffer overflow protection, and audit logging. Built using Python and cryptography with additional security features such as *2FA (OTP)* and *admin-controlled audit logging*.
📚 Project Structure

📂 SecureFileManagement/
├── 📂 SecureFileManagement/
│   ├── 📄 secret.key
│   └── 📄 audit_log.txt
├── 📄 secure_file_management.py
└── 📄 README.md

⚡️ Features Overview
✅ *1. File Encryption and Decryption*
- Files are encrypted using the Fernet encryption from the cryptography module.
- Only authorized users can encrypt and decrypt files.
✅ *2. Role-Based Access Control (RBAC)*
- *Admin* has full control over file operations and audit logs.
- *Users* can create and read files but cannot delete or view audit logs.
✅ *3. Two-Factor Authentication (2FA)*
- After password authentication, a *4-digit OTP* is generated and must be entered correctly to proceed.
✅ *4. Malware Detection and Buffer Overflow Prevention*
- Prevents malware, SQL injection, and buffer overflow attacks by detecting dangerous patterns.
- Rejects file content if it exceeds *100 words* or contains malicious signatures.
✅ *5. Audit Logging for File Operations*
- Tracks and records all file actions (create, read, delete).
- Admins can view detailed audit logs for monitoring.
✅ *6. File Deletion (Admin Only)*
- Only *admins* can delete files to prevent unauthorized data loss.
🛠️ Setup and Installation
🔥 1. Clone the Repository

bash
git clone https://github.com/your-username/SecureFileManagement.git
cd SecureFileManagement


📦 2. Install Required Packages

bash
pip install cryptography

If running on Google Colab, use:
bash
!pip install cryptography


🚀 How to Run the Application

⚙️ Step 1: Run the Main Script
bash
python secure_file_management.py


🎮 Usage Instructions
📚 1. Authentication & 2FA
Enter a valid username and password.
A 4-digit OTP will be generated and displayed.
Enter the correct OTP to proceed.
🔐 User Roles and Default Credentials

| Username | Password  | Role  |
|----------|-----------|-------|
| admin    | admin123  | Admin |
| Bablu    | 1234      | User  |
| user1    | user123   | User  |

📝 Audit Logging System

All user actions (create, read, delete) are logged with timestamps.
Logs are stored in audit_log.txt in the following format:

[2025-03-24 12:45:01] - User: admin - Action: Created & Encrypted - File: report.txt
[2025-03-24 12:46:22] - User: Bablu - Action: Read File - File: project.docx
[2025-03-24 12:50:10] - User: admin - Action: Deleted File - File: malware.txt
