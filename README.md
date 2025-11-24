# Elevate-Labs-Cybersecurity-Projects
CyberSecurity Internship Projects - Secure File Storage System using AES Encryption
## Secure File Storage System using AES Encryption

This project implements a simple and secure file encryption tool using Python's cryptography library.  
It allows users to encrypt and decrypt files using AES-based Fernet encryption.  
Whenever a file is encrypted, the program automatically generates and saves metadata such as:

- Original file name  
- Encrypted file name  
- File size  
- File path  
- Encryption timestamp  
- SHA-256 hash for integrity check  

During decryption, the tool restores the original file and verifies whether the file was tampered with by comparing the stored SHA-256 hash.  
This project demonstrates basic cryptography, file security, and integrity verification commonly used in cybersecurity.
