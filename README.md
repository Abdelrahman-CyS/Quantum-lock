# Quantum Lock - Password Manager

Quantum Lock is a secure and efficient password manager built using Python and Tkinter. It allows users to manage their passwords safely using various encryption methods such as Fernet, AES, and Triple DES. The application provides features for password storage, retrieval, update, and deletion, alongside a robust user interface with customizable appearance modes.

## Features

- **Secure Encryption**: Supports multiple encryption methods (Fernet, AES, Triple DES) to protect user passwords.
- **Password Strength Evaluation**: Evaluates and displays the strength of passwords.
- **Password Generation**: Generates strong passwords with customizable options.
- **User Authentication**: Implements user login functionality with secure password storage.
- **Database Management**: Manages user vaults and passwords using SQLite.
- **Customizable UI**: Includes a dark and light mode interface for better user experience.
- **Clipboard Copying**: Copies generated or stored passwords to the clipboard securely.
- **Error Handling**: Provides comprehensive error handling for database operations and encryption/decryption processes.

## Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/quantum-lock.git
    cd quantum-lock
    ```

2. **Install the required dependencies**:
    Make sure you have Python 3.x installed. You can install the dependencies using pip:

    ```bash
    pip install -r requirements.txt
    ```

    **Dependencies include**:
    - `tkinter`
    - `customtkinter`
    - `cryptography`
    - `pyperclip`
    - `bcrypt`
    - `sqlite3`

3. **Run the Application**:
    ```bash
    python main.py
    ```

## File Structure

- `main.py`: The main application file that initializes the Tkinter GUI and handles the user interface.
- `login.py`: Manages user login and vault creation.
- `database.py`: Contains functions for managing the SQLite database, including vault and password storage.
- `encryption.py`: Provides encryption and decryption functions using Fernet, AES, and Triple DES.
- `admin.py`: (Details about this file were not provided, assume it handles administrative tasks).
- `keys.key` & `secret.key`: Key files used for encryption/decryption (ensure these are securely stored and not publicly accessible).

## Usage

1. **Launch the Application**: Run `main.py` to start the password manager.
2. **Login or Create a Vault**: On first use, create a new vault. Subsequent launches will prompt for login using the vault's credentials.
3. **Add, Update, or Delete Passwords**: Use the UI to manage your passwords. Choose the desired encryption method from the options available.
4. **Generate Strong Passwords**: Use the password generation tool to create strong, secure passwords. Customize the options to include/exclude specific character types.

## Security Considerations

- **Encryption**: This application uses strong encryption standards to protect sensitive information. Ensure your encryption keys (`keys.key` and `secret.key`) are stored securely and not shared.
- **Password Strength**: Utilize the built-in password strength evaluation to ensure your passwords meet the security requirements.
- **Database Security**: The database is stored locally and should be protected with system-level security measures.

4. **Screenshot**:

![image](https://github.com/user-attachments/assets/27ccd6eb-354c-407a-a258-f78624f78021)

![image](https://github.com/user-attachments/assets/76ce0c57-9b41-40b1-bbe8-96809b514b46)

