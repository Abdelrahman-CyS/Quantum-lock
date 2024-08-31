import sqlite3
import uuid
import time
import math
import bcrypt  # Import bcrypt for password hashing and verification

from cryptography.fernet import Fernet
from encryption import encrypt_string_fernet, decrypt_string_fernet, encrypt_string_aes, decrypt_string_aes, encrypt_string_3des, decrypt_string_3des

DATABASE_NAME = "password_manager.db"

# List of common passwords to blacklist
COMMON_PASSWORDS = ["password", "123456", "123456789", "qwerty", "abc123", "password1", "111111"]

def calculate_entropy(password):
    charset_size = 0
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(c in '!@#$%^&*()-_+=' for c in password):
        charset_size += 14
    return len(password) * math.log2(charset_size)

def is_common_password(password):
    return password.lower() in COMMON_PASSWORDS

def evaluate_password_strength(password):
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in '!@#$%^&*()-_+=' for c in password)
    is_sequential = any(password[i:i+3].isalpha() and ord(password[i+1]) == ord(password[i]) + 1 and ord(password[i+2]) == ord(password[i+1]) + 1 for i in range(len(password) - 2))
    is_repeated = any(password.count(c) > len(password) // 2 for c in set(password))

    if is_common_password(password):
        return "Very Weak"

    entropy = calculate_entropy(password)
    strength = "Very Weak"

    if length >= 8 and has_upper and has_lower and has_digit and has_symbol and not is_sequential and not is_repeated and entropy >= 50:
        strength = "Very Strong"
    elif length >= 8 and has_upper and has_lower and has_digit and has_symbol and not is_sequential and entropy >= 40:
        strength = "Strong"
    elif length >= 6 and ((has_upper and has_lower) or (has_digit and has_symbol)) and entropy >= 30:
        strength = "Medium"
    elif length >= 6 and (has_upper or has_lower or has_digit or has_symbol):
        strength = "Weak"

    return strength

def create_db_and_table():
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()

        # Create the vaults table if it doesn't exist
        cursor.execute("""CREATE TABLE IF NOT EXISTS vaults (
                            id TEXT PRIMARY KEY,
                            name TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL,
                            email TEXT UNIQUE NOT NULL,
                            security_question TEXT NOT NULL,
                            security_answer TEXT NOT NULL,
                            security_code TEXT NOT NULL,
                            role TEXT NOT NULL DEFAULT 'vault')""")
        
        # Create the passwords table if it doesn't exist
        cursor.execute("""CREATE TABLE IF NOT EXISTS passwords (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            vault_id TEXT NOT NULL,
                            website TEXT NOT NULL,
                            email TEXT NOT NULL,
                            password TEXT NOT NULL,
                            encryption_type TEXT,
                            password_strength TEXT,
                            FOREIGN KEY (vault_id) REFERENCES vaults (id))""")

        conn.commit()
        conn.close()
        
        # Add the role column if it doesn't exist
        add_role_column_if_not_exists()
        
        print("Database and tables created/updated successfully")
    except Exception as e:
        print(f"Error creating or updating database and tables: {e}")

def fetch_vault_email(vaultname):
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT email FROM vaults WHERE name = ?", (vaultname,))
        result = cursor.fetchone()
        conn.close()
        if result:
            return result[0]
        else:
            return None
    except sqlite3.Error as e:
        print(f"SQL Error in fetch_vault_email: {e}")
        return None

def verify_database_structure():
    # Verify that the database structure is correct
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()

        cursor.execute("PRAGMA foreign_keys = ON;")
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vaults';")
        if cursor.fetchone() is None:
            create_db_and_table()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='passwords';")
        if cursor.fetchone() is None:
            create_db_and_table()

        conn.close()
        print("Database structure verified")
    except Exception as e:
        print(f"Error verifying database structure: {e}")

def load_vaults():
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM vaults")
        vaults = [row[0] for row in cursor.fetchall()]
        conn.close()
        print(f"Loaded vaults: {vaults}")
        return vaults if vaults else ["Default vault"]
    except Exception as e:
        print(f"Error loading vaults: {e}")
        return ["Default vault"]

def add_vault(vaultname, password, email, security_question=None, security_answer=None, security_code=None, role="vault"):
    retries = 5
    while retries:
        try:
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            
            # Check if the vaultname already exists
            cursor.execute("SELECT id FROM vaults WHERE name = ?", (vaultname,))
            if cursor.fetchone():
                conn.close()
                raise sqlite3.IntegrityError("vaultname already exists")
            
            # Check if the email already exists
            cursor.execute("SELECT id FROM vaults WHERE email = ?", (email,))
            if cursor.fetchone():
                conn.close()
                raise sqlite3.IntegrityError("Email already exists")
            
            # Insert the new vault into the database
            cursor.execute("""INSERT INTO vaults (id, name, password, email, security_question, security_answer, security_code, role) 
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                           (str(uuid.uuid4()), vaultname, password, email, security_question, security_answer, security_code, role))
            conn.commit()
            conn.close()
            print(f"vault {vaultname} added successfully with security key: {security_code}")
            return
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e):
                retries -= 1
                time.sleep(1)
            else:
                raise
        except sqlite3.IntegrityError as e:
            print(f"IntegrityError: {e}")
            raise
        except Exception as e:
            print(f"Exception: {e}")
            raise

def add_admin(vaultname, password, email, security_question=None, security_answer=None, security_code=None):
    add_vault(vaultname, password, email, security_question, security_answer, security_code, role="admin")

def delete_vault(vault_id):
    retries = 5
    while retries:
        try:
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM vaults WHERE id = ?", (vault_id,))
            conn.commit()
            conn.close()
            print("vault deleted successfully")
            return
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e):
                retries -= 1
                time.sleep(1)
            else:
                raise
        except sqlite3.Error as e:
            print(f"SQL Error: {e}")
        except Exception as e:
            print(f"Error deleting vault: {e}")

def save_password(vault_id, website, email, password, encryption_method, fernet_key, aes_key, des3_key):
    try:
        if encryption_method == "Fernet":
            encrypted_website = encrypt_string_fernet(website, fernet_key)
            encrypted_email = encrypt_string_fernet(email, fernet_key)
            encrypted_password = encrypt_string_fernet(password, fernet_key)
        elif encryption_method == "AES":
            encrypted_website = encrypt_string_aes(website, aes_key)
            encrypted_email = encrypt_string_aes(email, aes_key)
            encrypted_password = encrypt_string_aes(password, aes_key)
        elif encryption_method == "3DES" or encryption_method == "Triple DES":
            encrypted_website = encrypt_string_3des(website, des3_key)
            encrypted_email = encrypt_string_3des(email, des3_key)
            encrypted_password = encrypt_string_3des(password, des3_key)
        else:
            raise ValueError(f"Unsupported encryption method: {encryption_method}")

        print(f"Encrypted data: Website: {encrypted_website}, Email: {encrypted_email}, Password: {encrypted_password}")

        password_strength = evaluate_password_strength(password)
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO passwords (vault_id, website, email, password, encryption_type, password_strength) VALUES (?, ?, ?, ?, ?, ?)",
                       (vault_id, encrypted_website, encrypted_email, encrypted_password, encryption_method, password_strength))
        conn.commit()
        conn.close()
        print("Password stored successfully")
    except Exception as e:
        print(f"Error saving password: {e}")
        raise

def load_passwords(vault_id, fernet_key, aes_key, des3_key):
    passwords = []
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT id, website, email, password, encryption_type, password_strength FROM passwords WHERE vault_id = ?", (vault_id,))
        rows = cursor.fetchall()
        for row in rows:
            try:
                encryption_type = row[4]
                if encryption_type == "Fernet":
                    decrypted_website = decrypt_string_fernet(row[1], fernet_key)
                    decrypted_email = decrypt_string_fernet(row[2], fernet_key)
                    decrypted_password = decrypt_string_fernet(row[3], fernet_key)
                elif encryption_type == "AES":
                    decrypted_website = decrypt_string_aes(row[1], aes_key)
                    decrypted_email = decrypt_string_aes(row[2], aes_key)
                    decrypted_password = decrypt_string_aes(row[3], aes_key)
                elif encryption_type == "3DES" or encryption_type == "Triple DES":
                    decrypted_website = decrypt_string_3des(row[1], des3_key)
                    decrypted_email = decrypt_string_3des(row[2], des3_key)
                    decrypted_password = decrypt_string_3des(row[3], des3_key)
                else:
                    raise ValueError(f"Unsupported encryption method: {encryption_type}")
                passwords.append((decrypted_website, decrypted_email, decrypted_password, row[0], encryption_type, row[5]))
            except Exception as decrypt_error:
                print(f"Error decrypting data for row {row[0]}: {decrypt_error}")
        conn.close()
    except sqlite3.Error as e:
        print(f"SQL Error: {e}")
    except Exception as e:
        print(f"Unexpected error loading passwords: {e}")
    return passwords



def load_all_passwords(fernet_key, aes_key, des3_key):
    passwords = []
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT vault_id, website, email, password, encryption_type, password_strength FROM passwords")
        rows = cursor.fetchall()
        for row in rows:
            try:
                encryption_type = row[4]
                if encryption_type == "Fernet":
                    decrypted_website = decrypt_string_fernet(row[1], fernet_key)
                    decrypted_email = decrypt_string_fernet(row[2], fernet_key)
                    decrypted_password = decrypt_string_fernet(row[3], fernet_key)
                elif encryption_type == "AES":
                    decrypted_website = decrypt_string_aes(row[1], aes_key)
                    decrypted_email = decrypt_string_aes(row[2], aes_key)
                    decrypted_password = decrypt_string_aes(row[3], aes_key)
                elif encryption_type == "3DES":
                    decrypted_website = decrypt_string_3des(row[1], des3_key)
                    decrypted_email = decrypt_string_3des(row[2], des3_key)
                    decrypted_password = decrypt_string_3des(row[3], des3_key)
                passwords.append((decrypted_website, decrypted_email, decrypted_password, encryption_type, row[5]))
            except Exception as decrypt_error:
                print(f"Error decrypting data for row {row[0]}: {decrypt_error}")
        conn.close()
        print("Passwords loaded successfully")
    except sqlite3.Error as e:
        print(f"SQL Error: {e}")
    except Exception as e:
        print(f"Unexpected error loading passwords: {e}")
    return passwords

def delete_password(password_id):
    retries = 5
    while retries:
        try:
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM passwords WHERE id = ?", (password_id,))
            conn.commit()
            conn.close()
            print("Password deleted successfully")
            return
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e):
                retries -= 1
                time.sleep(1)
            else:
                raise
        except sqlite3.Error as e:
            print(f"SQL Error: {e}")
        except Exception as e:
            print(f"Error deleting password: {e}")

def delete_all_passwords(vault_id):
    retries = 5
    while retries:
        try:
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM passwords WHERE vault_id = ?", (vault_id,))
            conn.commit()
            conn.close()
            print("All passwords deleted successfully")
            return
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e):
                retries -= 1
                time.sleep(1)
            else:
                raise
        except sqlite3.Error as e:
            print(f"SQL Error: {e}")
        except Exception as e:
            print(f"Error deleting all passwords: {e}")

def update_password(password_id, website, email, password, encryption_method, fernet_key, aes_key, des3_key):
    retries = 5
    while retries:
        try:
            if encryption_method == "Fernet":
                new_encrypted_website = encrypt_string_fernet(website, fernet_key)
                new_encrypted_email = encrypt_string_fernet(email, fernet_key)
                new_encrypted_password = encrypt_string_fernet(password, fernet_key)
            elif encryption_method == "AES":
                new_encrypted_website = encrypt_string_aes(website, aes_key)
                new_encrypted_email = encrypt_string_aes(email, aes_key)
                new_encrypted_password = encrypt_string_aes(password, aes_key)
            elif encryption_method == "3DES" or encryption_method == "Triple DES":
                new_encrypted_website = encrypt_string_3des(website, des3_key)
                new_encrypted_email = encrypt_string_3des(email, des3_key)
                new_encrypted_password = encrypt_string_3des(password, des3_key)
            else:
                raise ValueError(f"Unsupported encryption method: {encryption_method}")

            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            cursor.execute("UPDATE passwords SET website = ?, email = ?, password = ?, encryption_type = ?, password_strength = ? WHERE id = ?",
                           (new_encrypted_website, new_encrypted_email, new_encrypted_password, encryption_method, evaluate_password_strength(password), password_id))
            conn.commit()
            conn.close()
            print("Password updated successfully")
            return
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e):
                retries -= 1
                time.sleep(1)
            else:
                raise
        except sqlite3.Error as e:
            print(f"SQL Error: {e}")
        except Exception as e:
            print(f"Error updating password: {e}")


def reset_vault_password(email, new_password):
    retries = 5
    while retries:
        try:
            hashed_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()  # Hash the new password before storing
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            cursor.execute("UPDATE vaults SET password = ? WHERE email = ?", (hashed_password, email))
            conn.commit()
            conn.close()
            print(f"Password reset successfully for {email}")
            return
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e):
                retries -= 1
                time.sleep(1)
            else:
                raise
        except sqlite3.Error as e:
            print(f"SQL Error: {e}")
        except Exception as e:
            print(f"Error resetting password: {e}")

def fetch_vaults():
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("""SELECT u.id, u.name, u.email, COUNT(p.id) AS password_count, 
                          u.security_question, u.security_answer, u.security_code, u.password
                          FROM vaults u
                          LEFT JOIN passwords p ON u.id = p.vault_id
                          GROUP BY u.id""")
        vaults = cursor.fetchall()
        conn.close()
        return vaults
    except Exception as e:
        print(f"Error fetching vaults: {e}")
        return []

def update_vault(vault_id, vaultname, email, password=None, security_question=None, security_answer=None, security_code=None):
    retries = 5
    while retries:
        try:
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            if password:
                cursor.execute("""UPDATE vaults SET name = ?, email = ?, password = ?, 
                                  security_question = ?, security_answer = ?, security_code = ?
                                  WHERE id = ?""",
                               (vaultname, email, password, security_question, security_answer, security_code, vault_id))
            else:
                cursor.execute("""UPDATE vaults SET name = ?, email = ?
                                  WHERE id = ?""",
                               (vaultname, email, vault_id))
            conn.commit()
            conn.close()
            print(f"vault {vaultname} updated successfully!")
            return
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e):
                retries -= 1
                time.sleep(1)
            else:
                raise
        except sqlite3.IntegrityError:
            print("Update Failed: vaultname or email already exists.")
            raise
        except Exception as e:
            print(f"Error updating vault: {e}")
            raise


def get_security_question_answer(email):
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT security_question, security_answer FROM vaults WHERE email = ?", (email,))
        result = cursor.fetchone()
        conn.close()
        return result
    except Exception as e:
        print(f"Error getting security question and answer: {e}")
        return None

def get_security_key(email):
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT security_code FROM vaults WHERE email = ?", (email,))
        result = cursor.fetchone()
        conn.close()
        return result
    except Exception as e:
        print(f"Error getting security key: {e}")
        return None

def update_password_by_key(email, new_password, security_key):
    retries = 5
    while retries:
        try:
            hashed_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()  # Hash the new password before storing
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            cursor.execute("UPDATE vaults SET password = ? WHERE email = ? AND security_code = ?", (hashed_password, email, security_key))
            conn.commit()
            conn.close()
            print(f"Password updated successfully for {email} using security key")
            return
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e):
                retries -= 1
                time.sleep(1)
            else:
                raise
        except Exception as e:
            print(f"Error updating password by security key: {e}")
            raise

def add_role_column_if_not_exists():
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(vaults)")
        columns = [info[1] for info in cursor.fetchall()]
        
        if 'role' not in columns:
            cursor.execute("ALTER TABLE vaults ADD COLUMN role TEXT NOT NULL DEFAULT 'vault'")
            conn.commit()
            print("Role column added to vaults table.")
        conn.close()
    except Exception as e:
        print(f"Error adding role column: {e}")

def create_admin_table():
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admin (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                security_question TEXT NOT NULL,
                security_answer TEXT NOT NULL,
                security_code TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'admin'
            )
        """)
        conn.commit()
        conn.close()
        print("Admin table created successfully")
    except sqlite3.Error as e:
        print(f"Error creating admin table: {e}")

def insert_admin_credentials(vaultname, password, email, security_question, security_answer, security_code):
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO admin (id, name, password, email, security_question, security_answer, security_code, role) VALUES (?, ?, ?, ?, ?, ?, ?, 'admin')", 
                       (str(uuid.uuid4()), vaultname, hashed_password, email, security_question, security_answer, security_code))
        cursor.execute("INSERT INTO vaults (id, name, password, email, security_question, security_answer, security_code, role) VALUES (?, ?, ?, ?, ?, ?, ?, 'admin')", 
                       (str(uuid.uuid4()), vaultname, hashed_password, email, security_question, security_answer, security_code))
        conn.commit()
        conn.close()
        print("Admin credentials inserted successfully")
    except sqlite3.Error as e:
        print(f"Error inserting admin credentials: {e}")

def verify_admin_credentials(vaultname, password):
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM vaults WHERE name = ? AND role = 'admin'", (vaultname,))
        result = cursor.fetchone()
        conn.close()
        if result and bcrypt.checkpw(password.encode(), result[0].encode()):
            return True
        else:
            return False
    except sqlite3.Error as e:
        print(f"Error verifying admin credentials: {e}")
        return False

def admin_exists():
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM vaults WHERE role = 'admin'")
        result = cursor.fetchone()
        conn.close()
        return result[0] > 0
    except sqlite3.Error as e:
        print(f"Error checking admin existence: {e}")
        return False

def reset_admin_password(vaultname, new_password, security_phrase):
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT security_phrase FROM admin WHERE name = ?", (vaultname,))
        result = cursor.fetchone()
        if result and result[0] == security_phrase:
            hashed_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
            cursor.execute("UPDATE vaults SET password = ? WHERE name = ?", (hashed_password, vaultname))
            conn.commit()
            conn.close()
            print("Admin password reset successfully.")
            return True
        else:
            conn.close()
            print("Incorrect security phrase.")
            return False
    except sqlite3.Error as e:
        print(f"Error resetting admin password: {e}")
        return False
