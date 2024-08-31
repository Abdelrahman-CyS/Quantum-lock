import tkinter
import os
import re
import sys
import uuid
import pyotp
import time
import random
import string
import sqlite3
import math
import bcrypt  # Import bcrypt for password hashing and verification
import customtkinter as ctk

from PIL import Image
from customtkinter import CTkImage
from cryptography.fernet import Fernet
from tkinter import simpledialog, messagebox
from database import admin_exists, create_admin_table, add_admin, add_vault, create_db_and_table

DATABASE_NAME = "password_manager.db"
EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
PASSWORD_REGEX = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
SECURITY_QUESTIONS = [
    "What’s your favorite movie?",
    "What was your dream job as a child?",
    "What is your favorite color?"
]

KEY_FILE = "keys.key"

# Rate limiting configuration
RATE_LIMITS = {
    'admin_login': (5, 60),  # 5 attempts per minute
    'vault_login': (5, 60),  # 5 attempts per minute
    'password_reset': (3, 3600)  # 3 attempts per hour
}

attempts = {
    'admin_login': {},
    'vault_login': {},
    'password_reset': {}
}

def rate_limited(action, key):
    max_attempts, window = RATE_LIMITS[action]
    current_time = time.time()
    attempts_list = attempts[action].get(key, [])

    # Filter attempts within the time window
    attempts_list = [t for t in attempts_list if t > current_time - window]
    attempts[action][key] = attempts_list

    attempts_left = max_attempts - len(attempts_list)
    if len(attempts_list) >= max_attempts:
        wait_time = window - (current_time - attempts_list[0])
        return True, attempts_left, wait_time
    
    # Adaptive increase in wait time for repeated attempts
    if len(attempts_list) > 1 and (current_time - attempts_list[0]) < window:
        window *= 1.5  # Increase window by 50%

    attempts_list.append(current_time)
    return False, attempts_left, 0

def generate_and_store_keys():
    """Generates new encryption keys and stores them in a file."""
    fernet_key = Fernet.generate_key()
    aes_key = os.urandom(32)  # 256-bit key for AES
    des3_key = os.urandom(24)  # 192-bit key for 3DES

    with open(KEY_FILE, "wb") as key_file:
        key_file.write(fernet_key + b"\n")
        key_file.write(aes_key + b"\n")
        key_file.write(des3_key + b"\n")

def load_keys():
    """Loads encryption keys from a file or generates new ones if the file does not exist."""
    if not os.path.exists(KEY_FILE):
        generate_and_store_keys()

    with open(KEY_FILE, "rb") as key_file:
        keys = key_file.readlines()
        fernet_key = keys[0].strip()
        aes_key = keys[1].strip()
        des3_key = keys[2].strip()

    return fernet_key, aes_key, des3_key

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

def generate_captcha():
    """Generates a random CAPTCHA string."""
    characters = string.ascii_uppercase + string.digits
    captcha = ''.join(random.choice(characters) for _ in range(6))
    return captcha

class CaptchaDialog(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("CAPTCHA Verification")
        self.geometry("300x200")

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure((0, 1, 2, 3, 4), weight=1)

        self.label = ctk.CTkLabel(self, text="Enter the CAPTCHA code", font=("Helvetica", 14, "bold"))
        self.label.grid(row=0, column=0, padx=10, pady=(20, 10), sticky="ew")

        self.captcha_code = self.generate_and_display_captcha()
        self.captcha_label = ctk.CTkLabel(self, text=self.captcha_code, font=("Helvetica", 18, "bold"), fg_color="white", bg_color="black")
        self.captcha_label.grid(row=1, column=0, padx=10, pady=(10, 0), sticky="ew")

        self.captcha_entry = ctk.CTkEntry(self, placeholder_text="CAPTCHA")
        self.captcha_entry.grid(row=2, column=0, padx=10, pady=(10, 0), sticky="ew")

        self.verify_button = ctk.CTkButton(self, text="Verify", command=self.verify_captcha)
        self.verify_button.grid(row=3, column=0, padx=10, pady=(20, 10), sticky="ew")

        self.refresh_button = ctk.CTkButton(self, text="Refresh CAPTCHA", command=self.refresh_captcha)
        self.refresh_button.grid(row=4, column=0, padx=10, pady=(0, 20), sticky="ew")

        self.result = None

    def generate_and_display_captcha(self):
        self.captcha_code = generate_captcha()
        self.captcha_label.configure(text=self.captcha_code)
        return self.captcha_code

    def refresh_captcha(self):
        self.generate_and_display_captcha()

    def verify_captcha(self):
        if self.captcha_entry.get() == self.captcha_code:
            self.result = True
        else:
            self.result = False
        self.destroy()

class AdminRegistrationWindow(ctk.CTkToplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Register Admin")
        self.geometry("1300x800")
        self.configure(fg_color="#1A1A2E")  # Dark blue background

        self.grid_columnconfigure((0, 1), weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.create_left_frame()
        self.create_right_frame()

    def create_left_frame(self):
        left_frame = ctk.CTkFrame(self, fg_color="#16213E", corner_radius=0)
        left_frame.grid(row=0, column=0, sticky="nsew")
        left_frame.grid_rowconfigure((0, 1, 2), weight=1)
        left_frame.grid_columnconfigure(0, weight=1)

        # Title
        title_frame = ctk.CTkFrame(left_frame, fg_color="transparent")
        title_frame.grid(row=0, column=0, padx=50, pady=(50, 0), sticky="new")
        
        ctk.CTkLabel(title_frame, text="Welcome to", font=("Roboto", 24), text_color="#E94560").pack()
        ctk.CTkLabel(title_frame, text="Admin Registration", font=("Roboto", 40, "bold"), text_color="#FFFFFF").pack()

        # Decorative element (you can replace this with an actual image)
        canvas = ctk.CTkCanvas(left_frame, width=300, height=300, bg="#16213E", highlightthickness=0)
        canvas.grid(row=1, column=0)
        canvas.create_oval(10, 10, 290, 290, outline="#E94560", width=4)
        canvas.create_text(150, 150, text="ADMIN", font=("Arial", 30, "bold"), fill="#FFFFFF")

        # Footer
        ctk.CTkLabel(left_frame, text="Secure • Efficient • Powerful", font=("Roboto", 16), text_color="#E94560").grid(row=2, column=0, pady=(0, 50))

    def create_right_frame(self):
        right_frame = ctk.CTkFrame(self, fg_color="#0F3460", corner_radius=0)
        right_frame.grid(row=0, column=1, sticky="nsew")
        right_frame.grid_columnconfigure(0, weight=1)
        right_frame.grid_rowconfigure((0, 1, 2, 3, 4, 5), weight=1)

        ctk.CTkLabel(right_frame, text="Create Your Admin Account", font=("Roboto", 28, "bold"), text_color="#FFFFFF").grid(row=0, column=0, pady=(50, 20))

        self.email_entry = self.create_entry(right_frame, "Email", row=1)
        self.email_entry.bind("<FocusOut>", self.check_email_availability)
        
        self.vaultname_entry = self.create_entry(right_frame, "vaultname", row=2)
        self.vaultname_entry.bind("<FocusOut>", self.check_vaultname_availability)
        
        self.password_entry = self.create_entry(right_frame, "Password", row=3, show="•")
        self.password_entry.bind("<KeyRelease>", self.update_password_strength)

        self.password_strength_label = ctk.CTkLabel(right_frame, text="Password Strength: ", font=("Helvetica", 12))
        self.password_strength_label.grid(row=4, column=0, padx=100, pady=(0, 10), sticky="w")

        self.confirm_password_entry = self.create_entry(right_frame, "Confirm Password", row=5, show="•")
        
        self.security_question_combobox = ctk.CTkComboBox(right_frame, values=SECURITY_QUESTIONS)
        self.security_question_combobox.grid(row=6, column=0, padx=100, pady=10, sticky="ew")

        self.security_answer_entry = self.create_entry(right_frame, "Security Answer", row=7)

        self.register_button = ctk.CTkButton(
            right_frame,
            text="Register Now",
            command=self.register_admin,
            font=("Roboto", 18, "bold"),
            fg_color="#E94560",
            hover_color="#B83B5E",
            height=50,
            corner_radius=25
        )
        self.register_button.grid(row=8, column=0, padx=100, pady=(20, 50), sticky="ew")

    def create_entry(self, parent, placeholder, row, show=None):
        entry = ctk.CTkEntry(
            parent,
            placeholder_text=placeholder,
            font=("Roboto", 16),
            height=50,
            corner_radius=25,
            border_width=2,
            border_color="#E94560",
            fg_color="#0A2647",
            text_color="#FFFFFF",
            placeholder_text_color="#888888",
            show=show
        )
        entry.grid(row=row, column=0, padx=100, pady=10, sticky="ew")
        return entry

    def update_password_strength(self, event=None):
        password = self.password_entry.get()
        strength = self.evaluate_password_strength(password)
        self.password_strength_label.configure(text=f"Password Strength: {strength}")

    def calculate_entropy(self, password):
        charset_size = 0
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(c in '!@#$%^&*()-_+=' for c in password):
            charset_size += 14
        if charset_size == 0:  # Ensure charset_size is greater than zero
            return 0
        return len(password) * math.log2(charset_size)

    def is_common_password(self, password):
        COMMON_PASSWORDS = ["password", "123456", "123456789", "qwerty", "abc123", "password1", "111111"]
        return password.lower() in COMMON_PASSWORDS

    def evaluate_password_strength(self, password):
        length = len(password)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in '!@#$%^&*()-_+=' for c in password)
        is_sequential = any(password[i:i+3].isalpha() and ord(password[i+1]) == ord(password[i]) + 1 and ord(password[i+2]) == ord(password[i+1]) + 1 for i in range(len(password) - 2))
        is_repeated = any(password.count(c) > len(password) // 2 for c in set(password))

        if self.is_common_password(password):
            return "Very Weak"

        entropy = self.calculate_entropy(password)
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

    def check_vaultname_availability(self, event=None):
        vaultname = self.vaultname_entry.get()
        vaultnames, _ = self.fetch_vaultnames_emails()
        if vaultname in vaultnames:
            tkinter.messagebox.showerror("Registration Failed", "vaultname already exists.")
            self.vaultname_entry.focus_set()
        else:
            print(f"vaultname {vaultname} is available.")

    def check_email_availability(self, event=None):
        email = self.email_entry.get()
        _, emails = self.fetch_vaultnames_emails()
        if email in emails:
            tkinter.messagebox.showerror("Registration Failed", "Email already exists.")
            self.email_entry.focus_set()
        else:
            print(f"Email {email} is available.")

    def fetch_vaultnames_emails(self):
        try:
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT name, email FROM vaults")
            vaults = cursor.fetchall()
            conn.close()
            vaultnames = [vault[0] for vault in vaults]
            emails = [vault[1] for vault in vaults]
            return vaultnames, emails
        except sqlite3.Error as e:
            print(f"SQL Error: {e}")
            return [], []
        except Exception as e:
            print(f"Unexpected error: {e}")
            return [], []

    def register_admin(self):
        email = self.email_entry.get()
        vaultname = self.vaultname_entry.get()
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        security_question = self.security_question_combobox.get()
        security_answer = self.security_answer_entry.get()
        security_code = str(uuid.uuid4())  # Changed to UUID instead of pyotp

        if len(email) == 0 or len(vaultname) == 0 or len(password) == 0 or len(confirm_password) == 0 or security_question == "Select a security question" or len(security_answer) == 0:
            tkinter.messagebox.showerror("Registration Failed", "Please fill out all fields.")
            return

        if not re.match(EMAIL_REGEX, email):
            tkinter.messagebox.showerror("Registration Failed", "Please enter a valid email address.")
            return

        if password != confirm_password:
            tkinter.messagebox.showerror("Registration Failed", "Passwords do not match.")
            return

        if not re.match(PASSWORD_REGEX, password):
            tkinter.messagebox.showerror(
                "Registration Failed", 
                "Password does not meet the required criteria.\n\nPassword must be at least 8 characters long and include:\n- An uppercase letter\n- A lowercase letter\n- A number\n- A special character (@$!%*?&)"
            )
            return

        try:
            print("Attempting to add admin vault...")
            hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()  # Hash the password before storing
            add_admin(vaultname, hashed_password, email, security_question=security_question, security_answer=security_answer, security_code=security_code)
            tkinter.messagebox.showinfo("Registration Successful", f"Admin vault registered successfully. Your security key is: {security_code}")
            self.master.create_login_widgets()  # Correctly call the parent's method
            self.destroy()
        except sqlite3.IntegrityError as e:
            print(f"IntegrityError: {e}")
            tkinter.messagebox.showerror("Registration Failed", "vaultname or email already exists.")
        except Exception as e:
            print(f"Exception: {e}")
            tkinter.messagebox.showerror("Registration Failed", f"An error occurred: {e}")

class LoginWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Quantum Lock - Secure Login")
        self.geometry("1300x800")
        self.configure(fg_color="#1a1a1a")

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        create_db_and_table()  # Ensure the database and tables are created
        create_admin_table()   # Ensure the admin table is created

        # Check for existing admin
        if not admin_exists():
            self.open_admin_registration_window()
        else:
            self.create_login_widgets()

    def create_login_widgets(self):
        # Main frame
        self.main_frame = ctk.CTkFrame(self, corner_radius=20, fg_color="#2b2b2b")
        self.main_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(9, weight=1)

        # Logo
        self.logo_img = ctk.CTkImage(Image.open(resource_path("assets/logo.png")), size=(120, 120))
        self.logo_label = ctk.CTkLabel(self.main_frame, image=self.logo_img, text="")
        self.logo_label.grid(row=0, column=0, padx=30, pady=(40, 20))

        # Title
        self.login_label = ctk.CTkLabel(self.main_frame, text="Quantum Lock",
                                        font=ctk.CTkFont(size=32, weight="bold"), text_color="#ffffff")
        self.login_label.grid(row=1, column=0, padx=30, pady=(0, 5))
        
        self.subtitle_label = ctk.CTkLabel(self.main_frame, text="Secure Login",
                                           font=ctk.CTkFont(size=16), text_color="#a0a0a0")
        self.subtitle_label.grid(row=2, column=0, padx=30, pady=(0, 30))

        # vaultname Entry
        self.vaultname_entry = ctk.CTkEntry(self.main_frame, width=300, height=40, 
                                           placeholder_text="vaultname", border_color="#3a3a3a", 
                                           fg_color="#3a3a3a", text_color="#ffffff")
        self.vaultname_entry.grid(row=3, column=0, padx=30, pady=(0, 15))
        self.vaultname_entry.bind("<Return>", self.focus_password_entry)

        # Password Entry
        self.password_entry = ctk.CTkEntry(self.main_frame, width=300, height=40, show="•", 
                                           placeholder_text="Password", border_color="#3a3a3a", 
                                           fg_color="#3a3a3a", text_color="#ffffff")
        self.password_entry.grid(row=4, column=0, padx=30, pady=(0, 30))
        self.password_entry.bind("<Return>", self.trigger_login)

        # Login Button
        self.login_button = ctk.CTkButton(self.main_frame, text="Login", command=self.login_event, 
                                          width=300, height=40, fg_color="#007bff", hover_color="#0056b3")
        self.login_button.grid(row=5, column=0, padx=30, pady=(0, 15))

        # Register Button
        self.register_button = ctk.CTkButton(self.main_frame, text="Register", command=self.open_register_frame, 
                                             width=300, height=40, fg_color="#17a2b8", hover_color="#138496")
        self.register_button.grid(row=6, column=0, padx=30, pady=(0, 15))

        # Forgot Password Button
        self.forgot_password_button = ctk.CTkButton(self.main_frame, text="Forgot Password", 
                                                    command=self.open_forgot_password_frame, width=300, height=40,
                                                    fg_color="transparent", border_width=2, 
                                                    text_color="#a0a0a0", hover_color="#3a3a3a")
        self.forgot_password_button.grid(row=7, column=0, padx=30, pady=(0, 30))

        # Message Label
        self.message_label = ctk.CTkLabel(self.main_frame, text="", font=("Helvetica", 14), 
                                          text_color="#ff0000", fg_color="#2b2b2b", 
                                          width=300, height=40, wraplength=280)
        self.message_label.grid(row=8, column=0, padx=30, pady=(0, 15))

    def create_reset_password_widgets(self):
        # Initialize the ForgotPasswordFrame here
        self.forgot_password_frame = ForgotPasswordFrame(self)
        self.forgot_password_frame.grid(row=0, column=0, sticky="nsew")

    def display_message(self, message, color="#ff0000"):
        self.message_label.configure(text=message, text_color=color)
        
    def focus_password_entry(self, event):
        self.password_entry.focus_set()

    def trigger_login(self, event):
        self.login_event()

    def login_event(self):
        entered_vaultname = self.vaultname_entry.get()
        entered_password = self.password_entry.get()

        if not entered_vaultname or not entered_password:
            self.display_message("Please enter both vaultname and password.")
            return

        limited, attempts_left, wait_time = rate_limited('vault_login', entered_vaultname)
        if limited:
            self.display_message(
                f"Too many login attempts. Please try again in {int(wait_time // 60)} minutes and {int(wait_time % 60)} seconds. Attempts left: 0."
            )
            return

        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT password, role FROM vaults WHERE name = ?", (entered_vaultname,))
        result = cursor.fetchone()
        conn.close()

        if result and bcrypt.checkpw(entered_password.encode(), result[0].encode()):
            if result[1] == "admin":
                self.display_message("Admin login successful!", color="#00ff00")
                self.after(1000, self.open_admin_page)
            else:
                self.display_message("Login successful!", color="#00ff00")
                self.after(1000, self.open_password_manager, entered_vaultname)
        else:
            self.display_message(f"Invalid vaultname or password. Attempts left: {attempts_left}.")

    def open_password_manager(self, vaultname):
        try:
            self.destroy()
            from main import PasswordManagerApp
            app = PasswordManagerApp(vaultname)
            app.mainloop()
        except Exception as e:
            print(f"Error starting PasswordManagerApp: {e}")
            messagebox.showerror("Error", f"Error starting PasswordManagerApp: {e}")

    def open_admin_page(self):
        self.withdraw()
        from admin import AdminPage
        admin_app = AdminPage(self)
        admin_app.mainloop()
        self.deiconify()

    def open_register_frame(self):
        self.main_frame.grid_forget()
        self.register_frame = RegisterFrame(self)
        self.register_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")

    def open_forgot_password_frame(self):
        self.main_frame.grid_forget()
        self.forgot_password_frame = ForgotPasswordFrame(self)
        self.forgot_password_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")

    def open_admin_registration_window(self):
        admin_registration_window = AdminRegistrationWindow(self)
        admin_registration_window.grab_set()
        self.wait_window(admin_registration_window)
        self.create_login_widgets()

class RegisterFrame(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)

        self.grid_columnconfigure((0, 1), weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.create_left_frame()
        self.create_right_frame()

    def create_left_frame(self):
        left_frame = ctk.CTkFrame(self, fg_color="#16213E", corner_radius=0)
        left_frame.grid(row=0, column=0, sticky="nsew")
        left_frame.grid_rowconfigure((0, 1, 2), weight=1)
        left_frame.grid_columnconfigure(0, weight=1)

        # Title
        title_frame = ctk.CTkFrame(left_frame, fg_color="transparent")
        title_frame.grid(row=0, column=0, padx=50, pady=(50, 0), sticky="new")

        ctk.CTkLabel(title_frame, text="Welcome to", font=("Roboto", 24), text_color="#00A8E8").pack()
        ctk.CTkLabel(title_frame, text="vault Registration", font=("Roboto", 40, "bold"), text_color="#FFFFFF").pack()

        # Decorative element (you can replace this with an actual image)
        canvas = ctk.CTkCanvas(left_frame, width=300, height=300, bg="#16213E", highlightthickness=0)
        canvas.grid(row=1, column=0)
        canvas.create_oval(10, 10, 290, 290, outline="#00A8E8", width=4)
        canvas.create_text(150, 150, text="vault", font=("Arial", 30, "bold"), fill="#FFFFFF")

        # Footer
        ctk.CTkLabel(left_frame, text="Secure • Efficient • Powerful", font=("Roboto", 16), text_color="#00A8E8").grid(row=2, column=0, pady=(0, 50))

    def create_right_frame(self):
        right_frame = ctk.CTkFrame(self, fg_color="#0F3460", corner_radius=0)
        right_frame.grid(row=0, column=1, sticky="nsew")
        right_frame.grid_columnconfigure(0, weight=1)
        right_frame.grid_rowconfigure((0, 1, 2, 3, 4, 5, 6, 7, 8, 9), weight=1)

        ctk.CTkLabel(right_frame, text="Create Your Account", font=("Roboto", 28, "bold"), text_color="#FFFFFF").grid(row=0, column=0, pady=(50, 20))

        self.email_entry = self.create_entry(right_frame, "Email", row=1)
        self.email_entry.bind("<FocusOut>", self.check_email_availability)
        
        self.vaultname_entry = self.create_entry(right_frame, "vaultname", row=2)
        self.vaultname_entry.bind("<FocusOut>", self.check_vaultname_availability)
        
        self.password_entry = self.create_entry(right_frame, "Password", row=3, show="•")
        self.password_entry.bind("<KeyRelease>", self.update_password_strength)

        self.password_strength_label = ctk.CTkLabel(right_frame, text="Password Strength: ", font=("Helvetica", 12))
        self.password_strength_label.grid(row=4, column=0, padx=100, pady=(0, 10), sticky="w")

        self.confirm_password_entry = self.create_entry(right_frame, "Confirm Password", row=5, show="•")
        
        self.security_question_combobox = ctk.CTkComboBox(right_frame, values=SECURITY_QUESTIONS)
        self.security_question_combobox.grid(row=6, column=0, padx=100, pady=10, sticky="ew")

        self.security_answer_entry = self.create_entry(right_frame, "Security Answer", row=7)

        self.register_button = ctk.CTkButton(
            right_frame,
            text="Register Now",
            command=self.register,
            font=("Roboto", 18, "bold"),
            fg_color="#00A8E8",
            hover_color="#007ACC",
            height=50,
            corner_radius=25
        )
        self.register_button.grid(row=8, column=0, padx=100, pady=(20, 50), sticky="ew")

    def create_entry(self, parent, placeholder, row, show=None):
        entry = ctk.CTkEntry(
            parent,
            placeholder_text=placeholder,
            font=("Roboto", 16),
            height=50,
            corner_radius=25,
            border_width=2,
            border_color="#00A8E8",
            fg_color="#0A2647",
            text_color="#FFFFFF",
            placeholder_text_color="#888888",
            show=show
        )
        entry.grid(row=row, column=0, padx=100, pady=10, sticky="ew")
        return entry

    def update_password_strength(self, event=None):
        password = self.password_entry.get()
        strength = self.evaluate_password_strength(password)
        self.password_strength_label.configure(text=f"Password Strength: {strength}")

    def calculate_entropy(self, password):
        charset_size = 0
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(c in '!@#$%^&*()-_+=' for c in password):
            charset_size += 14
        if charset_size == 0:  # Ensure charset_size is greater than zero
            return 0
        return len(password) * math.log2(charset_size)

    def is_common_password(self, password):
        COMMON_PASSWORDS = ["password", "123456", "123456789", "qwerty", "abc123", "password1", "111111"]
        return password.lower() in COMMON_PASSWORDS

    def evaluate_password_strength(self, password):
        length = len(password)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in '!@#$%^&*()-_+=' for c in password)
        is_sequential = any(password[i:i+3].isalpha() and ord(password[i+1]) == ord(password[i]) + 1 and ord(password[i+2]) == ord(password[i+1]) + 1 for i in range(len(password) - 2))
        is_repeated = any(password.count(c) > len(password) // 2 for c in set(password))

        if self.is_common_password(password):
            return "Very Weak"

        entropy = self.calculate_entropy(password)
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

    def check_vaultname_availability(self, event=None):
        vaultname = self.vaultname_entry.get()
        vaultnames, _ = self.fetch_vaultnames_emails()
        if vaultname in vaultnames:
            tkinter.messagebox.showerror("Registration Failed", "vaultname already exists.")
            self.vaultname_entry.focus_set()
        else:
            print(f"vaultname {vaultname} is available.")

    def check_email_availability(self, event=None):
        email = self.email_entry.get()
        _, emails = self.fetch_vaultnames_emails()
        if email in emails:
            tkinter.messagebox.showerror("Registration Failed", "Email already exists.")
            self.email_entry.focus_set()
        else:
            print(f"Email {email} is available.")

    def fetch_vaultnames_emails(self):
        try:
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT name, email FROM vaults")
            vaults = cursor.fetchall()
            conn.close()
            vaultnames = [vault[0] for vault in vaults]
            emails = [vault[1] for vault in vaults]
            return vaultnames, emails
        except sqlite3.Error as e:
            print(f"SQL Error: {e}")
            return [], []
        except Exception as e:
            print(f"Unexpected error: {e}")
            return [], []

    def register(self):
        email = self.email_entry.get()
        vaultname = self.vaultname_entry.get()
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        security_question = self.security_question_combobox.get()
        security_answer = self.security_answer_entry.get()
        security_code = str(uuid.uuid4())  # Changed to UUID instead of pyotp

        if len(email) == 0 or len(vaultname) == 0 or len(password) == 0 or len(confirm_password) == 0 or security_question == "Select a security question" or len(security_answer) == 0:
            tkinter.messagebox.showerror("Registration Failed", "Please fill out all fields.")
            return

        if not re.match(EMAIL_REGEX, email):
            tkinter.messagebox.showerror("Registration Failed", "Please enter a valid email address.")
            return

        if password != confirm_password:
            tkinter.messagebox.showerror("Registration Failed", "Passwords do not match.")
            return

        if not re.match(PASSWORD_REGEX, password):
            tkinter.messagebox.showerror(
                "Registration Failed", 
                "Password does not meet the required criteria.\n\nPassword must be at least 8 characters long and include:\n- An uppercase letter\n- A lowercase letter\n- A number\n- A special character (@$!%*?&)"
            )
            return

        try:
            print("Attempting to add vault...")
            hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()  # Hash the password before storing
            add_vault(vaultname, hashed_password, email, security_question=security_question, security_answer=security_answer, security_code=security_code, role="vault")
            tkinter.messagebox.showinfo("Registration Successful", f"vault registered successfully. Your security key is: {security_code}")
            self.master.create_login_widgets()  # Correctly call the parent's method
            self.destroy()
        except sqlite3.IntegrityError as e:
            print(f"IntegrityError: {e}")
            tkinter.messagebox.showerror("Registration Failed", "vaultname or email already exists.")
        except Exception as e:
            print(f"Exception: {e}")
            tkinter.messagebox.showerror("Registration Failed", f"An error occurred: {e}")

class ForgotPasswordFrame(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master

        # Set color scheme
        self.bg_color = "#1A1A2E"  # Dark blue background
        self.fg_color = "#FFFFFF"  # White text
        self.accent_color = "#E94560"  # Bright pink accent
        self.secondary_bg = "#16213E"  # Darker blue for contrast

        self.configure(fg_color=self.bg_color)

        # Remove weight from row 1 to eliminate bottom space
        self.grid_columnconfigure((0, 1), weight=1)
        self.grid_rowconfigure(0, weight=1)  # Only give weight to row 0

        self.create_left_frame()
        self.create_right_frame()

    def create_left_frame(self):
        left_frame = ctk.CTkFrame(self, fg_color=self.secondary_bg, corner_radius=0)
        left_frame.grid(row=0, column=0, sticky="nsew")
        
        # Adjust row configuration to fill the frame vertically
        left_frame.grid_rowconfigure((0, 1, 2), weight=1)
        left_frame.grid_columnconfigure(0, weight=1)

        # Title
        title_frame = ctk.CTkFrame(left_frame, fg_color="transparent")
        title_frame.grid(row=0, column=0, padx=50, pady=(20, 0), sticky="new")
        
        ctk.CTkLabel(title_frame, text="Password Recovery", font=("Roboto", 24), text_color=self.accent_color).pack()
        ctk.CTkLabel(title_frame, text="Reset Your Password", font=("Roboto", 40, "bold"), text_color=self.fg_color).pack()

        # Decorative element
        canvas = ctk.CTkCanvas(left_frame, width=300, height=300, bg=self.secondary_bg, highlightthickness=0)
        canvas.grid(row=1, column=0, pady=(20, 20))
        canvas.create_oval(10, 10, 290, 290, outline=self.accent_color, width=4)
        canvas.create_text(150, 150, text="RESET", font=("Arial", 30, "bold"), fill=self.fg_color)

        # Footer
        ctk.CTkLabel(left_frame, text="Secure • Simple • Swift", font=("Roboto", 16), text_color=self.accent_color).grid(row=2, column=0, pady=(0, 20))

    def create_right_frame(self):
        right_frame = ctk.CTkFrame(self, fg_color=self.bg_color, corner_radius=0)
        right_frame.grid(row=0, column=1, sticky="nsew")
        
        # Add rows for flexible spacing
        right_frame.grid_rowconfigure(0, weight=1)
        right_frame.grid_rowconfigure(7, weight=1)  # Ensures that rows 0 and 7 take up any extra space for vertical centering

        right_frame.grid_columnconfigure(0, weight=1)
        
        # Place elements in the middle rows
        ctk.CTkLabel(right_frame, text="Recover Your Account", font=("Roboto", 28, "bold"), text_color=self.fg_color).grid(row=1, column=0, pady=(20, 10))

        self.email_entry = self.create_entry(right_frame, "Email", row=2)
        self.security_key_entry = self.create_entry(right_frame, "Security Key", row=3, show="•")

        self.reset_button = self.create_button(right_frame, "Reset Password", self.reset_password, row=4)
        self.forgot_key_button = self.create_button(right_frame, "Forgot Security Key", self.open_forgot_security_key_frame, row=5, is_secondary=True)
        self.back_button = self.create_button(right_frame, "Back", self.go_back_to_login, row=6, is_secondary=True)

        self.message_label = ctk.CTkLabel(right_frame, text="", font=("Roboto", 12), text_color=self.accent_color)
        self.message_label.grid(row=7, column=0, padx=20, pady=(10, 20), sticky="ew")

    def create_entry(self, parent, placeholder, row, show=None):
        entry = ctk.CTkEntry(
            parent,
            placeholder_text=placeholder,
            font=("Roboto", 16),
            height=50,
            corner_radius=25,
            border_width=2,
            border_color=self.accent_color,
            fg_color=self.secondary_bg,
            text_color=self.fg_color,
            placeholder_text_color="#888888",
            show=show
        )
        entry.grid(row=row, column=0, padx=100, pady=10, sticky="ew")
        return entry

    def create_button(self, parent, text, command, row, is_secondary=False):
        button = ctk.CTkButton(
            parent,
            text=text,
            command=command,
            font=("Roboto", 18, "bold"),
            fg_color=self.accent_color if not is_secondary else "transparent",
            hover_color="#B83B5E" if not is_secondary else "#34495E",
            height=50,
            corner_radius=25,
            border_width=2 if is_secondary else 0,
            border_color=self.accent_color if is_secondary else None,
            text_color=self.fg_color
        )
        button.grid(row=row, column=0, padx=100, pady=10, sticky="ew")
        return button

    def reset_password(self):
        email = self.email_entry.get()
        security_key = self.security_key_entry.get()

        if not self.validate_input(email, security_key):
            return

        try:
            if self.verify_security_key(email, security_key):
                new_password = self.prompt_new_password()
                if new_password:
                    self.update_password_and_security_key(email, new_password)
                    self.show_success_message(email)
                    self.master.create_login_widgets()
                    self.destroy()
            else:
                self.show_error_message("Incorrect security key.")
        except Exception as e:
            self.show_error_message(f"An error occurred: {e}")

    def validate_input(self, email, security_key):
        if not email or not security_key:
            self.show_error_message("Please enter both email and security key.")
            return False
        if not re.match(EMAIL_REGEX, email):
            self.show_error_message("Please enter a valid email address.")
            return False
        return True

    def verify_security_key(self, email, security_key):
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT security_code FROM vaults WHERE email = ?", (email,))
        result = cursor.fetchone()
        conn.close()
        return result and result[0] == security_key

    def prompt_new_password(self):
        while True:
            new_password = simpledialog.askstring("New Password", "Enter your new password:", show="*")
            if not new_password:
                return None
            if re.match(PASSWORD_REGEX, new_password):
                return new_password
            self.show_error_message("Password does not meet the required criteria.")

    def update_password_and_security_key(self, email, new_password):
        new_security_key = str(uuid.uuid4())  # Changed to UUID instead of pyotp
        hashed_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("UPDATE vaults SET password = ?, security_code = ? WHERE email = ?", (hashed_password, new_security_key, email))
        conn.commit()
        conn.close()
        self.show_security_key_popup(new_security_key)

    def show_success_message(self, email):
        tkinter.messagebox.showinfo("Reset Successful", f"Password has been reset for {email}.")

    def show_error_message(self, message):
        self.message_label.configure(text=message)

    def open_forgot_security_key_frame(self):
        email = self.email_entry.get()
        if not email or not re.match(EMAIL_REGEX, email):
            self.show_error_message("Please enter a valid email address before proceeding.")
            return
        try:
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT security_question, security_answer FROM vaults WHERE email = ?", (email,))
            result = cursor.fetchone()
            conn.close()

            if result is None:
                self.show_error_message("Email does not exist.")
                return

            stored_security_question, stored_security_answer = result
            forgot_security_key_frame = ForgotSecurityKeyFrame(self, email, stored_security_question, stored_security_answer)
            forgot_security_key_frame.grid(row=0, column=0, columnspan=2, sticky="nsew")
        except Exception as e:
            self.show_error_message(f"An error occurred: {e}")

    def show_security_key_popup(self, security_key):
        SecurityKeyPopup(self, security_key)

    def go_back_to_login(self):
        self.master.create_login_widgets()
        self.destroy()
        
    def reinitialize(self):
        self.grid_forget()
        self.master.create_reset_password_widgets()  # Assuming this method sets up the ForgotPasswordFrame widgets


class ForgotSecurityKeyFrame(ctk.CTkFrame):
    def __init__(self, master, email, security_question, security_answer):
        super().__init__(master, fg_color=master.bg_color)
        self.master = master
        self.email = email
        self.security_answer = security_answer

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure((0, 1, 2, 3, 4, 5, 6, 7), weight=1)

        ctk.CTkLabel(self, text="Security Question", font=("Roboto", 28, "bold"), text_color=master.fg_color).grid(row=0, column=0, pady=(50, 20))
        ctk.CTkLabel(self, text=security_question, font=("Roboto", 16), text_color=master.fg_color).grid(row=1, column=0, padx=50, pady=(10, 0), sticky="w")

        self.answer_entry = master.create_entry(self, "Your Answer", row=2)
        self.reset_button = master.create_button(self, "Reset Security Key", self.reset_security_key, row=3)

        self.message_label = ctk.CTkLabel(self, text="", font=("Roboto", 12), text_color=master.accent_color)
        self.message_label.grid(row=4, column=0, padx=20, pady=(10, 20), sticky="ew")

        self.security_key_label = ctk.CTkLabel(self, text="", font=("Roboto", 16, "bold"), text_color=master.accent_color)
        self.security_key_label.grid(row=5, column=0, padx=20, pady=(10, 20), sticky="ew")

        self.copy_button = master.create_button(self, "Copy Security Key", self.copy_security_key, row=6)
        self.copy_button.grid_remove()  # Hide the button initially

        self.back_button = master.create_button(self, "Back", self.go_back, row=7, is_secondary=True)

    def reset_security_key(self):
        entered_answer = self.answer_entry.get()

        if entered_answer.lower() == self.security_answer.lower():
            new_security_key = str(uuid.uuid4())
            try:
                conn = sqlite3.connect(DATABASE_NAME)
                cursor = conn.cursor()
                cursor.execute("UPDATE vaults SET security_code = ? WHERE email = ?", (new_security_key, self.email))
                conn.commit()
                conn.close()

                self.show_security_key(new_security_key)
            except Exception as e:
                self.message_label.configure(text=f"An error occurred: {e}")
        else:
            self.message_label.configure(text="Incorrect answer to the security question.")

    def show_security_key(self, security_key):
        self.security_key_label.configure(text=f"Your new Security Key: {security_key}")
        self.copy_button.grid()  # Show the copy button

    def copy_security_key(self):
        self.clipboard_clear()
        self.clipboard_append(self.security_key_label.cget("text").split(": ")[1])
        tkinter.messagebox.showinfo("Copied", "Security Key copied to clipboard.")

    def go_back(self):
        self.destroy()
        self.master.reinitialize()  # Call reinitialize on the parent frame


class SecurityKeyPopup(ctk.CTkToplevel):
    def __init__(self, master, security_key):
        super().__init__(master)

        self.master = master
        self.title("New Security Key")
        self.geometry("400x250")
        self.configure(fg_color=master.bg_color)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure((0, 1, 2, 3, 4), weight=1)  # Adjust row configuration for the back button

        ctk.CTkLabel(self, text="Your new security key is:", font=("Roboto", 18), text_color=master.fg_color).grid(row=0, column=0, padx=20, pady=(30, 10), sticky="ew")

        key_label = ctk.CTkLabel(self, text=security_key, font=("Roboto", 24, "bold"), text_color=master.accent_color)
        key_label.grid(row=1, column=0, padx=20, pady=10, sticky="ew")

        copy_button = self.create_button(self, "Copy to Clipboard", lambda: self.copy_to_clipboard(security_key), row=2)
        close_button = self.create_button(self, "Close", self.destroy, row=3, is_secondary=True)
        back_button = self.create_button(self, "Back", self.go_back, row=4, is_secondary=True)

    def create_button(self, parent, text, command, row, is_secondary=False):
        button = ctk.CTkButton(
            parent,
            text=text,
            command=command,
            font=("Roboto", 18, "bold"),
            fg_color=self.master.accent_color if not is_secondary else "transparent",
            hover_color="#B83B5E" if not is_secondary else "#34495E",
            height=50,
            corner_radius=25,
            border_width=2 if is_secondary else 0,
            border_color=self.master.accent_color if is_secondary else None,
            text_color=self.master.fg_color
        )
        button.grid(row=row, column=0, padx=100, pady=(20, 10), sticky="ew")
        return button

    def copy_to_clipboard(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)
        tkinter.messagebox.showinfo("Copied", "Security key copied to clipboard.")

    def go_back(self):
        self.destroy()
        self.master.open_forgot_password_frame()  # Adjust as needed to call the relevant method to open the password reset dialog


if __name__ == "__main__":
    login_app = LoginWindow()
    login_app.mainloop()
