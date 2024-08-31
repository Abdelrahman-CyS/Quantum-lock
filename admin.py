import tkinter as tk
import customtkinter as ctk
from tkinter import messagebox
import uuid
import re
import sqlite3
import bcrypt
from database import fetch_vaults, delete_vault, add_vault, update_vault, insert_admin_credentials, verify_admin_credentials, create_admin_table, admin_exists
from login import LoginWindow
from customtkinter import CTkLabel, CTkFrame

SECURITY_QUESTIONS = [
    "What’s your favorite movie?",
    "What was your dream job as a child?",
    "What is your favorite color?"
]

EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
PASSWORD_REGEX = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
DATABASE_NAME = "password_manager.db" 

# Function to register a new vault with hashed password
def register_vault(vaultname, password, email, security_question, security_answer, security_code):
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    add_vault(vaultname, hashed_password, email, security_question, security_answer, security_code)

class AdminPage(ctk.CTkToplevel):
    def __init__(self, master, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.title("Quantum Lock - Admin Dashboard")
        self.geometry("1200x800")
        self.configure(fg_color="#1a1a1a")

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.create_sidebar()
        self.create_main_content()

        self.admin_vault = None  # Store admin vault details
        self.all_vaults = []  # Store all vaults
        self.fetch_all_vaults()  # Fetch all vaults when initializing

    def create_sidebar(self):
        sidebar = ctk.CTkFrame(self, fg_color="#2b2b2b", width=200, corner_radius=0)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_rowconfigure(7, weight=1)

        logo_label = ctk.CTkLabel(sidebar, text="Admin Panel", font=ctk.CTkFont(size=20, weight="bold"))
        logo_label.grid(row=0, column=0, padx=20, pady=(20, 30))

        buttons = [
            ("Dashboard", self.show_dashboard),
            ("vault Management", self.show_vault_management),
            ("Add vault", self.show_add_vault)
        ]

        for i, (text, command) in enumerate(buttons, start=1):
            btn = ctk.CTkButton(sidebar, text=text, command=command, fg_color="transparent", anchor="w")
            btn.grid(row=i, column=0, padx=20, pady=10, sticky="ew")

        logout_btn = ctk.CTkButton(sidebar, text="Logout", command=self.logout, fg_color="#d32f2f", hover_color="#b71c1c")
        logout_btn.grid(row=8, column=0, padx=20, pady=20, sticky="ew")

    def create_main_content(self):
        self.main_frame = ctk.CTkFrame(self, fg_color="#1a1a1a")
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)

        self.header_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.header_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        self.header_frame.grid_columnconfigure(1, weight=1)

        self.title_label = ctk.CTkLabel(self.header_frame, text="Dashboard", 
                                        font=ctk.CTkFont(size=24, weight="bold"),
                                        text_color="#ffffff")
        self.title_label.grid(row=0, column=0, sticky="w", padx=10, pady=10)

        self.search_entry = ctk.CTkEntry(self.header_frame, placeholder_text="Search vaults...",
                                        fg_color="#2b2b2b", text_color="#ffffff",
                                        placeholder_text_color="#888888")
        self.search_entry.grid(row=0, column=1, sticky="e", padx=10, pady=10)
        self.search_entry.bind("<KeyRelease>", self.live_search)

        self.content_frame = ctk.CTkScrollableFrame(self.main_frame, fg_color="#1a1a1a")
        self.content_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        self.content_frame.grid_columnconfigure(0, weight=1)

        # Customize scrollbar colors
        self.content_frame._scrollbar.configure(fg_color="#2b2b2b", button_color="#4CAF50", button_hover_color="#45a049")

        self.show_dashboard()

    def show_dashboard(self):
        self.clear_content()
        self.title_label.configure(text="Dashboard")
        
        # Add dashboard widgets here
        stats_frame = ctk.CTkFrame(self.content_frame)
        stats_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        stats_frame.grid_columnconfigure((0, 1, 2), weight=1)

        self.total_vaults_label = self.create_stat_widget(stats_frame, "Total vaults", "loading...", 0, 0)
        self.active_vaults_label = self.create_stat_widget(stats_frame, "Active vaults", "loading...", 0, 1)
        self.total_passwords_label = self.create_stat_widget(stats_frame, "Total Passwords", "loading...", 0, 2)

        # Load actual data
        self.load_dashboard_data()

    def create_stat_widget(self, parent, title, value, row, column):
        frame = ctk.CTkFrame(parent)
        frame.grid(row=row, column=column, padx=10, pady=10, sticky="nsew")
        
        title_label = ctk.CTkLabel(frame, text=title, font=ctk.CTkFont(size=16, weight="bold"))
        title_label.pack(pady=(10, 5))
        
        value_label = ctk.CTkLabel(frame, text=value, font=ctk.CTkFont(size=24))
        value_label.pack(pady=(5, 10))
        
        return value_label

    def load_dashboard_data(self):
        vaults = fetch_vaults()
        total_vaults = len(vaults)
        active_vaults = total_vaults  # Placeholder for active vaults count
        total_passwords = sum(vault[3] for vault in vaults)

        # Update the stat widgets
        self.total_vaults_label.configure(text=str(total_vaults))
        self.active_vaults_label.configure(text=str(active_vaults))
        self.total_passwords_label.configure(text=str(total_passwords))

    def show_vault_management(self):
        self.clear_content()
        self.title_label.configure(text="vault Management")
        self.refresh_vaults()

    def show_add_vault(self):
        self.clear_content()
        self.title_label.configure(text="Add vault")
        
        add_vault_frame = ctk.CTkFrame(self.content_frame, fg_color="#2b2b2b")
        add_vault_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        add_vault_frame.grid_columnconfigure(0, weight=1)
        add_vault_frame.grid_rowconfigure((0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10), weight=1)

        label = ctk.CTkLabel(add_vault_frame, text="Register New vault", font=("Helvetica", 20, "bold"))
        label.grid(row=0, column=0, padx=10, pady=(20, 10), sticky="ew")

        email_label = ctk.CTkLabel(add_vault_frame, text="Email:")
        email_label.grid(row=1, column=0, padx=10, pady=(10, 0), sticky="w")
        self.email_entry = ctk.CTkEntry(add_vault_frame)
        self.email_entry.grid(row=2, column=0, padx=10, pady=(0, 10), sticky="ew")
        self.email_entry.bind("<FocusOut>", lambda event: self.check_email_availability(event, self.email_entry))

        vaultname_label = ctk.CTkLabel(add_vault_frame, text="vaultname:")
        vaultname_label.grid(row=3, column=0, padx=10, pady=(10, 0), sticky="w")
        self.vaultname_entry = ctk.CTkEntry(add_vault_frame)
        self.vaultname_entry.grid(row=4, column=0, padx=10, pady=(0, 10), sticky="ew")
        self.vaultname_entry.bind("<FocusOut>", lambda event: self.check_vaultname_availability(event, self.vaultname_entry))

        password_label = ctk.CTkLabel(add_vault_frame, text="Password:")
        password_label.grid(row=5, column=0, padx=10, pady=(10, 0), sticky="w")
        self.password_entry = ctk.CTkEntry(add_vault_frame, show="*")
        self.password_entry.grid(row=6, column=0, padx=10, pady=(0, 10), sticky="ew")
        self.password_entry.bind("<KeyRelease>", lambda event: self.update_password_strength(event, self.password_entry))

        self.password_strength_label = ctk.CTkLabel(add_vault_frame, text="Password Strength: ", text_color="#E0E0E0")
        self.password_strength_label.grid(row=7, column=0, padx=10, pady=(0, 10), sticky="w")

        # Create a frame for password requirements
        password_req_frame = CTkFrame(add_vault_frame, fg_color="#3a3a3a", corner_radius=6)
        password_req_frame.grid(row=8, column=0, padx=20, pady=(10, 20), sticky="ew")

        # Title for password requirements
        req_title = CTkLabel(
            password_req_frame,
            text="Password Requirements:",
            font=("Helvetica", 12, "bold"),
            text_color="#4CAF50"
        )
        req_title.pack(padx=10, pady=(10, 5), anchor="w")

        # List of requirements
        requirements = [
            "At least 8 characters long",
            "Include an uppercase letter",
            "Include a lowercase letter",
            "Include a number",
            "Include a special character (@$!%*?&)"
        ]

        for req in requirements:
            req_label = CTkLabel(
                password_req_frame,
                text=f"• {req}",
                font=("Helvetica", 11),
                text_color="#E0E0E0"
            )
            req_label.pack(padx=20, pady=2, anchor="w")

        confirm_password_label = ctk.CTkLabel(add_vault_frame, text="Confirm Password:")
        confirm_password_label.grid(row=9, column=0, padx=10, pady=(10, 0), sticky="w")
        self.confirm_password_entry = ctk.CTkEntry(add_vault_frame, show="*")
        self.confirm_password_entry.grid(row=10, column=0, padx=10, pady=(0, 10), sticky="ew")

        security_question_label = ctk.CTkLabel(add_vault_frame, text="Security Question:")
        security_question_label.grid(row=11, column=0, padx=10, pady=(10, 0), sticky="w")
        self.security_question_combobox = ctk.CTkComboBox(add_vault_frame, values=SECURITY_QUESTIONS)
        self.security_question_combobox.grid(row=12, column=0, padx=10, pady=(0, 10), sticky="ew")

        security_answer_label = ctk.CTkLabel(add_vault_frame, text="Security Answer:")
        security_answer_label.grid(row=13, column=0, padx=10, pady=(10, 0), sticky="w")
        self.security_answer_entry = ctk.CTkEntry(add_vault_frame)
        self.security_answer_entry.grid(row=14, column=0, padx=10, pady=(0, 10), sticky="ew")

        register_button = ctk.CTkButton(add_vault_frame, text="Register", 
                                        command=self.add_vault)
        register_button.grid(row=15, column=0, padx=10, pady=(10, 20), sticky="ew")

    def show_view_vault(self, vault):
        self.clear_content()
        self.title_label.configure(text="View vault")
        
        view_vault_frame = ctk.CTkFrame(self.content_frame, fg_color="#2b2b2b")
        view_vault_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        view_vault_frame.grid_columnconfigure(0, weight=1)
        
        id_label = ctk.CTkLabel(view_vault_frame, text="vault ID:")
        id_label.grid(row=0, column=0, padx=20, pady=(20, 5), sticky="w")
        self.id_entry = ctk.CTkEntry(view_vault_frame)
        self.id_entry.grid(row=1, column=0, padx=20, pady=5, sticky="ew")
        self.id_entry.insert(0, vault["id"])
        self.id_entry.configure(state="readonly")  # Make vault ID read-only

        vaultname_label = ctk.CTkLabel(view_vault_frame, text="vaultname:")
        vaultname_label.grid(row=2, column=0, padx=20, pady=(20, 5), sticky="w")
        self.vaultname_entry = ctk.CTkEntry(view_vault_frame)
        self.vaultname_entry.grid(row=3, column=0, padx=20, pady=5, sticky="ew")
        self.vaultname_entry.insert(0, vault["vaultname"])
        self.vaultname_entry.configure(state="readonly")  # Make vaultname read-only

        email_label = ctk.CTkLabel(view_vault_frame, text="Email:")
        email_label.grid(row=4, column=0, padx=20, pady=5, sticky="w")
        self.email_entry = ctk.CTkEntry(view_vault_frame)
        self.email_entry.grid(row=5, column=0, padx=20, pady=5, sticky="ew")
        self.email_entry.insert(0, vault["email"])
        self.email_entry.configure(state="readonly")  # Make email read-only

        password_label = ctk.CTkLabel(view_vault_frame, text="Password:")
        password_label.grid(row=6, column=0, padx=20, pady=5, sticky="w")
        self.password_entry = ctk.CTkEntry(view_vault_frame, show="*")
        self.password_entry.grid(row=7, column=0, padx=20, pady=5, sticky="ew")
        self.password_entry.insert(0, vault["password"])
        self.password_entry.configure(state="readonly")  # Make password read-only

        security_question_label = ctk.CTkLabel(view_vault_frame, text="Security Question:")
        security_question_label.grid(row=8, column=0, padx=20, pady=5, sticky="w")
        self.security_question_entry = ctk.CTkEntry(view_vault_frame)
        self.security_question_entry.grid(row=9, column=0, padx=20, pady=5, sticky="ew")
        self.security_question_entry.insert(0, vault["security_question"])
        self.security_question_entry.configure(state="readonly")  # Make security question read-only

        security_answer_label = ctk.CTkLabel(view_vault_frame, text="Security Answer:")
        security_answer_label.grid(row=10, column=0, padx=20, pady=5, sticky="w")
        self.security_answer_entry = ctk.CTkEntry(view_vault_frame)
        self.security_answer_entry.grid(row=11, column=0, padx=20, pady=5, sticky="ew")
        self.security_answer_entry.insert(0, vault["security_answer"])
        self.security_answer_entry.configure(state="readonly")  # Make security answer read-only

        security_code_label = ctk.CTkLabel(view_vault_frame, text="Security Key:")
        security_code_label.grid(row=12, column=0, padx=20, pady=5, sticky="w")
        self.security_code_entry = ctk.CTkEntry(view_vault_frame, show="*")
        self.security_code_entry.grid(row=13, column=0, padx=20, pady=5, sticky="ew")
        self.security_code_entry.insert(0, vault["security_code"])
        self.security_code_entry.configure(state="readonly")  # Make security code read-only

        # Toggle visibility buttons
        self.show_password_button = ctk.CTkButton(view_vault_frame, text="👁", width=30, command=self.toggle_password_visibility)
        self.show_password_button.grid(row=7, column=1, padx=(5, 10), pady=5)

        self.show_key_button = ctk.CTkButton(view_vault_frame, text="👁", width=30, command=self.toggle_key_visibility)
        self.show_key_button.grid(row=13, column=1, padx=(5, 10), pady=5)

        self.password_entry_visible = False
        self.security_code_entry_visible = False

    def toggle_password_visibility(self):
        if self.password_entry_visible:
            self.password_entry.configure(show="*")
        else:
            self.password_entry.configure(show="")
        self.password_entry_visible = not self.password_entry_visible

    def toggle_key_visibility(self):
        if self.security_code_entry_visible:
            self.security_code_entry.configure(show="*")
        else:
            self.security_code_entry.configure(show="")
        self.security_code_entry_visible = not self.security_code_entry_visible

    def check_email_availability(self, event, email_entry):
        email = email_entry.get()
        _, emails = self.fetch_vaultnames_emails()
        if email in emails:
            tk.messagebox.showerror("Registration Failed", "Email already exists.")
            email_entry.focus_set()
        else:
            print(f"Email {email} is available.")

    def check_vaultname_availability(self, event, vaultname_entry):
        vaultname = vaultname_entry.get()
        vaultnames, _ = self.fetch_vaultnames_emails()
        if vaultname in vaultnames:
            tk.messagebox.showerror("Registration Failed", "vaultname already exists.")
            vaultname_entry.focus_set()
        else:
            print(f"vaultname {vaultname} is available.")

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

    def update_password_strength(self, event, password_entry):
        password = password_entry.get()
        strength = self.evaluate_password_strength(password)
        self.password_strength_label.configure(text=f"Password Strength: {strength}")

    def evaluate_password_strength(self, password):
        if re.match(PASSWORD_REGEX, password):
            return "Strong"
        elif len(password) >= 8:
            return "Medium"
        else:
            return "Weak"

    def create_vault_card(self, vault, admin=False):
        card = ctk.CTkFrame(self.content_frame, corner_radius=10, fg_color="#2b2b2b" if admin else "#333333")
        card.grid(padx=10, pady=10, sticky="ew")
        card.grid_columnconfigure(1, weight=1)

        vaultname_label = ctk.CTkLabel(card, text=vault["vaultname"], font=ctk.CTkFont(size=16, weight="bold"), text_color="#ffffff")
        vaultname_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

        email_label = ctk.CTkLabel(card, text=vault["email"], text_color="#cccccc")
        email_label.grid(row=1, column=0, padx=10, pady=2, sticky="w")

        password_count_label = ctk.CTkLabel(card, text=f"Passwords: {vault['password_count']}", text_color="#cccccc")
        password_count_label.grid(row=2, column=0, padx=10, pady=2, sticky="w")

        view_button = ctk.CTkButton(card, text="View", command=lambda: self.show_view_vault(vault),
                                    fg_color="#4CAF50", hover_color="#45a049", text_color="#ffffff")
        view_button.grid(row=0, column=1, rowspan=3, padx=10, pady=5, sticky="e")

        if not admin:
            delete_button = ctk.CTkButton(card, text="Delete", fg_color="#d32f2f", hover_color="#b71c1c", 
                                        command=lambda: self.delete_vault(vault["id"]))
            delete_button.grid(row=0, column=2, rowspan=3, padx=10, pady=5, sticky="e")

        if admin:
            admin_label = ctk.CTkLabel(card, text="ADMIN", font=ctk.CTkFont(size=12, weight="bold"), 
                                    text_color="#FFD700", fg_color="#1a1a1a", corner_radius=5)
            admin_label.grid(row=0, column=2, padx=10, pady=5, sticky="e")
            
    def clear_content(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def logout(self):
        if self.master.winfo_exists():
            self.destroy()
            self.master.deiconify()
        else:
            print("Application has been destroyed.")
        
    def add_vault(self):
        email = self.email_entry.get()
        vaultname = self.vaultname_entry.get()
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        security_question = self.security_question_combobox.get()
        security_answer = self.security_answer_entry.get()
        security_code = str(uuid.uuid4())

        if len(email) == 0 or len(vaultname) == 0 or len(password) == 0 or len(confirm_password) == 0:
            tk.messagebox.showerror("Registration Failed", "Please fill out all fields.")
            return

        if not self.is_valid_email(email):
            tk.messagebox.showerror("Registration Failed", "Please enter a valid email address.")
            return

        if password != confirm_password:
            tk.messagebox.showerror("Registration Failed", "Passwords do not match.")
            return

        if not re.match(PASSWORD_REGEX, password):
            missing_criteria = []
            if len(password) < 8:
                missing_criteria.append("- At least 8 characters long")
            if not re.search(r'[A-Z]', password):
                missing_criteria.append("- An uppercase letter")
            if not re.search(r'[a-z]', password):
                missing_criteria.append("- A lowercase letter")
            if not re.search(r'\d', password):
                missing_criteria.append("- A number")
            if not re.search(r'[@$!%*?&]', password):
                missing_criteria.append("- A special character (@$!%*?&)")

            error_message = "Password does not meet the required criteria.\n\nYour password is missing:\n" + "\n".join(missing_criteria)
            tk.messagebox.showerror("Registration Failed", error_message)
            return

        try:
            print("Attempting to add vault...")
            register_vault(vaultname, password, email, security_question, security_answer, security_code)
            tk.messagebox.showinfo("Registration Successful", f"vault registered successfully. Your security key is: {security_code}")
            self.refresh_vaults()  # Refresh vault list after adding a new vault
            self.show_vault_management()
        except sqlite3.IntegrityError as e:
            print(f"IntegrityError: {e}")
            tk.messagebox.showerror("Registration Failed", "vaultname or email already exists.")
        except Exception as e:
            print(f"Exception: {e}")
            tk.messagebox.showerror("Registration Failed", f"An error occurred: {e}")

    def is_valid_email(self, email):
        return re.match(EMAIL_REGEX, email) is not None

    def delete_vault(self, vault_id):
        if not self.winfo_exists():
            return
        confirm = tk.messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete vault with ID {vault_id}?")
        if confirm:
            try:
                delete_vault(vault_id)
                tk.messagebox.showinfo("Success", f"vault with ID {vault_id} deleted successfully!")
                self.refresh_vaults()
            except Exception as e:
                tk.messagebox.showerror("Delete vault Failed", f"An error occurred: {e}")

    def refresh_vaults(self):
        self.fetch_all_vaults()
        self.display_vaults(self.all_vaults)

    def fetch_all_vaults(self):
        self.all_vaults = fetch_vaults()  # Fetch all vaults from the database

    def display_vaults(self, vaults):
        self.clear_content()
        admin_vault = None
        if not vaults:
            no_vaults_label = ctk.CTkLabel(self.content_frame, text="No vaults found.")
            no_vaults_label.grid(padx=10, pady=10)
        else:
            for vault in vaults:
                if vault[7] == 'admin':
                    admin_vault = vault
                    break

            if admin_vault:
                self.create_vault_card({
                    "id": admin_vault[0],
                    "vaultname": admin_vault[1],
                    "email": admin_vault[2],
                    "password_count": admin_vault[3],
                    "security_question": admin_vault[4],
                    "security_answer": admin_vault[5],
                    "security_code": admin_vault[6],
                    "password": admin_vault[7]
                }, admin=True)

                separator = ctk.CTkLabel(self.content_frame, text="", fg_color="#888888")
                separator.grid(padx=10, pady=10, sticky="ew")

            for vault in vaults:
                if vault[7] != 'admin':
                    self.create_vault_card({
                        "id": vault[0],
                        "vaultname": vault[1],
                        "email": vault[2],
                        "password_count": vault[3],
                        "security_question": vault[4],
                        "security_answer": vault[5],
                        "security_code": vault[6],
                        "password": vault[7]
                    })

    def create_vault_card(self, vault, admin=False):
        card = ctk.CTkFrame(self.content_frame, corner_radius=10, fg_color="#1e3a5f" if admin else "#333333")
        card.grid(padx=10, pady=10, sticky="ew")
        card.grid_columnconfigure(1, weight=1)

        if admin:
            admin_badge = ctk.CTkLabel(card, text="ADMIN", font=ctk.CTkFont(size=14, weight="bold"), 
                                    text_color="#FFD700", fg_color="#0d1b2a", corner_radius=5)
            admin_badge.grid(row=0, column=0, padx=(10, 5), pady=5, sticky="w")
            
            self.vaultname_entry = ctk.CTkEntry(card)
            self.vaultname_entry.insert(0, vault["vaultname"])
            self.vaultname_entry.configure(state="disabled")
            self.vaultname_entry.grid(row=1, column=0, padx=10, pady=5, sticky="w")
            
            self.email_entry = ctk.CTkEntry(card)
            self.email_entry.insert(0, vault["email"])
            self.email_entry.configure(state="disabled")
            self.email_entry.grid(row=2, column=0, padx=10, pady=5, sticky="w")

            edit_button = ctk.CTkButton(card, text="Edit", command=lambda: self.edit_vault_info(vault), fg_color="#FFD700", hover_color="#FFB300", text_color="#333333")
            edit_button.grid(row=3, column=0, padx=10, pady=5, sticky="e")

            self.save_button = ctk.CTkButton(card, text="Save", command=self.save_vault_info, fg_color="#4CAF50", hover_color="#45a049", text_color="#ffffff")
            self.save_button.grid(row=3, column=1, padx=10, pady=5, sticky="e")
            self.save_button.grid_remove()

        else:
            vaultname_label = ctk.CTkLabel(card, text=vault["vaultname"], 
                                        font=ctk.CTkFont(size=16, weight="bold"), 
                                        text_color="#ffffff")
            vaultname_label.grid(row=0, column=0, columnspan=2, padx=10, pady=5, sticky="w")

            email_label = ctk.CTkLabel(card, text=vault["email"], 
                                    text_color="#8ebbff" if admin else "#cccccc")
            email_label.grid(row=1, column=0, columnspan=2, padx=10, pady=2, sticky="w")

            password_count_label = ctk.CTkLabel(card, text=f"Passwords: {vault['password_count']}", 
                                                text_color="#8ebbff" if admin else "#cccccc")
            password_count_label.grid(row=2, column=0, columnspan=2, padx=10, pady=2, sticky="w")

            view_button = ctk.CTkButton(card, text="View", command=lambda: self.show_view_vault(vault),
                                        fg_color="#4CAF50", hover_color="#45a049", text_color="#ffffff")
            view_button.grid(row=0, column=2, rowspan=3, padx=10, pady=5, sticky="e")

            delete_button = ctk.CTkButton(card, text="Delete", fg_color="#d32f2f", hover_color="#b71c1c", 
                                        command=lambda: self.delete_vault(vault["id"]))
            delete_button.grid(row=0, column=3, rowspan=3, padx=10, pady=5, sticky="e")

    def edit_vault_info(self, vault):
        self.edit_mode = True
        self.current_admin_id = vault["id"]
        self.vaultname_entry.configure(state="normal")
        self.email_entry.configure(state="normal")
        self.save_button.grid()

    def save_vault_info(self):
        if self.edit_mode:
            updated_vaultname = self.vaultname_entry.get()
            updated_email = self.email_entry.get()
            vault_id = self.current_admin_id

            # Update the database with the modified details
            update_vault(vault_id, updated_vaultname, updated_email)
            self.edit_mode = False
            self.vaultname_entry.configure(state="disabled")
            self.email_entry.configure(state="disabled")
            self.save_button.grid_remove()
            messagebox.showinfo("Success", "Admin details updated successfully.")
            self.refresh_vaults()

    def live_search(self, event):
        search_term = self.search_entry.get().lower()
        filtered_vaults = [
            vault for vault in self.all_vaults
            if search_term in vault[1].lower() or search_term in vault[2].lower()
        ]
        self.display_vaults(filtered_vaults)

    def filter_vaults(self, event=None):
        search_term = self.search_entry.get().lower()
        filtered_vaults = [
            vault for vault in self.all_vaults
            if search_term in vault[1].lower() or search_term in vault[2].lower()
        ]
        self.display_vaults(filtered_vaults)

if __name__ == "__main__":
    create_admin_table()
    if not admin_exists():
        insert_admin_credentials('admin', 'defaultpassword')
    app = LoginWindow()
    app.mainloop()
