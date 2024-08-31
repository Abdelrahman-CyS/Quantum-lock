import tkinter
import tkinter.messagebox
import customtkinter as ctk
import pyperclip
import sqlite3
import math

from tkinter import ttk
from cryptography.fernet import Fernet
from random import choice, randint, shuffle
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from login import LoginWindow, load_keys, resource_path
from database import DATABASE_NAME, create_db_and_table, save_password, load_passwords, delete_password, delete_all_passwords, update_password, verify_database_structure, fetch_vault_email
from encryption import decrypt_string_fernet, decrypt_string_aes, decrypt_string_3des

ctk.set_appearance_mode("System")  # Modes: "System" (standard), "Dark", "Light")
ctk.set_default_color_theme("dark-blue")  # Themes: "blue" (standard), "green", "dark-blue")

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
    COMMON_PASSWORDS = ["password", "123456", "123456789", "qwerty", "abc123", "password1", "111111"]
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

class PasswordManagerApp(ctk.CTk):
    def __init__(self, vaultname):
        super().__init__()

        self.vaultname = vaultname
        self.fernet_key, self.aes_key, self.des3_key = load_keys()
        self.encryption_method = ctk.StringVar(value="Fernet")
        self.vault_email = fetch_vault_email(self.vaultname)

        self.title("Quantum Lock - Password Manager")
        self.geometry("1300x800")
        self.configure(fg_color="#1a1a1a")

        create_db_and_table()
        verify_database_structure()

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0, fg_color="#2b2b2b")
        self.sidebar_frame.grid(row=0, column=0, rowspan=2, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(7, weight=1)  # Add weight to push logout button to bottom

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="Password Manager", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 30))

        button_params = {"width": 180, "height": 40, "corner_radius": 6, "fg_color": "#3a3a3a", "hover_color": "#4a4a4a"}
        
        self.view_passwords_button = ctk.CTkButton(self.sidebar_frame, text="View Passwords", command=self.view_passwords, **button_params)
        self.view_passwords_button.grid(row=1, column=0, padx=10, pady=(0, 10))

        self.update_password_button = ctk.CTkButton(self.sidebar_frame, text="Update Password", command=self.prepare_update, **button_params)
        self.update_password_button.grid(row=2, column=0, padx=10, pady=10)

        self.delete_password_button = ctk.CTkButton(self.sidebar_frame, text="Delete Password", command=self.delete_selected_password, **button_params)
        self.delete_password_button.grid(row=3, column=0, padx=10, pady=10)

        self.delete_all_button = ctk.CTkButton(self.sidebar_frame, text="Delete All Passwords", command=self.delete_all_passwords, **button_params)
        self.delete_all_button.grid(row=4, column=0, padx=10, pady=10)

        self.appearance_mode_label = ctk.CTkLabel(self.sidebar_frame, text="Appearance Mode:", anchor="w")
        self.appearance_mode_label.grid(row=5, column=0, padx=20, pady=(30, 0))
        self.appearance_mode_menu = ctk.CTkOptionMenu(self.sidebar_frame, values=["Light", "Dark", "System"],
                                                      command=self.change_appearance_mode_event, width=180)
        self.appearance_mode_menu.grid(row=6, column=0, padx=10, pady=10)

        # Logout button at the bottom
        self.logout_button = ctk.CTkButton(self.sidebar_frame, text="Log Out", command=self.logout, width=180, fg_color="#d32f2f", hover_color="#b71c1c")
        self.logout_button.grid(row=8, column=0, padx=10, pady=20, sticky="s")

        # Main content area
        self.main_frame = ctk.CTkFrame(self, fg_color="#2b2b2b")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(4, weight=1)

        # Password entry section
        self.entry_frame = ctk.CTkFrame(self.main_frame, fg_color="#3a3a3a")
        self.entry_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        self.entry_frame.grid_columnconfigure(1, weight=1)

        labels = ["Website:", "Email/vaultname:", "Password:"]
        self.entries = {}
        for i, label in enumerate(labels):
            ctk.CTkLabel(self.entry_frame, text=label).grid(row=i, column=0, padx=10, pady=5, sticky="e")
            entry = ctk.CTkEntry(self.entry_frame, width=300)
            entry.grid(row=i, column=1, padx=10, pady=5, sticky="ew")
            self.entries[label.lower().replace(":", "")] = entry

        self.entries["email/vaultname"].insert(0, self.vault_email)
        self.entries["password"].configure(show="•")
        self.entries["password"].bind("<KeyRelease>", self.evaluate_password_strength_event)

        self.show_password_button = ctk.CTkButton(self.entry_frame, text="👁", width=30, command=self.toggle_password_visibility)
        self.show_password_button.grid(row=2, column=2, padx=(5, 10), pady=5)

        # Password generation section with horizontal checkboxes
        self.generation_frame = ctk.CTkFrame(self.main_frame, fg_color="#3a3a3a")
        self.generation_frame.grid(row=1, column=0, padx=10, pady=10, sticky="ew")
        self.generation_frame.grid_columnconfigure(1, weight=1)

        self.length_label = ctk.CTkLabel(self.generation_frame, text="Password Length:")
        self.length_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.length_scale = ctk.CTkSlider(self.generation_frame, from_=8, to=50, number_of_steps=42, width=300)
        self.length_scale.grid(row=0, column=1, padx=10, pady=5, sticky="ew")
        self.length_value = ctk.CTkLabel(self.generation_frame, text="29")
        self.length_value.grid(row=0, column=2, padx=10, pady=5)

        self.length_scale.configure(command=lambda value: self.length_value.configure(text=f"{int(value)}"))

        # Checkbox options in a single horizontal line
        options = ["Uppercase", "Lowercase", "Numbers", "Symbols", "Exclude Similar", "Exclude Ambiguous"]
        self.checkboxes = {}
        checkbox_frame = ctk.CTkFrame(self.generation_frame, fg_color="transparent")
        checkbox_frame.grid(row=1, column=0, columnspan=3, pady=10, sticky="ew")
        checkbox_frame.grid_columnconfigure((0, 1, 2, 3, 4, 5), weight=1)

        for i, option in enumerate(options):
            var = ctk.BooleanVar(value=True if i < 4 else False)
            checkbox = ctk.CTkCheckBox(checkbox_frame, text=option, variable=var)
            checkbox.grid(row=0, column=i, padx=5, pady=5)
            self.checkboxes[option.lower()] = var

        # Encryption and strength section
        self.encryption_frame = ctk.CTkFrame(self.main_frame, fg_color="#3a3a3a")
        self.encryption_frame.grid(row=2, column=0, padx=10, pady=10, sticky="ew")
        self.encryption_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(self.encryption_frame, text="Encryption Method:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.encryption_menu = ctk.CTkOptionMenu(self.encryption_frame, values=["Fernet", "AES", "Triple DES"], variable=self.encryption_method)
        self.encryption_menu.grid(row=0, column=1, padx=10, pady=5, sticky="w")

        self.strength_label = ctk.CTkLabel(self.encryption_frame, text="Strength: ")
        self.strength_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.strength_meter = ctk.CTkProgressBar(self.encryption_frame, width=300)
        self.strength_meter.grid(row=1, column=1, padx=10, pady=5, sticky="ew")
        self.strength_meter.set(0)

        # Buttons
        self.button_frame = ctk.CTkFrame(self.main_frame, fg_color="#2b2b2b")
        self.button_frame.grid(row=3, column=0, padx=10, pady=10, sticky="ew")
        self.button_frame.grid_columnconfigure((0, 1), weight=1)

        self.generate_button = ctk.CTkButton(self.button_frame, text="Generate Password", command=self.generate_password, fg_color="#4caf50", hover_color="#45a049")
        self.generate_button.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        self.store_button = ctk.CTkButton(self.button_frame, text="Store Password", command=self.save, fg_color="#2196f3", hover_color="#1e88e5")
        self.store_button.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        # Password table
        self.table_frame = ctk.CTkFrame(self.main_frame, fg_color="#3a3a3a")
        self.table_frame.grid(row=4, column=0, padx=10, pady=10, sticky="nsew")
        self.table_frame.grid_rowconfigure(1, weight=1)
        self.table_frame.grid_columnconfigure(0, weight=1)

        # Search bar
        self.search_entry = ctk.CTkEntry(self.table_frame, placeholder_text="Search by website or email")
        self.search_entry.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="ew")
        self.search_button = ctk.CTkButton(self.table_frame, text="Search", command=self.search_passwords, width=100)
        self.search_button.grid(row=0, column=1, padx=10, pady=(10, 5), sticky="e")

        # Treeview
        self.tree = ttk.Treeview(self.table_frame, columns=("Website", "Email", "Password", "Encryption Type", "Strength"), show="headings", selectmode="browse")
        self.tree.grid(row=1, column=0, columnspan=2, padx=10, pady=(5, 10), sticky="nsew")

        for col in self.tree["columns"]:
            self.tree.heading(col, text=col, command=lambda _col=col: self.treeview_sort_column(self.tree, _col, False))
            self.tree.column(col, anchor="center", width=100)

        # Scrollbar for Treeview
        self.scrollbar = ttk.Scrollbar(self.table_frame, orient="vertical", command=self.tree.yview)
        self.scrollbar.grid(row=1, column=2, pady=(5, 10), sticky="ns")
        self.tree.configure(yscrollcommand=self.scrollbar.set)

        # Status bar
        self.status_bar = ctk.CTkLabel(self, text="Ready", anchor="w", fg_color="#1a1a1a", corner_radius=0)
        self.status_bar.grid(row=1, column=1, sticky="ew", padx=20, pady=(0, 10))

        self.appearance_mode_menu.set("Dark")
        self.update_password_summary()

    def toggle_password_visibility(self):
        current_state = self.entries["password"].cget("show")
        new_state = "" if current_state == "•" else "•"
        self.entries["password"].configure(show=new_state)

    def save(self):
        vault = self.vaultname
        website = self.entries["website"].get()
        email = self.entries["email/vaultname"].get()
        password = self.entries["password"].get()

        print(f"Saving password for vault: {vault}, website: {website}, email: {email}")

        if len(website) == 0 or len(password) == 0:
            tkinter.messagebox.showerror("Error", "Please fill out all fields")
            print("Save failed: Please fill out all fields")
        else:
            is_ok = tkinter.messagebox.askokcancel(title=website, message=f"These are the details entered: \nEmail: {email} "
                                                                         f"\nPassword: {password} \nIs it ok to save?")
            if is_ok:
                try:
                    conn = sqlite3.connect(DATABASE_NAME)
                    cursor = conn.cursor()
                    cursor.execute("SELECT id FROM vaults WHERE name = ?", (vault,))
                    vault_result = cursor.fetchone()
                    if vault_result is None:
                        raise ValueError(f"No vault found with name {vault}")
                    vault_id = vault_result[0]
                    save_password(vault_id, website, email, password, self.encryption_method.get(), self.fernet_key, self.aes_key, self.des3_key)
                    self.entries["website"].delete(0, ctk.END)
                    self.entries["password"].delete(0, ctk.END)
                    tkinter.messagebox.showinfo("Success", "Password stored successfully")
                    self.update_password_summary()
                    self.view_passwords()  # Refresh the password view
                except sqlite3.Error as e:
                    print(f"SQL Error: {e}")
                    tkinter.messagebox.showerror("Database Error", f"An error occurred while saving the password: {e}")
                except ValueError as ve:
                    print(f"Value Error: {ve}")
                    tkinter.messagebox.showerror("vault Error", str(ve))
                except Exception as e:
                    print(f"Error saving password: {e}")
                    tkinter.messagebox.showerror("Error", f"An unexpected error occurred: {e}")

    def view_passwords(self):
        self.tree.delete(*self.tree.get_children())
        vault = self.vaultname

        print(f"Viewing passwords for vault: {vault}")

        try:
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM vaults WHERE name = ?", (vault,))
            vault_result = cursor.fetchone()
            if vault_result is None:
                raise ValueError(f"No vault found with name {vault}")
            vault_id = vault_result[0]

            passwords = load_passwords(vault_id, self.fernet_key, self.aes_key, self.des3_key)

            print(f"Retrieved {len(passwords)} passwords for vault {vault}")
            for website, email, password, password_id, encryption_type, password_strength in passwords:
                print(f"Password: Website: {website}, Email: {email}, Password: {password}, Encryption Type: {encryption_type}, Strength: {password_strength}")
                self.tree.insert("", "end", values=(website, email, password, encryption_type, password_strength), tags=(password_id,))

            conn.close()
            print("Passwords loaded successfully")
        except sqlite3.Error as e:
            print(f"SQL Error: {e}")
            tkinter.messagebox.showerror("Database Error", f"An error occurred while retrieving passwords: {e}")
        except ValueError as ve:
            print(f"Value Error: {ve}")
            tkinter.messagebox.showerror("vault Error", str(ve))
        except Exception as e:
            print(f"Unexpected error viewing passwords: {e}")
            tkinter.messagebox.showerror("Error", f"An unexpected error occurred: {e}")

    def update_password_summary(self):
        vault = self.vaultname
        try:
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM vaults WHERE name = ?", (vault,))
            vault_result = cursor.fetchone()
            if vault_result is None:
                raise ValueError(f"No vault found with name {vault}")
            vault_id = vault_result[0]

            cursor.execute("SELECT COUNT(*), MAX(id) FROM passwords WHERE vault_id = ?", (vault_id,))
            total_passwords, last_password_id = cursor.fetchone()
            self.status_bar.configure(text=f"Total Passwords: {total_passwords}")

            if last_password_id:
                cursor.execute("SELECT website FROM passwords WHERE id = ?", (last_password_id,))
                last_added_website = cursor.fetchone()[0]
                last_added_website = decrypt_string_fernet(last_added_website, self.fernet_key)
                self.status_bar.configure(text=f"Total Passwords: {total_passwords} | Last Added: {last_added_website}")
            else:
                self.status_bar.configure(text=f"Total Passwords: {total_passwords} | Last Added: None")

            conn.close()
        except sqlite3.Error as e:
            print(f"SQL Error in update_password_summary: {e}")
        except Exception as e:
            print(f"Error in update_password_summary: {e}")

    def search_passwords(self):
        search_term = self.search_entry.get().lower()
        if not search_term:
            self.view_passwords()  # If search term is empty, show all passwords
            return

        self.tree.delete(*self.tree.get_children())
        vault = self.vaultname

        try:
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM vaults WHERE name = ?", (vault,))
            vault_result = cursor.fetchone()
            if vault_result is None:
                raise ValueError(f"No vault found with name {vault}")
            vault_id = vault_result[0]

            cursor.execute("SELECT id, website, email, password, encryption_type, password_strength FROM passwords WHERE vault_id = ?", (vault_id,))
            rows = cursor.fetchall()

            filtered_passwords = []

            for row in rows:
                password_id, encrypted_website, encrypted_email, encrypted_password, encryption_type, password_strength = row

                decrypted_website = ''
                decrypted_email = ''

                if encryption_type == "Fernet":
                    decrypted_website = decrypt_string_fernet(encrypted_website, self.fernet_key).lower()
                    decrypted_email = decrypt_string_fernet(encrypted_email, self.fernet_key).lower()
                elif encryption_type == "AES":
                    decrypted_website = decrypt_string_aes(encrypted_website, self.aes_key).lower()
                    decrypted_email = decrypt_string_aes(encrypted_email, self.aes_key).lower()
                elif encryption_type == "3DES" or encryption_type == "Triple DES":
                    decrypted_website = decrypt_string_3des(encrypted_website, self.des3_key).lower()
                    decrypted_email = decrypt_string_3des(encrypted_email, self.des3_key).lower()

                if search_term in decrypted_website or search_term in decrypted_email:
                    decrypted_password = decrypt_string_fernet(encrypted_password, self.fernet_key) if encryption_type == "Fernet" else \
                                        decrypt_string_aes(encrypted_password, self.aes_key) if encryption_type == "AES" else \
                                        decrypt_string_3des(encrypted_password, self.des3_key)
                    filtered_passwords.append((decrypted_website, decrypted_email, decrypted_password, encryption_type, password_strength, password_id))

            for website, email, password, encryption_type, password_strength, password_id in filtered_passwords:
                self.tree.insert("", "end", values=(website, email, password, encryption_type, password_strength), tags=(password_id,))

            print("Passwords search completed successfully")
        except Exception as e:
            print(f"Error searching passwords: {e}")
            tkinter.messagebox.showerror("Error", f"An error occurred while searching passwords: {e}")


    def delete_selected_password(self):
        selected_item = self.tree.selection()[0]
        password_id = self.tree.item(selected_item)['tags'][0]
        print(f"Deleting password with ID: {password_id}")
        delete_password(password_id)
        self.view_passwords()
        self.update_password_summary()

    def delete_all_passwords(self):
        vault = self.vaultname
        print(f"Deleting all passwords for vault: {vault}")
        try:
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM vaults WHERE name = ?", (vault,))
            vault_result = cursor.fetchone()
            if vault_result is None:
                raise ValueError(f"No vault found with name {vault}")
            vault_id = vault_result[0]
            delete_all_passwords(vault_id)
            self.view_passwords()
            self.update_password_summary()
            tkinter.messagebox.showinfo("Success", "All passwords deleted successfully")
            print("All passwords deleted successfully")
        except sqlite3.Error as e:
            print(f"SQL Error: {e}")
            tkinter.messagebox.showerror("Database Error", f"An error occurred while deleting all passwords: {e}")
        except ValueError as ve:
            print(f"Value Error: {ve}")
            tkinter.messagebox.showerror("vault Error", str(ve))
        except Exception as e:
            print(f"Error deleting all passwords: {e}")

    def prepare_update(self):
        try:
            selected_item = self.tree.selection()[0]
            password_id = self.tree.item(selected_item)['tags'][0]
            print(f"Preparing to update password with ID: {password_id}")
            
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT website, email, password, encryption_type FROM passwords WHERE id = ?", (password_id,))
            encrypted_website, encrypted_email, encrypted_password, encryption_type = cursor.fetchone()
            conn.close()

            if encryption_type == "Fernet":
                decrypted_website = decrypt_string_fernet(encrypted_website, self.fernet_key)
                decrypted_email = decrypt_string_fernet(encrypted_email, self.fernet_key)
                decrypted_password = decrypt_string_fernet(encrypted_password, self.fernet_key)
            elif encryption_type == "AES":
                decrypted_website = decrypt_string_aes(encrypted_website, self.aes_key)
                decrypted_email = decrypt_string_aes(encrypted_email, self.aes_key)
                decrypted_password = decrypt_string_aes(encrypted_password, self.aes_key)
            elif encryption_type == "3DES" or encryption_type == "Triple DES":
                decrypted_website = decrypt_string_3des(encrypted_website, self.des3_key)
                decrypted_email = decrypt_string_3des(encrypted_email, self.des3_key)
                decrypted_password = decrypt_string_3des(encrypted_password, self.des3_key)
            else:
                raise ValueError(f"Unsupported encryption type: {encryption_type}")

            self.entries["website"].delete(0, ctk.END)
            self.entries["website"].insert(0, decrypted_website)
            self.entries["email/vaultname"].delete(0, ctk.END)
            self.entries["email/vaultname"].insert(0, decrypted_email)
            self.entries["password"].delete(0, ctk.END)
            self.entries["password"].insert(0, decrypted_password)
            self.store_button.configure(text="Update Password", command=lambda: self.update_password(password_id))
        except IndexError:
            tkinter.messagebox.showinfo("Selection Error", "Please select a password to update.")
        except sqlite3.Error as e:
            print(f"SQL Error: {e}")
            tkinter.messagebox.showinfo(title="SQL Error", message=f"SQL Error: {e}")
        except Exception as e:
            print(f"Error preparing to update password: {e}")
            tkinter.messagebox.showinfo(title="Error", message=f"Error preparing to update password: {e}")


    def update_password(self, password_id):
        vault = self.vaultname
        website = self.entries["website"].get()
        email = self.entries["email/vaultname"].get()
        new_password = self.entries["password"].get()

        print(f"Updating password with ID: {password_id} for vault: {vault}, website: {website}")

        if len(website) == 0 or len(new_password) == 0:
            tkinter.messagebox.showerror("Error", "Please fill out all fields")
            print("Update failed: Please fill out all fields")
        else:
            update_password(password_id, website, email, new_password, self.encryption_method.get(), self.fernet_key, self.aes_key, self.des3_key)
            tkinter.messagebox.showinfo("Success", "Password updated successfully")
            self.store_button.configure(text="Store Password", command=self.save)
            self.view_passwords()
            self.update_password_summary()

    def logout(self):
        self.destroy()  # Destroy the current window
        from login import LoginWindow
        login_app = LoginWindow()
        login_app.mainloop()

    def change_appearance_mode_event(self, new_appearance_mode: str):
        ctk.set_appearance_mode(new_appearance_mode)
        
        # Update colors based on the new appearance mode
        if new_appearance_mode == "Light":
            bg_color = "#f0f0f0"
            fg_color = "#333333"
        else:  # Dark mode
            bg_color = "#1a1a1a"
            fg_color = "#ffffff"
        
        # Update main window color
        self.configure(fg_color=bg_color)
        
        # Update sidebar color
        self.sidebar_frame.configure(fg_color="#d9d9d9" if new_appearance_mode == "Light" else "#2b2b2b")
        
        # Update main frame color
        self.main_frame.configure(fg_color="#e6e6e6" if new_appearance_mode == "Light" else "#2b2b2b")
        
        # Update entry frame color
        self.entry_frame.configure(fg_color="#d9d9d9" if new_appearance_mode == "Light" else "#3a3a3a")
        
        # Update generation frame color
        self.generation_frame.configure(fg_color="#d9d9d9" if new_appearance_mode == "Light" else "#3a3a3a")
        
        # Update encryption frame color
        self.encryption_frame.configure(fg_color="#d9d9d9" if new_appearance_mode == "Light" else "#3a3a3a")
        
        # Update button frame color
        self.button_frame.configure(fg_color="#e6e6e6" if new_appearance_mode == "Light" else "#2b2b2b")
        
        # Update table frame color
        self.table_frame.configure(fg_color="#d9d9d9" if new_appearance_mode == "Light" else "#3a3a3a")
        
        # Update status bar color
        self.status_bar.configure(fg_color=bg_color, text_color=fg_color)
        
        # Update treeview colors
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background=bg_color, foreground=fg_color, fieldbackground=bg_color)
        style.map("Treeview", background=[('selected', '#4a6984')])
        
    def evaluate_password_strength_event(self, event=None):
        password = self.entries["password"].get()
        strength = evaluate_password_strength(password)
        strength_values = {"Very Weak": 0.2, "Weak": 0.4, "Medium": 0.6, "Strong": 0.8, "Very Strong": 1.0}
        self.strength_label.configure(text=f"Strength: {strength}")
        self.strength_meter.set(strength_values.get(strength, 0))
        
        # Set color based on strength
        if strength == "Very Weak":
            self.strength_meter.configure(progress_color="#ff0000")  # Red
        elif strength == "Weak":
            self.strength_meter.configure(progress_color="#ff8c00")  # Dark Orange
        elif strength == "Medium":
            self.strength_meter.configure(progress_color="#ffd700")  # Gold
        elif strength == "Strong":
            self.strength_meter.configure(progress_color="#32cd32")  # Lime Green
        elif strength == "Very Strong":
            self.strength_meter.configure(progress_color="#008000")  # Green
        
        print(f"Password strength: {strength}")

    def generate_password(self):
        letters_uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        letters_lowercase = 'abcdefghijklmnopqrstuvwxyz'
        numbers = '0123456789'
        symbols = '!#$%&()*+'
        similar_chars = 'iIlLoO0'
        ambiguous_chars = '{}[]()/\\\'"`~,;:.<>'

        all_characters = ''
        if self.checkboxes["uppercase"].get():
            all_characters += letters_uppercase
        if self.checkboxes["lowercase"].get():
            all_characters += letters_lowercase
        if self.checkboxes["numbers"].get():
            all_characters += numbers
        if self.checkboxes["symbols"].get():
            all_characters += symbols

        if not all_characters:
            tkinter.messagebox.showerror("Error", "Please select at least one character type")
            return

        if self.checkboxes["exclude similar"].get():
            all_characters = ''.join(c for c in all_characters if c not in similar_chars)
        if self.checkboxes["exclude ambiguous"].get():
            all_characters = ''.join(c for c in all_characters if c not in ambiguous_chars)

        password_length = int(self.length_scale.get())
        password = ''.join(choice(all_characters) for _ in range(password_length))

        self.entries["password"].delete(0, ctk.END)
        self.entries["password"].insert(0, password)
        pyperclip.copy(password)
        tkinter.messagebox.showinfo("Info", "Password copied to clipboard")
        self.evaluate_password_strength_event()  # Evaluate the generated password strength
        print(f"Generated password: {password}")

if __name__ == "__main__":
    app = LoginWindow()
    app.mainloop()
