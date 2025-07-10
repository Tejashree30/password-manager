import random
import string
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk

# Utility function to generate a password
def generate_password(length, use_uppercase, use_lowercase, use_digits, use_symbols):
    if not (use_uppercase or use_lowercase or use_digits or use_symbols):
        raise ValueError("At least one character set must be selected.")

    characters = ''
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_lowercase:
        characters += string.ascii_lowercase
    if use_digits:
        characters += string.digits
    if use_symbols:
        characters += string.punctuation

    if length < 4:
        raise ValueError("Password length must be at least 4.")

    password = ''.join(random.choice(characters) for _ in range(length))
    return password

# Function to estimate password strength
def estimate_strength(password):
    length = len(password)
    categories = sum([
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(c in string.punctuation for c in password)
    ])
    
    if length >= 12 and categories >= 3:
        return "Strong"
    elif length >= 8 and categories >= 2:
        return "Medium"
    else:
        return "Weak"

# Main GUI Application
class PasswordGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Password Generator")
        self.root.geometry("500x400")
        self.root.resizable(False, False)

        # UI elements
        self.length_label = tk.Label(root, text="Password Length:")
        self.length_label.pack(pady=5)
        self.length_entry = tk.Entry(root, width=10)
        self.length_entry.pack()

        self.upper_var = tk.BooleanVar(value=True)
        self.lower_var = tk.BooleanVar(value=True)
        self.digit_var = tk.BooleanVar(value=True)
        self.symbol_var = tk.BooleanVar(value=True)

        self.checkbox_frame = tk.Frame(root)
        self.checkbox_frame.pack(pady=5)

        tk.Checkbutton(self.checkbox_frame, text="Uppercase", variable=self.upper_var).grid(row=0, column=0)
        tk.Checkbutton(self.checkbox_frame, text="Lowercase", variable=self.lower_var).grid(row=0, column=1)
        tk.Checkbutton(self.checkbox_frame, text="Digits", variable=self.digit_var).grid(row=1, column=0)
        tk.Checkbutton(self.checkbox_frame, text="Symbols", variable=self.symbol_var).grid(row=1, column=1)

        self.generate_button = tk.Button(root, text="Generate Password", command=self.generate)
        self.generate_button.pack(pady=10)

        self.result_label = tk.Label(root, text="Generated Password:", font=("Helvetica", 12))
        self.result_label.pack(pady=5)

        self.password_display = tk.Entry(root, width=40, font=("Helvetica", 14), justify="center")
        self.password_display.pack(pady=5)

        self.copy_button = tk.Button(root, text="Copy to Clipboard", command=self.copy_to_clipboard)
        self.copy_button.pack(pady=5)

        self.strength_label = tk.Label(root, text="", font=("Helvetica", 12, "bold"))
        self.strength_label.pack(pady=5)

    def generate(self):
        try:
            length = int(self.length_entry.get())
            password = generate_password(
                length,
                self.upper_var.get(),
                self.lower_var.get(),
                self.digit_var.get(),
                self.symbol_var.get()
            )
            self.password_display.delete(0, tk.END)
            self.password_display.insert(0, password)

            strength = estimate_strength(password)
            self.strength_label.config(text=f"Strength: {strength}", fg=self.get_strength_color(strength))
        except ValueError as e:
            messagebox.showerror("Input Error", str(e))

    def copy_to_clipboard(self):
        password = self.password_display.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")
        else:
            messagebox.showwarning("No Password", "Please generate a password first.")

    def get_strength_color(self, strength):
        return {
            "Strong": "green",
            "Medium": "orange",
            "Weak": "red"
        }.get(strength, "black")

# Run the app
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()
