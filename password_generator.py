import tkinter as tk
from tkinter import messagebox, filedialog
import random
import string

# Function to generate passwords based on user input
def generate_passwords():
    try:
        num_passwords = int(entry_num_passwords.get())
        length = int(entry_length.get())
        if num_passwords <= 0 or length < 8:
            raise ValueError
    except ValueError:
        messagebox.showerror("Invalid Input", "Enter valid numbers (min length 8.")
        return

    # List to store possible character sets
    char_sets = []
    if var_uppercase.get(): char_sets.append(string.ascii_uppercase)
    if var_lowercase.get(): char_sets.append(string.ascii_lowercase)
    if var_numbers.get(): char_sets.append(string.digits)
    if var_special.get(): char_sets.append(string.punctuation)

    # Custom special characters if entered by user
    custom_special = entry_custom_special.get()
    if custom_special:
        char_sets.append(custom_special)

    # Ensure there is at least one character set
    if not char_sets:
        messagebox.showerror("Error", "Select at least one character type.")
        return

    # Password generation logic
    passwords = []
    for _ in range(num_passwords):
        password = [random.choice(cs) for cs in char_sets]  
        password += random.choices(''.join(char_sets), k=length - len(password))
        random.shuffle(password)
        passwords.append(''.join(password))

    # Display passwords in the Text widget
    text_output.delete(1.0, tk.END)
    text_output.insert(tk.END, "\n".join(passwords))

# Function to copy passwords to clipboard
def copy_to_clipboard():
    root.clipboard_clear()
    root.clipboard_append(text_output.get(1.0, tk.END).strip())
    root.update()
    messagebox.showinfo("Copied", "Passwords copied to clipboard!")

# Function to save passwords to a file
def save_to_file():
    passwords = text_output.get(1.0, tk.END).strip()
    if not passwords:
        messagebox.showwarning("No Passwords", "No passwords to save.")
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, "w") as file:
            file.write(passwords)
        messagebox.showinfo("Saved", f"Passwords saved to {file_path}")

# Function to clear all input fields and output
def clear_all():
    entry_num_passwords.delete(0, tk.END)
    entry_length.delete(0, tk.END)
    entry_custom_special.delete(0, tk.END)
    text_output.delete(1.0, tk.END)
    var_uppercase.set(True)
    var_lowercase.set(True)
    var_numbers.set(True)
    var_special.set(True)

# Setting up the main window
root = tk.Tk()
root.title("Password Generator")
root.geometry("500x650")

# Input fields and labels
tk.Label(root, text="Number of Passwords:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
entry_num_passwords = tk.Entry(root)
entry_num_passwords.grid(row=0, column=1, padx=10, pady=5)

tk.Label(root, text="Password Length (min 8):").grid(row=1, column=0, padx=10, pady=5, sticky="w")
entry_length = tk.Entry(root)
entry_length.grid(row=1, column=1, padx=10, pady=5)

# Checkbuttons for character sets
var_uppercase = tk.BooleanVar(value=True)
var_lowercase = tk.BooleanVar(value=True)
var_numbers = tk.BooleanVar(value=True)
var_special = tk.BooleanVar(value=True)

tk.Checkbutton(root, text="Uppercase", variable=var_uppercase).grid(row=2, column=0, sticky="w", padx=10)
tk.Checkbutton(root, text="Lowercase", variable=var_lowercase).grid(row=3, column=0, sticky="w", padx=10)
tk.Checkbutton(root, text="Numbers", variable=var_numbers).grid(row=4, column=0, sticky="w", padx=10)
tk.Checkbutton(root, text="Special Characters", variable=var_special).grid(row=5, column=0, sticky="w", padx=10)

# Custom special characters input
tk.Label(root, text="Custom Special Characters:").grid(row=6, column=0, padx=10, pady=5, sticky="w")
entry_custom_special = tk.Entry(root)
entry_custom_special.grid(row=6, column=1, padx=10, pady=5)

# Buttons for generating, copying, saving, and clearing
tk.Button(root, text="Generate", command=generate_passwords).grid(row=7, column=0, columnspan=2, pady=10)
tk.Button(root, text="Copy to Clipboard", command=copy_to_clipboard).grid(row=8, column=0, columnspan=2, pady=5)
tk.Button(root, text="Save to File", command=save_to_file).grid(row=9, column=0, columnspan=2, pady=5)
tk.Button(root, text="Clear All", command=clear_all).grid(row=10, column=0, columnspan=2, pady=5)

# Text widget for displaying passwords
text_output = tk.Text(root, height=15, width=50)
text_output.grid(row=11, column=0, columnspan=2, pady=10)

# Footer labels
tk.Label(root, text="Password Strength:").grid(row=12, column=0, padx=10, pady=5, sticky="w")
tk.Label(root, text="Generated Passwords will appear here").grid(row=12, column=1, padx=10, pady=5)

# Starting the GUI event loop
root.mainloop()
