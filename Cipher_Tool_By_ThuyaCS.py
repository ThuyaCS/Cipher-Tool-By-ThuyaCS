# Made by ThuyaCS

import tkinter as tk
from tkinter import ttk
import ttkbootstrap as ttkb
from PIL import Image, ImageTk

def encrypt_CC(plaintext, shift):
    result = ""
    for char in plaintext:
        if char.isalpha():
            shift_amount = shift % 26
            base = ord('a') if char.islower() else ord('A')
            result += chr((ord(char) - base + shift_amount) % 26 + base)
        else:
            result += char
    return result

def decrypt_CC(ciphertext, shift):
    return encrypt_CC(ciphertext, -shift)

def vigenere_encrypt(plaintext, key):
    plaintext = plaintext.upper()
    key = key.upper()
    
    encrypted_text = ""
    key_index = 0
    
    for char in plaintext:
        if char.isalpha():
            shift = ord(key[key_index]) - ord('A')
            encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            encrypted_text += encrypted_char
            key_index = (key_index + 1) % len(key)
        else:
            encrypted_text += char
    
    return encrypted_text

def vigenere_decrypt(ciphertext, key):
    ciphertext = ciphertext.upper()
    key = key.upper()

    decrypted_text = ""
    key_index = 0

    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_index]) - ord('A')
            decrypted_char = chr((ord(char) - ord('A') - shift + 26) % 26 + ord('A'))
            decrypted_text += decrypted_char
            key_index = (key_index + 1) % len(key)
        else:
            decrypted_text += char
    return decrypted_text

def encrypt_decrypt():
    method = choice.get()
    text = input_text.get("1.0", "end-1c")
    
    if method == "Caesar Cipher":
        shift = int(shift_entry.get())
        if encrypt_decrypt_choice.get() == "Encrypt":
            result = encrypt_CC(text, shift)
        elif encrypt_decrypt_choice.get() == "Decrypt":
            result = decrypt_CC(text, shift)
    
    elif method == "Vigenère Cipher":
        key = key_entry.get()
        if encrypt_decrypt_choice.get() == "Encrypt":
            result = vigenere_encrypt(text, key)
        elif encrypt_decrypt_choice.get() == "Decrypt":
            result = vigenere_decrypt(text, key)
    
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, result)

def update_inputs(*args):
    method = choice.get()
    if method == "Caesar Cipher":
        key_label.grid_remove()
        key_entry.grid_remove()
        shift_label.grid()
        shift_entry.grid()
    elif method == "Vigenère Cipher":
        shift_label.grid_remove()
        shift_entry.grid_remove()
        key_label.grid()
        key_entry.grid()

# Create main window
window = ttkb.Window(themename="darkly")
window.maxsize(636,553)
window.minsize(636,553)
window.geometry("636x553")
window.title("Cipher Tool by ThuyaCS")

# Set window icon
icon = ImageTk.PhotoImage(file='E.png')
window.iconphoto(False, icon)

# Create widgets
title_label = ttk.Label(window, text="Cipher Tool", font=("Inter", 18, "bold"))
title_label.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

title_label = ttk.Label(window, text="By ThuyaCS", font=("Inter", 11, "bold"))
title_label.grid(row=1, column=0, columnspan=2, padx=10, pady=10)

choice_label = ttk.Label(window, text="Choose Method:")
choice_label.grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)

choice = ttk.Combobox(window, values=["Caesar Cipher", "Vigenère Cipher"])
choice.grid(row=2, column=1, padx=10, pady=5)
choice.current(0)
choice.bind("<<ComboboxSelected>>", update_inputs)

input_label = ttk.Label(window, text="Input Text:")
input_label.grid(row=3, column=0, padx=10, pady=5, sticky=tk.W)

input_text = tk.Text(window, height=5, width=50)
input_text.grid(row=3, column=1, padx=10, pady=5)

key_label = ttk.Label(window, text="Key (Vigenère Cipher):")
key_label.grid(row=4, column=0, padx=10, pady=5, sticky=tk.W)

key_entry = ttk.Entry(window, width=52)
key_entry.grid(row=4, column=1, padx=10, pady=5)

shift_label = ttk.Label(window, text="Shift (Caesar Cipher):")
shift_label.grid(row=5, column=0, padx=10, pady=5, sticky=tk.W)

shift_entry = ttk.Entry(window, width=52)
shift_entry.grid(row=5, column=1, padx=10, pady=5)

encrypt_decrypt_choice = tk.StringVar(value="Encrypt")
encrypt_radio = ttk.Radiobutton(window, text="Encrypt", variable=encrypt_decrypt_choice, value="Encrypt")
encrypt_radio.grid(row=6, column=0, padx=10, pady=5)

decrypt_radio = ttk.Radiobutton(window, text="Decrypt", variable=encrypt_decrypt_choice, value="Decrypt")
decrypt_radio.grid(row=6, column=1, padx=10, pady=5)

encrypt_decrypt_button = ttk.Button(window, text="Encrypt/Decrypt", command=encrypt_decrypt)
encrypt_decrypt_button.grid(row=7, column=0, columnspan=2, padx=10, pady=10)

output_label = ttk.Label(window, text="Output Text:")
output_label.grid(row=8, column=0, padx=10, pady=5, sticky=tk.W)

output_text = tk.Text(window, height=5, width=50)
output_text.grid(row=8, column=1, padx=10, pady=5)

# Start with the correct inputs
update_inputs()

# Start the main loop
window.mainloop()
