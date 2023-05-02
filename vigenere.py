from tkinter import *
import tkinter as tk
from tkinter import ttk


def vigenereScreen(text_area):
    def vigenereEncrypt(input, key):
        outputEn_field.delete("1.0", "end")
        input = input.upper()
        key = key.upper()
        encrypted_text = ""
        key_index = 0
        for char in input:
            if char.isalpha():
                shift = ord(key[key_index]) - ord('A') + 1
                if char.islower():
                    encrypted_char = chr(
                        (ord(char) - ord('A') + shift) % 26 + ord('a'))
                else:
                    encrypted_char = chr(
                        (ord(char) - ord('A') + shift) % 26 + ord('A'))
                key_index = (key_index + 1) % len(key)
            else:
                encrypted_char = char
            encrypted_text += encrypted_char
        outputEn_field.insert(tk.END, encrypted_text)

    def vigenereDecrypt(input, key):
        outputDe_field.delete("1.0", "end")
        decrypted_text = ""
        input = input.upper()
        key = key.upper()
        key_index = 0
        for char in input:
            if char.isalpha():
                shift = ord(key[key_index]) - ord('A') + 1
                if char.islower():
                    decrypted_char = chr(
                        (ord(char) - ord('a') - shift) % 26 + ord('a'))
                else:
                    decrypted_char = chr(
                        (ord(char) - ord('A') - shift) % 26 + ord('A'))
                key_index = (key_index + 1) % len(key)
            else:
                decrypted_char = char
            decrypted_text += decrypted_char
        outputDe_field.insert(tk.END, decrypted_text)

    vigenereHeader_label = tk.Label(
        text_area, bg="white", text="Vigenere Cipher", font=("Helvetica", 24))
    vigenereHeader_label.pack(pady=5, padx=50, anchor=tk.CENTER)
    """ Text to encrypt """
    toEncrypt_label = tk.Label(
        text_area, bg="white", text="Enter Text To Be Encrypted", font=("Helvetica", 14))
    toEncrypt_label.place(x=10, y=50)
    inputEn_field = tk.Text(text_area, font=(
        "Helvetica", 10), width=47, height=7, relief="solid")
    inputEn_field.place(x=13, y=80)

    # Key
    keyEn_label = tk.Label(
        text_area, bg="white", text="Enter Key", font=("Helvetica", 14))
    keyEn_label.place(x=10, y=210)
    keyEn_field = tk.Text(
        text_area, font=("Helvetica", 10), width=47, height=1, relief="solid")
    keyEn_field.place(x=13, y=240)

    # Encrypt Button
    encrypt_button = tk.Button(
        text_area, text="Encrypt", font=("Helvetica", 14), command=lambda: vigenereEncrypt(inputEn_field.get("1.0", "end").strip(), keyEn_field.get("1.0", "end").strip()))
    encrypt_button.place(x=10, y=390)

    # Vigenere Cipher Encrypted Output
    encryptedOutput_label = tk.Label(
        text_area, bg="white", text="Vigenere Cipher Encrypted Output", font=("Helvetica", 14))
    encryptedOutput_label.place(x=10, y=430)
    outputEn_field = tk.Text(text_area, font=(
        "Helvetica", 10), width=47, height=7, relief="solid")
    outputEn_field.place(x=13, y=460)

    """ Text to decrypt"""
    toDecrypt_label = tk.Label(
        text_area, bg="white", text="Enter Text To Be Decrypted", font=("Helvetica", 14))
    toDecrypt_label.place(x=400, y=50)
    inputDe_field = tk.Text(text_area, font=(
        "Helvetica", 10), width=45, height=7, relief="solid")
    inputDe_field.place(x=403, y=80)

    # Key
    keyDe_label = tk.Label(
        text_area, bg="white", text="Enter Shift Amount", font=("Helvetica", 14))
    keyDe_label.place(x=400, y=210)
    keyDe_field = tk.Text(
        text_area, font=("Helvetica", 10), width=45, height=1, relief="solid")
    keyDe_field.place(x=403, y=240)

    # Decrypt Button
    decrypt_button = tk.Button(
        text_area, text="Decrypt", font=("Helvetica", 14), command=lambda: vigenereDecrypt(inputDe_field.get("1.0", "end").strip(), keyDe_field.get("1.0", "end").strip()))
    decrypt_button.place(x=400, y=390)

    # Vigenere Cipher Decrypted Output
    decryptedOutput_label = tk.Label(
        text_area, bg="white", text="Vigenere Cipher Decrypted Output", font=("Helvetica", 14))
    decryptedOutput_label.place(x=400, y=430)
    outputDe_field = tk.Text(text_area, font=(
        "Helvetica", 10), width=45, height=7, relief="solid")
    outputDe_field.place(x=403, y=460)

    canvas = Canvas(text_area, width=3, height=520, background="white")
    canvas.pack()
