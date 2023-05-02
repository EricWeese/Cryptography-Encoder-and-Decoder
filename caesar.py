from tkinter import *
import tkinter as tk
from tkinter import ttk


def caesarScreen(text_area):
    def caesarEncrypt(input, shift):
        outputEn_field.delete("1.0", "end")
        encrypted_text = ""
        for char in input:
            if char.isalpha():
                if char.islower():
                    encrypted_char = chr(
                        (ord(char) - ord('a') + shift) % 26 + ord('a'))
                else:
                    encrypted_char = chr(
                        (ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                encrypted_char = char
            encrypted_text += encrypted_char
        encrypted_text = encrypted_text.upper()
        outputEn_field.insert(tk.END, encrypted_text)

    def caesarDecrypt(input, shift):
        outputDe_field.delete("1.0", "end")
        decrypted_text = ""
        for char in input:
            if char.isalpha():
                if char.islower():
                    decrypted_char = chr(
                        (ord(char) - ord('a') - shift) % 26 + ord('a'))
                else:
                    decrypted_char = chr(
                        (ord(char) - ord('A') - shift) % 26 + ord('A'))
            else:
                decrypted_char = char
            decrypted_text += decrypted_char
        outputDe_field.insert(tk.END, decrypted_text)

    caesarHeader_label = tk.Label(
        text_area, bg="white", text="Caesar Cipher", font=("Helvetica", 24))
    caesarHeader_label.pack(pady=5, padx=50, anchor=tk.CENTER)
    """ Text to encrypt """
    toEncrypt_label = tk.Label(
        text_area, bg="white", text="Enter Text To Be Encrypted", font=("Helvetica", 14))
    toEncrypt_label.place(x=10, y=50)
    inputEn_field = tk.Text(text_area, font=(
        "Helvetica", 10), width=47, height=7, relief="solid")
    inputEn_field.place(x=13, y=80)

    # Shift Amount Encryption
    shiftEn_label = tk.Label(
        text_area, bg="white", text="Enter Shift Amount", font=("Helvetica", 14))
    shiftEn_label.place(x=10, y=210)
    shiftEn_field = tk.Text(
        text_area, font=("Helvetica", 10), width=47, height=1, relief="solid")
    shiftEn_field.place(x=13, y=240)

    # Encrypt Button
    encrypt_button = tk.Button(
        text_area, text="Encrypt", font=("Helvetica", 14), command=lambda: caesarEncrypt(inputEn_field.get("1.0", "end").strip(), int(shiftEn_field.get("1.0", "end").strip())))
    encrypt_button.place(x=10, y=390)

    # Caesar Cipher Encrypted Output
    encryptedOutput_label = tk.Label(
        text_area, bg="white", text="Caesar Cipher Encrypted Output", font=("Helvetica", 14))
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

    # Shift Amount
    shiftDe_label = tk.Label(
        text_area, bg="white", text="Enter Shift Amount", font=("Helvetica", 14))
    shiftDe_label.place(x=400, y=210)
    shiftDe_field = tk.Text(
        text_area, font=("Helvetica", 10), width=45, height=1, relief="solid")
    shiftDe_field.place(x=403, y=240)

    # Decrypt Button
    decrypt_button = tk.Button(
        text_area, text="Decrypt", font=("Helvetica", 14), command=lambda: caesarDecrypt(inputDe_field.get("1.0", "end").strip(), int(shiftDe_field.get("1.0", "end").strip())))
    decrypt_button.place(x=400, y=390)

    # Caesar Cipher Decrypted Output
    decryptedOutput_label = tk.Label(
        text_area, bg="white", text="Caesar Cipher Decrypted Output", font=("Helvetica", 14))
    decryptedOutput_label.place(x=400, y=430)
    outputDe_field = tk.Text(text_area, font=(
        "Helvetica", 10), width=45, height=7, relief="solid")
    outputDe_field.place(x=403, y=460)

    canvas = Canvas(text_area, width=3, height=520, background="white")
    canvas.pack()
