from tkinter import *
import tkinter as tk
from tkinter import ttk
from Crypto.Cipher import Blowfish
import binascii


def blowfishScreen(text_area):
    def blowfishEncrypt(plaintext, mode, iv, key):
        outputEn_field.delete("1.0", "end")
        # Convert plaintext and key to bytes
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        if isinstance(iv, str):
            iv = iv.encode()
        if isinstance(key, str):
            key = key.encode()

        # Create Blowfish cipher object
        if mode == "CBC":
            cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        elif mode == "ECB":
            cipher = Blowfish.new(key, Blowfish.MODE_ECB)
        else:
            raise ValueError(
                "Invalid mode. Please choose either 'CBC' or 'ECB'.")

        # Pad plaintext to multiple of 8 bytes
        # plaintext_padded = plaintext.ljust(
        #    (len(plaintext) // 8 + 1) * 8, b'\x00')
        plaintext_padded = plaintext + b'\x00' * (8 - len(plaintext) % 8)
        # Encrypt the plaintext
        ciphertext = cipher.encrypt(plaintext_padded)

        # Convert ciphertext from bytes to hexadecimal string
        ciphertext_hex = binascii.hexlify(ciphertext).decode()
        outputEn_field.insert(tk.END, ciphertext_hex)

    def blowfishDecrypt(ciphertext_hex, mode, iv, key):
        outputDe_field.delete("1.0", "end")
        # Convert ciphertext and key to bytes
        ciphertext = binascii.unhexlify(ciphertext_hex)
        if isinstance(iv, str):
            iv = iv.encode()
        if isinstance(key, str):
            key = key.encode()

        # Create Blowfish cipher object
        if mode == "CBC":
            cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        elif mode == "ECB":
            cipher = Blowfish.new(key, Blowfish.MODE_ECB)
        else:
            raise ValueError(
                "Invalid mode. Please choose either 'CBC' or 'ECB'.")

        # Decrypt the ciphertext
        plaintext_padded = cipher.decrypt(ciphertext)

        # Remove padding from plaintext
        plaintext = plaintext_padded.rstrip(b'\x00')

        # Convert plaintext from bytes to string
        plaintext = plaintext.decode()

        outputDe_field.insert(tk.END, plaintext)

    blowfishHeader_label = tk.Label(
        text_area, bg="white", text="Blowfish", font=("Helvetica", 24))
    blowfishHeader_label.pack(pady=5, padx=50, anchor=tk.CENTER)
    """ Text to encrypt"""
    toEncrypt_label = tk.Label(
        text_area, bg="white", text="Enter Text To Be Encrypted", font=("Helvetica", 14))
    toEncrypt_label.place(x=10, y=50)
    inputEn_field = tk.Text(text_area, font=(
        "Helvetica", 10), width=47, height=7, relief="solid")
    inputEn_field.place(x=13, y=80)

    # Cipher Mode of Encryption
    modeEn_label = tk.Label(
        text_area, bg="white", text="Select Mode of Encryption", font=("Helvetica", 14))
    modeEn_label.place(x=10, y=200)
    modeEn_combobox = ttk.Combobox(text_area, values=['ECB', 'CBC'])
    modeEn_combobox.place(x=10, y=230)
    modeEn_combobox.current(0)

    # Key size
    ivEn_label = tk.Label(
        text_area, bg="white", text="Enter Initialization Vector", font=("Helvetica", 14))
    ivEn_label.place(x=10, y=260)
    ivEn_field = tk.Text(
        text_area, font=("Helvetica", 10), width=47, height=1, relief="solid")
    ivEn_field.place(x=10, y=290)

    # Secret Key
    secretKeyEn_label = tk.Label(
        text_area, bg="white", text="Enter Secret Key", font=("Helvetica", 14))
    secretKeyEn_label.place(x=10, y=320)
    secretKeyEn_field = tk.Text(
        text_area, font=("Helvetica", 10), width=47, height=1, relief="solid")
    secretKeyEn_field.place(x=10, y=350)

    # Encrypt Button
    encrypt_button = tk.Button(
        text_area, text="Encrypt", font=("Helvetica", 14), command=lambda: blowfishEncrypt(inputEn_field.get("1.0", "end").strip().encode(), modeEn_combobox.get().strip(), ivEn_field.get("1.0", "end").strip().encode(), secretKeyEn_field.get("1.0", "end").strip().encode()))
    encrypt_button.place(x=10, y=390)

    # Blowfish Encrypted Output
    encryptedOutput_label = tk.Label(
        text_area, bg="white", text="Blowfish Encrypted Output", font=("Helvetica", 14))
    encryptedOutput_label.place(x=10, y=430)
    outputEn_field = tk.Text(text_area, font=(
        "Helvetica", 10), width=47, height=7, relief="solid")
    outputEn_field.place(x=13, y=460)

    """ Text to decrypt"""
    toDecrypt_label = tk.Label(
        text_area, bg="white", text="Enter Text To Be Decrypted", font=("Helvetica", 14))
    toDecrypt_label.place(x=400, y=50)
    inputDe_field = tk.Text(text_area, font=(
        "Helvetica", 10), width=47, height=7, relief="solid")
    inputDe_field.place(x=403, y=80)

    # Cipher Mode of Decryption
    modeDe_label = tk.Label(
        text_area, bg="white", text="Select Mode of Decryption", font=("Helvetica", 14))
    modeDe_label.place(x=400, y=200)
    modeDe_combobox = ttk.Combobox(text_area, values=['ECB', 'CBC'])
    modeDe_combobox.place(x=400, y=230)
    modeDe_combobox.current(0)

    # Key size
    ivDe_label = tk.Label(
        text_area, bg="white", text="Enter Initialization Vector", font=("Helvetica", 14))
    ivDe_label.place(x=400, y=260)
    ivDe_field = tk.Text(
        text_area, font=("Helvetica", 10), width=47, height=1, relief="solid")
    ivDe_field.place(x=400, y=290)

    # Secret Key
    secretKeyDe_label = tk.Label(
        text_area, bg="white", text="Enter Secret Key", font=("Helvetica", 14))
    secretKeyDe_label.place(x=400, y=320)
    secretKeyDe_field = tk.Text(
        text_area, font=("Helvetica", 10), width=47, height=1, relief="solid")
    secretKeyDe_field.place(x=400, y=350)

    # Decrypt Button
    decrypt_button = tk.Button(
        text_area, text="Decrypt", font=("Helvetica", 14), command=lambda: blowfishDecrypt(inputDe_field.get("1.0", "end").strip().encode(), modeDe_combobox.get().strip(), ivDe_field.get("1.0", "end").strip().encode(), secretKeyDe_field.get("1.0", "end").strip().encode()))
    decrypt_button.place(x=400, y=390)

    # Blowfish Decrypted Output
    decryptedOutput_label = tk.Label(
        text_area, bg="white", text="Blowfish Decrypted Output", font=("Helvetica", 14))
    decryptedOutput_label.place(x=400, y=430)
    outputDe_field = tk.Text(text_area, font=(
        "Helvetica", 10), width=47, height=7, relief="solid")
    outputDe_field.place(x=403, y=460)

    canvas = Canvas(text_area, width=3, height=520, background="white")
    canvas.pack()
