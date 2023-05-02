from tkinter import *
import tkinter as tk
from tkinter import ttk
import caesar
import aes
import vigenere
import des
import blowfish
# Create the main window
root = tk.Tk()
root.geometry("1000x600")

# Create the menu bar on the left
menu_frame = tk.Frame(root, bg="light grey", width=200, height=600)
menu_frame.pack(side=tk.LEFT, fill=tk.Y)

# Create a label for each screen option in the menu bar

aes_label = tk.Label(menu_frame, bg="light grey",
                     text="AES", font=("Helvetica", 14))
aes_label.pack(pady=5, padx=50)

des_label = tk.Label(menu_frame, bg="light grey",
                     text="DES", font=("Helvetica", 14))
des_label.pack(pady=5, padx=50)

blowfish_label = tk.Label(menu_frame, bg="light grey",
                          text="Blowfish", font=("Helvetica", 14))
blowfish_label.pack(pady=5, padx=50)

caesar_label = tk.Label(menu_frame, bg="light grey",
                        text="Caesar Cipher", font=("Helvetica", 14))
caesar_label.pack(pady=5, padx=50)

vigenere_label = tk.Label(menu_frame, bg="light grey",
                          text="Vigenere Cipher", font=("Helvetica", 14))
vigenere_label.pack(pady=5, padx=50)


# Create the text area on the right
text_area = tk.Frame(root, bg="white", width=800, height=600)
text_area.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)


def desScreen():
    input_field = tk.Entry(text_area, font=("Helvetica", 14))
    input_field.pack(pady=20)
    calculate_button = tk.Button(text_area, text="Calculate", font=("Helvetica", 14),
                                 command=lambda: calculate(int(input_field.get()) / 2))
    calculate_button.pack(pady=20)
    text_area.insert(tk.END, "Enter a number to halve it:")


# Create a function to switch screens based on which label is clicked


def switch_screen(screen):
    for widget in text_area.winfo_children():
        widget.destroy()

    if screen == "aes":
        aes.aesScreen(text_area)

    elif screen == "des":
        des.desScreen(text_area)
    elif screen == "blowfish":
        blowfish.blowfishScreen(text_area)
    elif screen == "rsa":
        pass
    elif screen == "dsa":
        pass
    elif screen == "diffieHelman":
        pass
    elif screen == "caesar":
        caesar.caesarScreen(text_area)
    elif screen == "vigenere":
        vigenere.vigenereScreen(text_area)


# Define a function to calculate and display the result
def calculate(result):
    text_area.delete("1.0", tk.END)  # Clear the text area
    text_area.insert(tk.END, result)


# Bind each label to the switch_screen function
aes_label.bind("<Button-1>", lambda event: switch_screen("aes"))
des_label.bind("<Button-1>", lambda event: switch_screen("des"))
blowfish_label.bind("<Button-1>", lambda event: switch_screen("blowfish"))
caesar_label.bind("<Button-1>", lambda event: switch_screen("caesar"))
vigenere_label.bind("<Button-1>", lambda event: switch_screen("vigenere"))
aes.aesScreen(text_area)
# Start the main loop
root.mainloop()
