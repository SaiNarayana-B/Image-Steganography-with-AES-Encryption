from PIL import Image, ImageTk
from Crypto.Cipher import AES
import base64
import binascii
import tkinter as tk
from tkinter import filedialog
import binascii

class SteganographyApp:
    def __init__(self, master):
        self.master = master
        master.title("Steganography App - By Sai Narayana")

        self.label = tk.Label(master, text="Select an option:")
        self.label.pack()

        self.hide_button = tk.Button(master, text="Hide Message", command=self.hide_message)
        self.hide_button.pack()

        self.retrieve_button = tk.Button(master, text="Retrieve Message", command=self.retrieve_message)
        self.retrieve_button.pack()

    def hide_message(self):
        file_path = filedialog.askopenfilename(title="Select Image to Hide Message")
        text_file_path = filedialog.askopenfilename(title="Select Text File with Message")

        password_window = tk.Toplevel(self.master)
        password_label = tk.Label(password_window, text="Enter your password:")
        password_label.pack()

        password_entry = tk.Entry(password_window, show="*")
        password_entry.pack()

        ok_button = tk.Button(password_window, text="OK", command=lambda: self.process_hide(file_path, text_file_path, password_entry.get(), password_window))
        ok_button.pack()

    def process_hide(self, file_path, text_file_path, password, password_window):
        password_window.destroy()

        cipher = AES.new(password.rjust(16).encode(), AES.MODE_ECB)

        with open(text_file_path, 'r') as file:
            text = file.read()

        encoded = base64.b64encode(cipher.encrypt(text.rjust(32).encode()))

        output_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
        result = hide(file_path, output_path, encoded)
        print(result)

    def retrieve_message(self):
        file_path = filedialog.askopenfilename(title="Select Image to Retrieve Message")

        password_window = tk.Toplevel(self.master)
        password_label = tk.Label(password_window, text="Enter your password:")
        password_label.pack()

        password_entry = tk.Entry(password_window, show="*")
        password_entry.pack()

        ok_button = tk.Button(password_window, text="OK", command=lambda: self.process_retrieve(file_path, password_entry.get(), password_window))
        ok_button.pack()

    def process_retrieve(self, file_path, password, password_window):
        password_window.destroy()

        cipher = AES.new(password.rjust(16).encode(), AES.MODE_ECB)

        decoded = cipher.decrypt(base64.b64decode(retr(file_path)))

        output_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        with open(output_path, 'w') as file:
            file.write(decoded.strip().decode('utf-8'))

        print(f"Decoded message written to {output_path}")

def rgb2hex(r, g, b):
    return '#{:02x}{:02x}{:02x}'.format(r, g, b)

def hex2rgb(hexcode):
    return tuple(int(hexcode[i:i+2], 16) for i in (1, 3, 5))

def str2bin(message):
    binary = bin(int(binascii.hexlify(message.encode()), 16))
    return binary[2:]

def bin2str(binary):
    message = binascii.unhexlify('%x' % (int('0b'+binary, 2)))
    return message.decode('utf-8')

def encode(hexcode, digit):
    if hexcode[-1] in ('0', '1', '2', '3', '4', '5'):
        hexcode = hexcode[:-1] + digit
        return hexcode
    else:
        return None

def decode(hexcode):
    if hexcode[-1] in ('0', '1'):
        return hexcode[-1]
    else:
        return None

def hide(input_filename, output_filename='steg.png', message=''):
    img = Image.open(input_filename)
    binary = str2bin(message.decode('utf-8')) + '1111111111111110'

    img = img.convert('RGBA')

    datas = img.getdata()
    newData = []
    digit = 0

    for item in datas:
        if digit < len(binary):
            newpix = encode(rgb2hex(item[0], item[1], item[2]), binary[digit])
            if newpix is None:
                newData.append(item)
            else:
                r, g, b = hex2rgb(newpix)
                newData.append((r, g, b, 255))
                digit += 1
        else:
            newData.append(item)

    img.putdata(newData)
    img.save(output_filename, "PNG")
    return f"Completed! Image saved as {output_filename}"

def retr(filename):
    img = Image.open(filename)
    binary = ''

    if img.mode in ('RGBA',):
        img = img.convert('RGBA')
        datas = img.getdata()

        for item in datas:
            digit = decode(rgb2hex(item[0], item[1], item[2]))
            if digit is not None:
                binary += digit
                if binary[-16:] == '1111111111111110':
                    return bin2str(binary[:-16])

        return bin2str(binary)

    return "Incorrect Image Mode, Couldn't Retrieve"

if __name__ == '__main__':
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()
