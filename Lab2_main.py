import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

class CryptoApp:
    def __init__(self, master):
        self.master = master
        master.title("Криптографічна програма")

        self.action = tk.StringVar(value="encrypt")
        self.algorithm = tk.StringVar(value="AES")

        # Вибір дії
        tk.Label(master, text="Виберіть дію:").pack()
        tk.Radiobutton(master, text="Зашифрувати", variable=self.action, value="encrypt").pack()
        tk.Radiobutton(master, text="Розшифрувати", variable=self.action, value="decrypt").pack()

        # Вибір алгоритму
        tk.Label(master, text="Виберіть алгоритм:").pack()
        tk.Radiobutton(master, text="AES", variable=self.algorithm, value="AES").pack()
        tk.Radiobutton(master, text="RSA", variable=self.algorithm, value="RSA").pack()
        tk.Radiobutton(master, text="SHA256 (хешування)", variable=self.algorithm, value="SHA256").pack()

        # Вибір файлів
        tk.Button(master, text="Вибрати вхідний файл", command=self.select_input_file).pack()
        self.input_file_label = tk.Label(master, text="Вхідний файл не вибрано")
        self.input_file_label.pack()

        tk.Button(master, text="Вибрати вихідний файл", command=self.select_output_file).pack()
        self.output_file_label = tk.Label(master, text="Вихідний файл не вибрано")
        self.output_file_label.pack()

        # Кнопка виконання
        tk.Button(master, text="Виконати", command=self.execute).pack()

        self.input_file = None
        self.output_file = None

    def select_input_file(self):
        self.input_file = filedialog.askopenfilename()
        self.input_file_label.config(text=self.input_file if self.input_file else "Вхідний файл не вибрано")

    def select_output_file(self):
        self.output_file = filedialog.asksaveasfilename(defaultextension=".txt")
        self.output_file_label.config(text=self.output_file if self.output_file else "Вихідний файл не вибрано")

    def execute(self):
        if not self.input_file or not self.output_file:
            messagebox.showerror("Помилка", "Будь ласка, виберіть вхідний та вихідний файли.")
            return

        try:
            with open(self.input_file, 'rb') as f:
                data = f.read()

            if self.algorithm.get() == "AES":
                if self.action.get() == "encrypt":
                    result = self.aes_encrypt(data)
                else:
                    result = self.aes_decrypt(data)
            elif self.algorithm.get() == "RSA":
                if self.action.get() == "encrypt":
                    result = self.rsa_encrypt(data)
                else:
                    result = self.rsa_decrypt(data)
            elif self.algorithm.get() == "SHA256":
                result = self.sha256_hash(data)
            else:
                messagebox.showerror("Помилка", "Невідомий алгоритм.")
                return

            with open(self.output_file, 'wb') as f:
                f.write(result)

            messagebox.showinfo("Успіх", "Операція виконана успішно.")
        except Exception as e:
            messagebox.showerror("Помилка", f"Виникла помилка: {str(e)}")

    def aes_encrypt(self, data):
        password = self.get_password()
        salt = os.urandom(16)
        key = self.derive_key(password, salt)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
        return salt + iv + ct

    def aes_decrypt(self, data):
        password = self.get_password()
        salt = data[:16]
        iv = data[16:32]
        ct = data[32:]
        key = self.derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(ct) + decryptor.finalize()

    def rsa_encrypt(self, data):
        public_key = self.load_public_key()
        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def rsa_decrypt(self, data):
        private_key = self.load_private_key()
        plaintext = private_key.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

    def sha256_hash(self, data):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        return digest.finalize()

    def get_password(self):
        password = tk.simpledialog.askstring("Пароль", "Введіть пароль:", show='*')
        if not password:
            raise ValueError("Пароль не може бути порожнім.")
        return password.encode()

    def derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(password)

    def load_public_key(self):
        key_file = filedialog.askopenfilename(title="Виберіть публічний ключ")
        with open(key_file, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read()
            )
        return public_key

    def load_private_key(self):
        key_file = filedialog.askopenfilename(title="Виберіть приватний ключ")
        password = tk.simpledialog.askstring("Пароль ключа", "Введіть пароль для приватного ключа (якщо є):", show='*')
        with open(key_file, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password.encode() if password else None,
            )
        return private_key

root = tk.Tk()
app = CryptoApp(root)
root.mainloop()
