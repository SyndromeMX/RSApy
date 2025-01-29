import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64


class RSAApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Шифрование RSA")
        self.root.geometry("600x550")
        self.root.configure(bg="#f0f0f0")

        # === Верхнее меню переключения вкладок ===
        self.menu_frame = tk.Frame(self.root, bg="#d9d9d9", height=40)
        self.menu_frame.pack(fill="x")

        self.key_management_btn = tk.Button(
            self.menu_frame, text="Управление ключами", command=self.show_key_frame,
            bg="#0078D7", fg="white", font=("Arial", 10, "bold"), relief="flat", padx=10, pady=5
        )
        self.key_management_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.encryption_btn = tk.Button(
            self.menu_frame, text="Шифрование/Дешифрование", command=self.show_encryption_frame,
            bg="#0078D7", fg="white", font=("Arial", 10, "bold"), relief="flat", padx=10, pady=5
        )
        self.encryption_btn.pack(side=tk.LEFT, padx=5, pady=5)

        # === Разделительная полоса ===
        self.separator = tk.Frame(self.root, bg="black", height=2)
        self.separator.pack(fill="x")

        # === Вкладка: Управление ключами ===
        self.key_frame = tk.Frame(self.root, bg="#f0f0f0")

        self.gen_key_btn = tk.Button(
            self.key_frame, text="Сгенерировать ключи RSA", command=self.generate_keys,
            bg="#4CAF50", fg="white", font=("Arial", 10, "bold"), relief="flat", padx=10, pady=5
        )
        self.gen_key_btn.pack(pady=5)

        self.load_keys_btn = tk.Button(
            self.key_frame, text="Загрузить ключи", command=self.load_keys,
            bg="#FFA500", fg="white", font=("Arial", 10, "bold"), relief="flat", padx=10, pady=5
        )
        self.load_keys_btn.pack(pady=5)

        self.key_display = tk.Text(self.key_frame, height=10, width=70, wrap="word", font=("Arial", 10))
        self.key_display.pack(pady=5)

        # === Вкладка: Шифрование и дешифрование ===
        self.encryption_frame = tk.Frame(self.root, bg="#f0f0f0")

        self.text_entry = tk.Text(self.encryption_frame, height=5, width=60, font=("Arial", 10))
        self.text_entry.pack(pady=5)

        self.file_button_frame = tk.Frame(self.encryption_frame, bg="#f0f0f0")
        self.file_button_frame.pack(pady=5)

        self.load_file_btn = tk.Button(
            self.file_button_frame, text="Загрузить файл", command=self.load_file,
            bg="#008CBA", fg="white", font=("Arial", 10, "bold"), relief="flat", padx=10, pady=5
        )
        self.load_file_btn.pack(side=tk.LEFT, padx=5)

        self.save_file_btn = tk.Button(
            self.file_button_frame, text="Сохранить файл", command=self.save_encrypted_file,
            bg="#008CBA", fg="white", font=("Arial", 10, "bold"), relief="flat", padx=10, pady=5
        )
        self.save_file_btn.pack(side=tk.LEFT, padx=5)

        self.button_frame = tk.Frame(self.encryption_frame, bg="#f0f0f0")
        self.button_frame.pack(pady=5)

        self.encode_btn = tk.Button(
            self.button_frame, text="Зашифровать", command=self.encode_message,
            bg="#4CAF50", fg="white", font=("Arial", 10, "bold"), relief="flat", padx=10, pady=5
        )
        self.encode_btn.pack(side=tk.LEFT, padx=5)

        self.decode_btn = tk.Button(
            self.button_frame, text="Расшифровать", command=self.decode_message,
            bg="#FF5733", fg="white", font=("Arial", 10, "bold"), relief="flat", padx=10, pady=5
        )
        self.decode_btn.pack(side=tk.LEFT, padx=5)

        self.result_text = tk.Text(self.encryption_frame, height=5, width=60, font=("Arial", 10))
        self.result_text.pack(pady=5)

        self.private_key = None
        self.public_key = None

        # Показать начальную вкладку
        self.show_key_frame()

    def show_key_frame(self):
        self.encryption_frame.pack_forget()
        self.key_frame.pack()

    def show_encryption_frame(self):
        self.key_frame.pack_forget()
        self.encryption_frame.pack()

    def generate_keys(self):
        key = RSA.generate(2048)
        self.private_key = key.export_key()
        self.public_key = key.publickey().export_key()

        with open("private.pem", "wb") as priv_file:
            priv_file.write(self.private_key)

        with open("public.pem", "wb") as pub_file:
            pub_file.write(self.public_key)

        self.key_display.delete("1.0", tk.END)
        self.key_display.insert(tk.END, f"PRIVATE KEY:\n{self.private_key.decode()}\n\nPUBLIC KEY:\n{self.public_key.decode()}")

        messagebox.showinfo("Успех", "Ключи RSA сгенерированы!")

    def load_keys(self):
        try:
            with open("private.pem", "rb") as priv_file:
                self.private_key = priv_file.read()
            with open("public.pem", "rb") as pub_file:
                self.public_key = pub_file.read()

            self.key_display.delete("1.0", tk.END)
            self.key_display.insert(tk.END, "Ключи загружены!")

            messagebox.showinfo("Успех", "Ключи RSA загружены!")
        except FileNotFoundError:
            messagebox.showerror("Ошибка", "Файлы ключей не найдены!")

    def encode_message(self):
        if not self.public_key:
            messagebox.showerror("Ошибка", "Загрузите или создайте открытый ключ!")
            return

        message = self.text_entry.get("1.0", tk.END).strip().encode()
        rsa_key = RSA.import_key(self.public_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        encrypted_message = base64.b64encode(cipher.encrypt(message))

        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, encrypted_message.decode())

    def decode_message(self):
        if not self.private_key:
            messagebox.showerror("Ошибка", "Загрузите или создайте закрытый ключ!")
            return

        encrypted_message = self.result_text.get("1.0", tk.END).strip()
        rsa_key = RSA.import_key(self.private_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        decrypted_message = cipher.decrypt(base64.b64decode(encrypted_message))

        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, decrypted_message.decode())

    def load_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        with open(file_path, "r") as file:
            self.text_entry.insert(tk.END, file.read())

    def save_encrypted_file(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        with open(file_path, "w") as file:
            file.write(self.result_text.get("1.0", tk.END).strip())


root = tk.Tk()
app = RSAApp(root)
root.mainloop()
