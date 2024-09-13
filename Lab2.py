import tkinter as tk
from tkinter import filedialog, messagebox


def caesar_cipher(text, shift, direction, language):
    result = ''
    try:
        if language == "UKR":
            alphabet = "абвгдеєжзиіїйклмнопрстуфхцчшщьюя"
        elif language == "ENG":
            alphabet = 'abcdefghijklmnopqrstuvwxyz'
    except Exception as e:
        messagebox.showerror("Помилка - оберіть мову")


    if direction == 'encrypt':
        for char in text:
            if char.isalpha():
                index = alphabet.index(char.lower())
                new_index = (index + shift) % len(alphabet)
                if char.isupper():
                    result += alphabet[new_index].upper()
                else:
                    result += alphabet[new_index]
            else:
                result += char
    elif direction == 'decrypt':
        for char in text:
            if char.isalpha():
                index = alphabet.index(char.lower())
                new_index = (index - shift) % len(alphabet)
                if char.isupper():
                    result += alphabet[new_index].upper()
                else:
                    result += alphabet[new_index]
            else:
                result += char
    return result


def caesar_files(input_file, output_file, key, mode, language):
    try:
        with open(input_file, 'r', encoding='utf-8') as f_in:
            with open(output_file, 'w', encoding='utf-8') as f_out:
                for line in f_in:
                    processed_line = caesar_cipher(line, key, mode, language)
                    f_out.write(processed_line)
        messagebox.showinfo("Успіх", "Операція успішно виконана!")
    except Exception as e:
        messagebox.showerror("Помилка", f"Сталася помилка: {e}")


def open_file_dialog(entry):
    filename = filedialog.askopenfilename()
    if filename:
        entry.delete(0, tk.END)
        entry.insert(0, filename)


def save_file_dialog(entry):
    filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if filename:
        entry.delete(0, tk.END)
        entry.insert(0, filename)


def on_encrypt_decrypt():
    input_file = input_file_entry.get()
    output_file = output_file_entry.get()
    try:
        key = int(key_entry.get())
        mode = mode_var.get()
        language = language_var.get()
        caesar_files(input_file, output_file, key, mode, language)
    except ValueError:
        messagebox.showerror("Помилка", "Ключ має бути цілим числом.")


root = tk.Tk()
root.title("Шифр Цезаря")

input_file_label = tk.Label(root, text="Вхідний файл:")
input_file_label.grid(row=0, column=0, padx=10, pady=10)
input_file_entry = tk.Entry(root, width=40)
input_file_entry.grid(row=0, column=1, padx=10, pady=10)
input_file_button = tk.Button(root, text="Вибрати", command=lambda: open_file_dialog(input_file_entry))
input_file_button.grid(row=0, column=2, padx=10, pady=10)

output_file_label = tk.Label(root, text="Вихідний файл:")
output_file_label.grid(row=1, column=0, padx=10, pady=10)
output_file_entry = tk.Entry(root, width=40)
output_file_entry.grid(row=1, column=1, padx=10, pady=10)
output_file_button = tk.Button(root, text="Зберегти як", command=lambda: save_file_dialog(output_file_entry))
output_file_button.grid(row=1, column=2, padx=10, pady=10)

key_label = tk.Label(root, text="Ключ:")
key_label.grid(row=2, column=0, padx=10, pady=10)
key_entry = tk.Entry(root, width=10)
key_entry.grid(row=2, column=1, padx=10, pady=10)

mode_var = tk.StringVar(value="encrypt")
encrypt_radio = tk.Radiobutton(root, text="Зашифрувати", variable=mode_var, value="encrypt")
encrypt_radio.grid(row=3, column=0, padx=10, pady=10)
decrypt_radio = tk.Radiobutton(root, text="Розшифрувати", variable=mode_var, value="decrypt")
decrypt_radio.grid(row=3, column=1, padx=10, pady=10)

language_var = tk.StringVar(value="UKR")
ukr_radio = tk.Radiobutton(root, text="UKR", variable=language_var, value="UKR")
ukr_radio.grid(row=4, column=0, padx=10, pady=10)
eng_radio = tk.Radiobutton(root, text="ENG", variable=language_var, value="ENG")
eng_radio.grid(row=4, column=1, padx=10, pady=10)

process_button = tk.Button(root, text="Виконати", command=on_encrypt_decrypt)
process_button.grid(row=5, column=0, columnspan=3, padx=10, pady=20)

root.mainloop()