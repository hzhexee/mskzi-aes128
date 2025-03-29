import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import os
import random
import binascii
from main import aes_encrypt, aes_decrypt, aes_encrypt_block, aes_decrypt_block

class AES128App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AES-128 Шифрование")
        self.geometry("900x700")
        self.resizable(True, True)
        
        # Режимы шифрования Rijndael
        self.modes = {
            "ECB": self.ecb_mode,
            "CBC": self.cbc_mode,
            "CFB": self.cfb_mode,
            "OFB": self.ofb_mode,
            "CTR": self.ctr_mode
        }
        
        # Настройка интерфейса
        self.create_widgets()
        
    def create_widgets(self):
        # Основной фрейм
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Верхняя панель: выбор режима и ключа
        top_frame = ttk.LabelFrame(main_frame, text="Настройки шифрования", padding="10")
        top_frame.pack(fill=tk.X, pady=5)
        
        # Выбор режима шифрования Rijndael
        ttk.Label(top_frame, text="Режим шифрования:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.mode_var = tk.StringVar(value="CBC")
        mode_combo = ttk.Combobox(top_frame, textvariable=self.mode_var, values=list(self.modes.keys()), width=10, state="readonly")
        mode_combo.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Настройки ключа
        key_frame = ttk.LabelFrame(top_frame, text="Ключ шифрования (16 байт)", padding="5")
        key_frame.grid(row=0, column=2, rowspan=2, padx=10, columnspan=3, sticky=tk.W+tk.E)
        
        self.key_mode_var = tk.StringVar(value="default")
        ttk.Radiobutton(key_frame, text="По умолчанию", variable=self.key_mode_var, value="default",
                        command=self.toggle_key_entry).grid(row=0, column=0, sticky=tk.W, padx=5)
        ttk.Radiobutton(key_frame, text="Пользовательский", variable=self.key_mode_var, value="custom",
                        command=self.toggle_key_entry).grid(row=0, column=1, sticky=tk.W, padx=5)
        
        self.key_entry = ttk.Entry(key_frame, width=40)
        self.key_entry.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W+tk.E)
        self.key_entry.insert(0, "MySecretKey12345")
        self.key_entry.config(state='disabled')
        
        ttk.Button(key_frame, text="Генерировать случайный", command=self.generate_random_key).grid(
            row=1, column=2, padx=5, pady=5)
        
        # Настройки IV (вектора инициализации)
        iv_frame = ttk.LabelFrame(top_frame, text="Вектор инициализации (IV, 16 байт)", padding="5")
        iv_frame.grid(row=2, column=0, columnspan=5, padx=5, pady=5, sticky=tk.W+tk.E)
        
        self.iv_mode_var = tk.StringVar(value="default")
        ttk.Radiobutton(iv_frame, text="По умолчанию", variable=self.iv_mode_var, 
                      value="default", command=self.toggle_iv_entry).grid(row=0, column=0, sticky=tk.W, padx=5)
        ttk.Radiobutton(iv_frame, text="Пользовательский", variable=self.iv_mode_var, 
                      value="custom", command=self.toggle_iv_entry).grid(row=0, column=1, sticky=tk.W, padx=5)
        
        self.iv_entry = ttk.Entry(iv_frame, width=40)
        self.iv_entry.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W+tk.E)
        self.iv_entry.insert(0, "InitVectorAES128")
        self.iv_entry.config(state='disabled')
        
        ttk.Button(iv_frame, text="Генерировать случайный", command=self.generate_random_iv).grid(
            row=1, column=2, padx=5, pady=5)
        
        # Средняя панель: ввод текста и выбор файла
        middle_frame = ttk.LabelFrame(main_frame, text="Ввод данных", padding="10")
        middle_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Выбор источника ввода
        input_frame = ttk.Frame(middle_frame)
        input_frame.pack(fill=tk.X)
        
        self.input_mode_var = tk.StringVar(value="text")
        ttk.Radiobutton(input_frame, text="Текст", variable=self.input_mode_var, value="text",
                        command=self.toggle_input_mode).grid(row=0, column=0, sticky=tk.W, padx=5)
        ttk.Radiobutton(input_frame, text="Файл", variable=self.input_mode_var, value="file",
                        command=self.toggle_input_mode).grid(row=0, column=1, sticky=tk.W, padx=5)
        
        # Поле для ввода текста
        self.input_text = scrolledtext.ScrolledText(middle_frame, height=10)
        self.input_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Фрейм с кнопками выбора файла
        file_frame = ttk.Frame(middle_frame)
        file_frame.pack(fill=tk.X, pady=5)
        
        self.input_file_var = tk.StringVar()
        ttk.Label(file_frame, text="Входной файл:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(file_frame, textvariable=self.input_file_var, width=50, state="readonly").grid(
            row=0, column=1, padx=5, pady=5, sticky=tk.W+tk.E)
        ttk.Button(file_frame, text="Выбрать файл", command=self.select_input_file).grid(
            row=0, column=2, padx=5, pady=5)
        ttk.Button(file_frame, text="Создать файл", command=self.create_new_file).grid(
            row=0, column=3, padx=5, pady=5)
        
        file_frame.grid_columnconfigure(1, weight=1)
        
        # Панель с кнопками шифрования/дешифрования
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(action_frame, text="Шифровать", command=self.encrypt_data, width=20).pack(
            side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Дешифровать", command=self.decrypt_data, width=20).pack(
            side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Очистить", command=self.clear_fields, width=15).pack(
            side=tk.RIGHT, padx=5)
        
        # Нижняя панель: вывод результата
        bottom_frame = ttk.LabelFrame(main_frame, text="Результат", padding="10")
        bottom_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Поле для вывода результата
        self.output_text = scrolledtext.ScrolledText(bottom_frame, height=10)
        self.output_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Кнопка сохранения результата
        save_frame = ttk.Frame(bottom_frame)
        save_frame.pack(fill=tk.X)
        
        ttk.Button(save_frame, text="Сохранить результат в файл", command=self.save_output,
                  width=30).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Начальное состояние интерфейса
        self.toggle_input_mode()
    
    def toggle_key_entry(self):
        if self.key_mode_var.get() == "default":
            self.key_entry.config(state='disabled')
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, "MySecretKey12345")
        else:
            self.key_entry.config(state='normal')
    
    def toggle_iv_entry(self):
        if self.iv_mode_var.get() == "default":
            self.iv_entry.config(state='disabled')
            self.iv_entry.delete(0, tk.END)
            self.iv_entry.insert(0, "InitVectorAES128")
        else:
            self.iv_entry.config(state='normal')
    
    def generate_random_key(self):
        self.key_mode_var.set("custom")
        self.key_entry.config(state='normal')
        self.key_entry.delete(0, tk.END)
        random_key = ''.join(chr(random.randint(33, 126)) for _ in range(16))
        self.key_entry.insert(0, random_key)
    
    def generate_random_iv(self):
        self.iv_mode_var.set("custom")
        self.iv_entry.config(state='normal')
        self.iv_entry.delete(0, tk.END)
        random_iv = ''.join(chr(random.randint(33, 126)) for _ in range(16))
        self.iv_entry.insert(0, random_iv)
    
    def toggle_input_mode(self):
        if self.input_mode_var.get() == "text":
            self.input_text.config(state='normal')
        else:
            self.input_text.config(state='disabled')
    
    def select_input_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")])
        if file_path:
            self.input_file_var.set(file_path)
            self.input_mode_var.set("file")
            self.toggle_input_mode()
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.input_text.config(state='normal')
                self.input_text.delete(1.0, tk.END)
                self.input_text.insert(tk.END, content)
                self.input_text.config(state='disabled')
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось прочитать файл: {str(e)}")
    
    def create_new_file(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")])
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("")
                self.input_file_var.set(file_path)
                self.input_mode_var.set("file")
                self.toggle_input_mode()
                self.input_text.config(state='normal')
                self.input_text.delete(1.0, tk.END)
                messagebox.showinfo("Создание файла", "Файл успешно создан. Введите текст и сохраните его.")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось создать файл: {str(e)}")
    
    def get_key_and_iv(self):
        # Получение ключа
        key = self.key_entry.get().encode('utf-8')
        if len(key) != 16:
            messagebox.showerror("Ошибка", "Ключ должен быть ровно 16 символов!")
            return None, None
        
        # Получение IV для режимов, которые его используют
        current_mode = self.mode_var.get()
        iv = None
        if current_mode != "ECB":  # ECB не использует IV
            iv = self.iv_entry.get().encode('utf-8')
            if len(iv) != 16:
                messagebox.showerror("Ошибка", "Вектор инициализации должен быть ровно 16 символов!")
                return None, None
        
        return key, iv
    
    def get_input_data(self):
        if self.input_mode_var.get() == "text":
            return self.input_text.get(1.0, tk.END).strip().encode('utf-8')
        else:
            file_path = self.input_file_var.get()
            if not file_path:
                messagebox.showerror("Ошибка", "Файл не выбран!")
                return None
            try:
                with open(file_path, 'rb') as f:
                    return f.read()
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось прочитать файл: {str(e)}")
                return None
    
    def save_output(self):
        output_content = self.output_text.get(1.0, tk.END).strip()
        if not output_content:
            messagebox.showwarning("Предупреждение", "Нет данных для сохранения!")
            return
        
        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                               filetypes=[("Текстовые файлы", "*.txt"), ("Двоичные файлы", "*.bin"), 
                                                         ("Все файлы", "*.*")])
        if file_path:
            try:
                # Проверяем, является ли содержимое шестнадцатеричной строкой
                if all(c in "0123456789abcdefABCDEF " for c in output_content):
                    # Это шестнадцатеричная строка, сохраняем как бинарный файл
                    hex_content = output_content.replace(" ", "")
                    binary_content = binascii.unhexlify(hex_content)
                    with open(file_path, 'wb') as f:
                        f.write(binary_content)
                else:
                    # Это текст, сохраняем как текстовый файл
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(output_content)
                
                messagebox.showinfo("Сохранение", f"Файл успешно сохранен: {file_path}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {str(e)}")
    
    def clear_fields(self):
        self.input_text.config(state='normal')
        self.input_text.delete(1.0, tk.END)
        
        if self.input_mode_var.get() == "file":
            self.input_file_var.set("")
        
        self.output_text.delete(1.0, tk.END)
        
        # Возвращаем поля ключа и IV к начальным значениям
        if self.key_mode_var.get() == "default":
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, "MySecretKey12345")
        
        if self.iv_mode_var.get() == "default":
            self.iv_entry.delete(0, tk.END)
            self.iv_entry.insert(0, "InitVectorAES128")
        
        # Восстанавливаем начальное состояние интерфейса
        self.toggle_input_mode()
    
    # Реализации режимов шифрования
    def ecb_mode(self, data, key, iv, encrypt=True):
        """Electronic Codebook Mode (ECB)"""
        result = bytearray()
        
        # Разбиваем данные на блоки по 16 байт
        blocks = [data[i:i+16] for i in range(0, len(data), 16)]
        
        # Добавляем padding к последнему блоку если нужно
        if encrypt:
            if len(blocks[-1]) < 16:
                padding_length = 16 - len(blocks[-1])
                blocks[-1] += bytes([padding_length]) * padding_length
            else:  # Если последний блок полный и мы шифруем, добавляем целый блок padding
                blocks.append(bytes([16]) * 16)
        
        for block in blocks:
            if encrypt:
                if len(block) == 16:
                    # Шифруем каждый блок отдельно используя функцию для блока
                    encrypted_block = aes_encrypt_block(block, key)
                    result.extend(encrypted_block)
            else:
                if len(block) == 16:
                    # Дешифруем каждый блок отдельно используя функцию для блока
                    decrypted_block = aes_decrypt_block(block, key)
                    result.extend(decrypted_block)
                else:
                    # Предупреждение для неполного блока
                    messagebox.showwarning("Предупреждение", f"Пропущен неполный блок данных длиной {len(block)} байт")
        
        # Удаляем padding при дешифровании
        if not encrypt and len(result) > 0:
            padding_length = result[-1]
            if 0 < padding_length <= 16:
                # Проверяем валидность padding (все последние байты должны быть равны padding_length)
                if all(result[-i] == padding_length for i in range(1, padding_length + 1)):
                    result = result[:-padding_length]
        
        return bytes(result)
    
    def cbc_mode(self, data, key, iv, encrypt=True):
        """Cipher Block Chaining Mode (CBC)"""
        if encrypt:
            return aes_encrypt(data, key, iv)
        else:
            return aes_decrypt(data, key, iv)
    
    def cfb_mode(self, data, key, iv, encrypt=True):
        """Cipher Feedback Mode (CFB)"""
        result = bytearray()
        block_size = 16
        
        # Проверка, что длина данных кратна блоку
        if encrypt:
            # Добавляем padding для шифрования
            padding_length = block_size - (len(data) % block_size) if len(data) % block_size != 0 else 0
            data = data + bytes([padding_length]) * padding_length
        
        segments = [data[i:i+block_size] for i in range(0, len(data), block_size)]
        
        feedback = iv
        
        for segment in segments:
            # Шифруем feedback
            encrypted_feedback = aes_encrypt(feedback, key, None)[:len(segment)]
            
            if encrypt:
                # XOR с открытым текстом
                processed = bytes(a ^ b for a, b in zip(segment, encrypted_feedback))
                feedback = processed  # Для следующего блока
            else:
                # XOR с шифротекстом
                processed = bytes(a ^ b for a, b in zip(segment, encrypted_feedback))
                feedback = segment  # Для следующего блока
            
            result.extend(processed)
        
        # Удаляем padding при дешифровании
        if not encrypt and len(result) > 0:
            padding_length = result[-1]
            if 0 < padding_length <= block_size:
                result = result[:-padding_length]
        
        return bytes(result)
    
    def ofb_mode(self, data, key, iv, encrypt=True):
        """Output Feedback Mode (OFB)"""
        result = bytearray()
        block_size = 16
        
        # Проверка, что длина данных кратна блоку
        if encrypt:
            # Добавляем padding для шифрования
            padding_length = block_size - (len(data) % block_size) if len(data) % block_size != 0 else 0
            data = data + bytes([padding_length]) * padding_length
        
        segments = [data[i:i+block_size] for i in range(0, len(data), block_size)]
        
        feedback = iv
        
        for segment in segments:
            # Шифруем feedback
            encrypted_feedback = aes_encrypt(feedback, key, None)[:len(segment)]
            feedback = encrypted_feedback  # Для следующего блока
            
            # XOR с открытым/шифрованным текстом
            processed = bytes(a ^ b for a, b in zip(segment, encrypted_feedback))
            result.extend(processed)
        
        # Удаляем padding при дешифровании
        if not encrypt and len(result) > 0:
            padding_length = result[-1]
            if 0 < padding_length <= block_size:
                result = result[:-padding_length]
        
        return bytes(result)
    
    def ctr_mode(self, data, key, iv, encrypt=True):
        """Counter Mode (CTR)"""
        result = bytearray()
        block_size = 16
        
        # Проверка, что длина данных кратна блоку
        if encrypt:
            # Добавляем padding для шифрования
            padding_length = block_size - (len(data) % block_size) if len(data) % block_size != 0 else 0
            data = data + bytes([padding_length]) * padding_length
        
        segments = [data[i:i+block_size] for i in range(0, len(data), block_size)]
        
        counter = list(iv)  # Преобразуем IV в список для изменения
        
        for segment in segments:
            # Шифруем текущее значение счетчика
            encrypted_counter = aes_encrypt(bytes(counter), key, None)[:len(segment)]
            
            # XOR с открытым/шифрованным текстом
            processed = bytes(a ^ b for a, b in zip(segment, encrypted_counter))
            result.extend(processed)
            
            # Увеличиваем счетчик
            for i in range(len(counter) - 1, -1, -1):
                counter[i] = (counter[i] + 1) & 0xFF
                if counter[i] != 0:
                    break
        
        # Удаляем padding при дешифровании
        if not encrypt and len(result) > 0:
            padding_length = result[-1]
            if 0 < padding_length <= block_size:
                result = result[:-padding_length]
        
        return bytes(result)
    
    def encrypt_data(self):
        key, iv = self.get_key_and_iv()
        if key is None:
            return
        
        data = self.get_input_data()
        if data is None:
            return
        
        try:
            mode_function = self.modes[self.mode_var.get()]
            encrypted_data = mode_function(data, key, iv, encrypt=True)
            
            # Вывод результата в шестнадцатеричном формате
            hex_output = encrypted_data.hex()
            
            # Форматируем вывод в удобном виде (группы по 2 символа)
            formatted_hex = ' '.join(hex_output[i:i+2] for i in range(0, len(hex_output), 2))
            
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, formatted_hex)
            
            messagebox.showinfo("Шифрование", "Данные успешно зашифрованы!")
        except Exception as e:
            messagebox.showerror("Ошибка шифрования", str(e))
    
    def decrypt_data(self):
        key, iv = self.get_key_and_iv()
        if key is None:
            return
        
        # Получаем данные из поля ввода
        hex_input = self.input_text.get(1.0, tk.END).strip()
        
        try:
            # Проверяем, является ли ввод шестнадцатеричной строкой
            if all(c in "0123456789abcdefABCDEF " for c in hex_input):
                # Преобразуем шестнадцатеричную строку в байты
                hex_input = hex_input.replace(" ", "")
                data = binascii.unhexlify(hex_input)
            else:
                data = self.get_input_data()
                if data is None:
                    return
            
            mode_function = self.modes[self.mode_var.get()]
            decrypted_data = mode_function(data, key, iv, encrypt=False)
            
            # Выводим расшифрованный текст
            try:
                # Пытаемся декодировать как UTF-8
                text_output = decrypted_data.decode('utf-8')
                self.output_text.delete(1.0, tk.END)
                self.output_text.insert(tk.END, text_output)
            except UnicodeDecodeError:
                # Если не удается декодировать как текст, выводим как шестнадцатеричную строку
                hex_output = decrypted_data.hex()
                formatted_hex = ' '.join(hex_output[i:i+2] for i in range(0, len(hex_output), 2))
                self.output_text.delete(1.0, tk.END)
                self.output_text.insert(tk.END, formatted_hex)
            
            messagebox.showinfo("Дешифрование", "Данные успешно расшифрованы!")
        except Exception as e:
            messagebox.showerror("Ошибка дешифрования", str(e))

if __name__ == "__main__":
    app = AES128App()
    app.mainloop()
