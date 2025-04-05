import os
import random
import binascii
import base64
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QSplitter,
                            QLabel, QComboBox, QRadioButton, QLineEdit, 
                            QPushButton, QTextEdit, QVBoxLayout, QHBoxLayout,
                            QGridLayout, QFileDialog, QMessageBox, QMenuBar,
                            QMenu, QToolBar, QTabWidget, QStatusBar, QFrame,
                            QButtonGroup)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QIcon, QFont, QPixmap, QColor, QAction
from main import aes_encrypt, aes_decrypt, aes_encrypt_block, aes_decrypt_block

class ModernQLabel(QLabel):
    """Стилизованный QLabel с современным видом"""
    def __init__(self, text="", parent=None, is_title=False):
        super().__init__(text, parent)
        if is_title:
            font = QFont()
            font.setBold(True)
            self.setFont(font)
            self.setStyleSheet("color: #003366; padding: 5px;")

class ModernQFrame(QFrame):
    """Стилизованная панель с границей и заголовком"""
    def __init__(self, title="", parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setStyleSheet("background-color: white; border: 1px solid #dddddd; border-radius: 5px;")
        
        # Основной макет
        self.layout = QVBoxLayout(self)
        
        # Добавляем заголовок, если он указан
        if title:
            header = ModernQLabel(title, is_title=True)
            self.layout.addWidget(header)
            
            # Добавляем разделительную линию
            line = QFrame()
            line.setFrameShape(QFrame.Shape.HLine)
            line.setFrameShadow(QFrame.Shadow.Sunken)
            line.setStyleSheet("background-color: #ddd;")
            self.layout.addWidget(line)

class AES128App(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AES-128 Шифрование и Дешифрование")
        self.resize(1100, 700)
        
        # Установка светлой темы для всего приложения
        self.setStyleSheet("""
            QMainWindow, QWidget, QDialog, QFrame {
                background-color: white;
                color: black;
            }
            QPushButton {
                background-color: #f0f0f0;
                color: black;
                border: 1px solid #cccccc;
                border-radius: 4px;
                padding: 5px;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
            QLineEdit, QTextEdit, QComboBox {
                background-color: white;
                color: black;
                border: 1px solid #cccccc;
                border-radius: 4px;
                padding: 3px;
            }
            QLabel {
                color: black;
            }
            QRadioButton {
                color: black;
            }
            QTabWidget::pane {
                border: 1px solid #cccccc;
                background-color: white;
            }
            QTabBar::tab {
                background-color: #f0f0f0;
                color: black;
                padding: 5px 10px;
                border: 1px solid #cccccc;
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: white;
                border-bottom: 1px solid white;
            }
            QStatusBar {
                background-color: #f0f0f0;
                color: black;
            }
            QToolBar {
                background-color: white;
                border-bottom: 1px solid #cccccc;
            }
        """)
        
        # Режимы шифрования
        self.modes = {
            "ECB": self.ecb_mode,
            "CBC": self.cbc_mode,
            "CFB": self.cfb_mode,
            "OFB": self.ofb_mode,
            "CTR": self.ctr_mode
        }
        
        # Создаем центральный виджет
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        # Создаем строку состояния
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Готов к работе")
        
        # Создаем меню и панель инструментов
        self.create_menu_and_toolbar()
        
        # Настройка интерфейса
        self.create_widgets()
        
    def create_menu_and_toolbar(self):
        # Создаем меню
        menu_bar = self.menuBar()
        
        # Меню файла
        file_menu = menu_bar.addMenu("Файл")
        
        open_action = QAction("Открыть...", self)
        open_action.triggered.connect(self.select_input_file)
        open_action.setShortcut("Ctrl+O")
        file_menu.addAction(open_action)
        
        save_action = QAction("Сохранить результат...", self)
        save_action.triggered.connect(self.save_output)
        save_action.setShortcut("Ctrl+S")
        file_menu.addAction(save_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Выход", self)
        exit_action.triggered.connect(self.close)
        exit_action.setShortcut("Alt+F4")
        file_menu.addAction(exit_action)
        
        # Меню операций
        operation_menu = menu_bar.addMenu("Операции")
        
        encrypt_action = QAction("Шифровать", self)
        encrypt_action.triggered.connect(self.encrypt_data)
        encrypt_action.setShortcut("F5")
        operation_menu.addAction(encrypt_action)
        
        decrypt_action = QAction("Дешифровать", self)
        decrypt_action.triggered.connect(self.decrypt_data)
        decrypt_action.setShortcut("F6")
        operation_menu.addAction(decrypt_action)
        
        operation_menu.addSeparator()
        
        clear_action = QAction("Очистить поля", self)
        clear_action.triggered.connect(self.clear_fields)
        clear_action.setShortcut("Ctrl+L")
        operation_menu.addAction(clear_action)
        
        # Меню помощи
        help_menu = menu_bar.addMenu("Справка")
        
        about_action = QAction("О программе", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
        # Создаем панель инструментов
        toolbar = QToolBar("Основная панель")
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(24, 24))
        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, toolbar)
        
        toolbar.addAction(open_action)
        toolbar.addAction(save_action)
        toolbar.addSeparator()
        toolbar.addAction(encrypt_action)
        toolbar.addAction(decrypt_action)
        toolbar.addSeparator()
        toolbar.addAction(clear_action)
    
    def create_widgets(self):
        # Создаем главный горизонтальный сплиттер
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Левая панель для настроек
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(5, 5, 5, 5)
        
        # Режим шифрования через вкладки
        mode_frame = ModernQFrame("Режим шифрования")
        mode_layout = QVBoxLayout()
        mode_frame.layout.addLayout(mode_layout)
        
        self.mode_tabs = QTabWidget()
        self.mode_tabs.setTabPosition(QTabWidget.TabPosition.North)
        for mode in self.modes.keys():
            tab = QWidget()
            tab_layout = QVBoxLayout(tab)
            
            # Добавляем описание режима
            descriptions = {
                "ECB": "Режим электронной кодовой книги (Electronic Codebook Mode)\n"
                      "Каждый блок шифруется независимо. Не требует IV.",
                "CBC": "Режим сцепления блоков шифротекста (Cipher Block Chaining)\n"
                      "Каждый блок XOR с предыдущим зашифрованным блоком.",
                "CFB": "Режим обратной связи по шифротексту (Cipher Feedback)\n"
                      "Поддерживает шифрование данных меньше блока.",
                "OFB": "Режим обратной связи по выходу (Output Feedback)\n"
                      "Генерирует ключевой поток для XOR с открытым текстом.",
                "CTR": "Режим счетчика (Counter Mode)\n"
                      "Превращает блочный шифр в поточный с помощью счетчика."
            }
            
            desc_label = QLabel(descriptions.get(mode, ""))
            desc_label.setWordWrap(True)
            desc_label.setStyleSheet("color: #555; font-style: italic;")
            tab_layout.addWidget(desc_label)
            tab_layout.addStretch()
            
            self.mode_tabs.addTab(tab, mode)
        
        mode_layout.addWidget(self.mode_tabs)
        left_layout.addWidget(mode_frame)
        
        # Ключи и IV
        keys_frame = ModernQFrame("Параметры шифрования")
        keys_layout = QVBoxLayout()
        keys_frame.layout.addLayout(keys_layout)
        
        # Управление ключом
        key_layout = QGridLayout()
        key_layout.setContentsMargins(5, 5, 5, 5)
        
        key_label = ModernQLabel("Ключ шифрования (16 байт):", is_title=True)
        key_layout.addWidget(key_label, 0, 0, 1, 3)
        
        self.key_radio_group = QButtonGroup(self)
        self.key_default_radio = QRadioButton("По умолчанию")
        self.key_custom_radio = QRadioButton("Пользовательский")
        
        self.key_radio_group.addButton(self.key_default_radio)
        self.key_radio_group.addButton(self.key_custom_radio)
        self.key_default_radio.setChecked(True)
        
        key_radio_layout = QHBoxLayout()
        key_radio_layout.addWidget(self.key_default_radio)
        key_radio_layout.addWidget(self.key_custom_radio)
        key_radio_layout.addStretch()
        
        key_layout.addLayout(key_radio_layout, 1, 0, 1, 3)
        
        self.key_entry = QLineEdit("MySecretKey12345")
        self.key_entry.setStyleSheet("padding: 8px; border: 1px solid #ccc; border-radius: 4px;")
        self.key_entry.setEnabled(False)
        self.key_entry.setTextMargins(5, 2, 5, 2)
        
        key_layout.addWidget(self.key_entry, 2, 0, 1, 2)
        
        self.gen_key_btn = QPushButton("Сгенерировать")
        self.gen_key_btn.setStyleSheet("background-color: #8FBC8F; color: black; padding: 5px; font-weight: bold;")
        key_layout.addWidget(self.gen_key_btn, 2, 2)
        
        keys_layout.addLayout(key_layout)
        
        # Управление вектором инициализации
        iv_layout = QGridLayout()
        iv_layout.setContentsMargins(5, 15, 5, 5)
        
        iv_label = ModernQLabel("Вектор инициализации (16 байт):", is_title=True)
        iv_layout.addWidget(iv_label, 0, 0, 1, 3)
        
        self.iv_radio_group = QButtonGroup(self)
        self.iv_default_radio = QRadioButton("По умолчанию")
        self.iv_custom_radio = QRadioButton("Пользовательский")
        
        self.iv_radio_group.addButton(self.iv_default_radio)
        self.iv_radio_group.addButton(self.iv_custom_radio)
        self.iv_default_radio.setChecked(True)
        
        iv_radio_layout = QHBoxLayout()
        iv_radio_layout.addWidget(self.iv_default_radio)
        iv_radio_layout.addWidget(self.iv_custom_radio)
        iv_radio_layout.addStretch()
        
        iv_layout.addLayout(iv_radio_layout, 1, 0, 1, 3)
        
        self.iv_entry = QLineEdit("InitVectorAES128")
        self.iv_entry.setStyleSheet("padding: 8px; border: 1px solid #ccc; border-radius: 4px;")
        self.iv_entry.setEnabled(False)
        self.iv_entry.setTextMargins(5, 2, 5, 2)
        
        iv_layout.addWidget(self.iv_entry, 2, 0, 1, 2)
        
        self.gen_iv_btn = QPushButton("Сгенерировать")
        self.gen_iv_btn.setStyleSheet("background-color: #8FBC8F; color: black; padding: 5px; font-weight: bold;")
        iv_layout.addWidget(self.gen_iv_btn, 2, 2)
        
        keys_layout.addLayout(iv_layout)
        
        # Кнопки шифрования и дешифрования внизу панели конфигурации
        crypto_buttons_layout = QHBoxLayout()
        
        self.encrypt_btn = QPushButton("Шифровать ➜")
        self.encrypt_btn.setStyleSheet("background-color: #B0C4DE; color: black; padding: 10px; font-weight: bold;")
        self.encrypt_btn.setMinimumHeight(40)
        crypto_buttons_layout.addWidget(self.encrypt_btn)
        
        self.decrypt_btn = QPushButton("➜ Дешифровать")
        self.decrypt_btn.setStyleSheet("background-color: #FFB6C1; color: black; padding: 10px; font-weight: bold;")
        self.decrypt_btn.setMinimumHeight(40)
        crypto_buttons_layout.addWidget(self.decrypt_btn)
        
        keys_layout.addLayout(crypto_buttons_layout)
        
        left_layout.addWidget(keys_frame)
        left_layout.addStretch()
        
        # Добавляем левую панель к сплиттеру
        main_splitter.addWidget(left_widget)
        
        # Правая панель для ввода/вывода
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(5, 5, 5, 5)
        
        # Панель выбора источника данных
        source_frame = ModernQFrame("Источник данных")
        source_layout = QVBoxLayout()
        source_frame.layout.addLayout(source_layout)
        
        # Радио-кнопки выбора источника
        source_radio_layout = QHBoxLayout()
        
        self.source_radio_group = QButtonGroup(self)
        self.text_radio = QRadioButton("Текстовый ввод")
        self.file_radio = QRadioButton("Файл")
        
        self.source_radio_group.addButton(self.text_radio)
        self.source_radio_group.addButton(self.file_radio)
        self.text_radio.setChecked(True)
        
        source_radio_layout.addWidget(self.text_radio)
        source_radio_layout.addWidget(self.file_radio)
        source_radio_layout.addStretch()
        
        source_layout.addLayout(source_radio_layout)
        
        # Выбор файла
        file_layout = QHBoxLayout()
        file_layout.addWidget(QLabel("Путь к файлу:"))
        self.input_file_entry = QLineEdit()
        self.input_file_entry.setReadOnly(True)
        file_layout.addWidget(self.input_file_entry)
        
        self.select_file_btn = QPushButton("Обзор...")
        file_layout.addWidget(self.select_file_btn)
        
        source_layout.addLayout(file_layout)
        
        right_layout.addWidget(source_frame)
        
        # Вертикальный сплиттер для областей ввода/вывода
        io_splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Панель ввода
        input_frame = ModernQFrame("Входные данные")
        input_layout = QVBoxLayout()
        input_frame.layout.addLayout(input_layout)
        
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Введите текст для шифрования/дешифрования здесь...")
        self.input_text.setStyleSheet("border: 1px solid #cccccc; border-radius: 4px; background-color: white; color: black;")
        input_layout.addWidget(self.input_text)
        
        io_splitter.addWidget(input_frame)
        
        # Панель вывода
        output_frame = ModernQFrame("Результат")
        output_layout = QVBoxLayout()
        output_frame.layout.addLayout(output_layout)
        
        self.output_text = QTextEdit()
        self.output_text.setPlaceholderText("Результат операции будет отображаться здесь...")
        self.output_text.setReadOnly(True)
        self.output_text.setStyleSheet("border: 1px solid #cccccc; border-radius: 4px; background-color: white; color: black;")
        output_layout.addWidget(self.output_text)
        
        # Кнопка сохранения и очистки
        output_buttons_layout = QHBoxLayout()
        
        self.save_btn = QPushButton("Сохранить результат")
        self.save_btn.setStyleSheet("background-color: #B0C4DE; color: black; padding: 5px; font-weight: bold;")
        output_buttons_layout.addWidget(self.save_btn)
        
        output_buttons_layout.addStretch()
        
        self.clear_btn = QPushButton("Очистить все")
        self.clear_btn.setStyleSheet("background-color: #E0E0E0; color: black; padding: 5px;")
        output_buttons_layout.addWidget(self.clear_btn)
        
        output_layout.addLayout(output_buttons_layout)
        
        io_splitter.addWidget(output_frame)
        
        # Устанавливаем начальные размеры панелей
        io_splitter.setSizes([300, 300])
        
        right_layout.addWidget(io_splitter, 1)  # Растягиваем по вертикали
        
        # Добавляем правую панель к сплиттеру
        main_splitter.addWidget(right_widget)
        
        # Устанавливаем начальные размеры панелей (40% слева, 60% справа)
        main_splitter.setSizes([400, 600])
        
        # Добавляем сплиттер в главный макет
        main_layout = QVBoxLayout(self.central_widget)
        main_layout.setContentsMargins(5, 5, 5, 5)
        main_layout.addWidget(main_splitter)
        
        # Подключение сигналов к слотам
        self.connect_signals()
    
    def connect_signals(self):
        # Подключение сигналов радиокнопок
        self.key_default_radio.toggled.connect(self.toggle_key_entry)
        self.key_custom_radio.toggled.connect(self.toggle_key_entry)
        self.iv_default_radio.toggled.connect(self.toggle_iv_entry)
        self.iv_custom_radio.toggled.connect(self.toggle_iv_entry)
        self.text_radio.toggled.connect(self.toggle_input_mode)
        self.file_radio.toggled.connect(self.toggle_input_mode)
        
        # Подключение кнопок
        self.gen_key_btn.clicked.connect(self.generate_random_key)
        self.gen_iv_btn.clicked.connect(self.generate_random_iv)
        self.select_file_btn.clicked.connect(self.select_input_file)
        self.encrypt_btn.clicked.connect(self.encrypt_data)
        self.decrypt_btn.clicked.connect(self.decrypt_data)
        self.clear_btn.clicked.connect(self.clear_fields)
        self.save_btn.clicked.connect(self.save_output)
        
        # Подключаем изменение режима для обновления интерфейса
        self.mode_tabs.currentChanged.connect(self.mode_changed)
    
    def show_about(self):
        """Показывает информацию о программе"""
        QMessageBox.about(self, "О программе", 
                         "AES-128 Шифрование и Дешифрование\n"
                         "Версия 2.0\n\n"
                         "Программа для шифрования и дешифрования текста и файлов "
                         "с использованием алгоритма AES-128 в различных режимах.\n\n"
                         "© 2024")
    
    def mode_changed(self, index):
        """Обновляет интерфейс при смене режима шифрования"""
        mode = list(self.modes.keys())[index]
        
        # Обновляем доступность настроек IV в зависимости от режима
        if mode == "ECB":
            self.iv_entry.setEnabled(False)
            self.gen_iv_btn.setEnabled(False)
            self.iv_default_radio.setEnabled(False)
            self.iv_custom_radio.setEnabled(False)
            self.status_bar.showMessage("Выбран режим ECB: вектор инициализации (IV) не требуется")
        else:
            self.iv_default_radio.setEnabled(True)
            self.iv_custom_radio.setEnabled(True)
            if self.iv_custom_radio.isChecked():
                self.iv_entry.setEnabled(True)
            self.gen_iv_btn.setEnabled(True)
            self.status_bar.showMessage(f"Выбран режим {mode}: требуется вектор инициализации (IV)")
    
    def toggle_key_entry(self):
        if self.key_default_radio.isChecked():
            self.key_entry.setEnabled(False)
            self.key_entry.setText("MySecretKey12345")
        else:
            self.key_entry.setEnabled(True)
    
    def toggle_iv_entry(self):
        if self.iv_default_radio.isChecked():
            self.iv_entry.setEnabled(False)
            self.iv_entry.setText("InitVectorAES128")
        else:
            self.iv_entry.setEnabled(True)
    
    def generate_random_key(self):
        self.key_custom_radio.setChecked(True)
        self.key_entry.setEnabled(True)
        random_key = ''.join(chr(random.randint(33, 126)) for _ in range(16))
        self.key_entry.setText(random_key)
        self.status_bar.showMessage("Сгенерирован новый случайный ключ", 3000)
    
    def generate_random_iv(self):
        self.iv_custom_radio.setChecked(True)
        self.iv_entry.setEnabled(True)
        random_iv = ''.join(chr(random.randint(33, 126)) for _ in range(16))
        self.iv_entry.setText(random_iv)
        self.status_bar.showMessage("Сгенерирован новый случайный вектор инициализации", 3000)
    
    def toggle_input_mode(self):
        if self.text_radio.isChecked():
            self.input_text.setEnabled(True)
            self.status_bar.showMessage("Режим текстового ввода активирован")
        else:
            self.input_text.setEnabled(False)
            self.status_bar.showMessage("Режим файлового ввода активирован")
    
    def select_input_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Выбор файла", "", 
                                                "Текстовые файлы (*.txt);;Все файлы (*.*)")
        if file_path:
            self.input_file_entry.setText(file_path)
            self.file_radio.setChecked(True)
            self.toggle_input_mode()
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.input_text.setEnabled(True)
                self.input_text.setPlainText(content)
                self.input_text.setEnabled(False)
                self.status_bar.showMessage(f"Файл загружен: {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось прочитать файл: {str(e)}")
                self.status_bar.showMessage("Ошибка при чтении файла")
    
    def get_key_and_iv(self):
        # Получение ключа
        key = self.key_entry.text().encode('utf-8')
        if len(key) != 16:
            QMessageBox.critical(self, "Ошибка", "Ключ должен быть ровно 16 символов!")
            self.status_bar.showMessage("Ошибка: неправильная длина ключа")
            return None, None
        
        # Получение IV для режимов, которые его используют
        current_mode = list(self.modes.keys())[self.mode_tabs.currentIndex()]
        iv = None
        if current_mode != "ECB":  # ECB не использует IV
            iv = self.iv_entry.text().encode('utf-8')
            if len(iv) != 16:
                QMessageBox.critical(self, "Ошибка", "Вектор инициализации должен быть ровно 16 символов!")
                self.status_bar.showMessage("Ошибка: неправильная длина вектора инициализации")
                return None, None
        
        return key, iv
    
    def get_input_data(self):
        if self.text_radio.isChecked():
            return self.input_text.toPlainText().encode('utf-8')
        else:
            file_path = self.input_file_entry.text()
            if not file_path:
                QMessageBox.critical(self, "Ошибка", "Файл не выбран!")
                self.status_bar.showMessage("Ошибка: файл не выбран")
                return None
            try:
                with open(file_path, 'rb') as f:
                    return f.read()
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось прочитать файл: {str(e)}")
                self.status_bar.showMessage("Ошибка при чтении файла")
                return None
    
    def save_output(self):
        output_content = self.output_text.toPlainText().strip()
        if not output_content:
            QMessageBox.warning(self, "Предупреждение", "Нет данных для сохранения!")
            self.status_bar.showMessage("Предупреждение: нет данных для сохранения")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(self, "Сохранить результат", "", 
                                                 "Текстовые файлы (*.txt);;Двоичные файлы (*.bin);;Все файлы (*.*)")
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
                
                QMessageBox.information(self, "Сохранение", f"Файл успешно сохранен: {file_path}")
                self.status_bar.showMessage(f"Результат сохранен в {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить файл: {str(e)}")
                self.status_bar.showMessage("Ошибка при сохранении файла")
    
    def clear_fields(self):
        self.input_text.setEnabled(True)
        self.input_text.setPlainText("")
        
        if self.file_radio.isChecked():
            self.input_file_entry.setText("")
        
        self.output_text.setPlainText("")
        
        # Возвращаем поля ключа и IV к начальным значениям
        if self.key_default_radio.isChecked():
            self.key_entry.setText("MySecretKey12345")
        
        if self.iv_default_radio.isChecked():
            self.iv_entry.setText("InitVectorAES128")
        
        # Восстанавливаем начальное состояние интерфейса
        self.toggle_input_mode()
        self.status_bar.showMessage("Все поля очищены")
    
    def encrypt_data(self):
        key, iv = self.get_key_and_iv()
        if key is None:
            return
        
        data = self.get_input_data()
        if data is None:
            return
        
        try:
            current_mode = list(self.modes.keys())[self.mode_tabs.currentIndex()]
            mode_function = self.modes[current_mode]
            
            self.status_bar.showMessage(f"Шифрование данных в режиме {current_mode}...")
            encrypted_data = mode_function(data, key, iv, encrypt=True)
            
            # Вывод результата в шестнадцатеричном формате
            hex_output = encrypted_data.hex()
            
            # Форматируем вывод в удобном виде (группы по 2 символа)
            formatted_hex = ' '.join(hex_output[i:i+2] for i in range(0, len(hex_output), 2))
            
            self.output_text.setPlainText(formatted_hex)
            
            QMessageBox.information(self, "Шифрование", "Данные успешно зашифрованы!")
            self.status_bar.showMessage("Шифрование успешно завершено")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка шифрования", str(e))
            self.status_bar.showMessage(f"Ошибка шифрования: {str(e)}")
    
    def decrypt_data(self):
        key, iv = self.get_key_and_iv()
        if key is None:
            return
        
        # Получаем данные из поля ввода
        hex_input = self.input_text.toPlainText().strip()
        
        try:
            self.status_bar.showMessage("Дешифрование данных...")
            
            # Проверяем, является ли ввод шестнадцатеричной строкой
            if all(c in "0123456789abcdefABCDEF " for c in hex_input):
                # Преобразуем шестнадцатеричную строку в байты
                hex_input = hex_input.replace(" ", "")
                data = binascii.unhexlify(hex_input)
            else:
                data = self.get_input_data()
                if data is None:
                    return
            
            current_mode = list(self.modes.keys())[self.mode_tabs.currentIndex()]
            mode_function = self.modes[current_mode]
            
            decrypted_data = mode_function(data, key, iv, encrypt=False)
            
            # Выводим расшифрованный текст
            try:
                # Пытаемся декодировать как UTF-8
                text_output = decrypted_data.decode('utf-8')
                self.output_text.setPlainText(text_output)
            except UnicodeDecodeError:
                # Если не удается декодировать как текст, выводим как шестнадцатеричную строку
                hex_output = decrypted_data.hex()
                formatted_hex = ' '.join(hex_output[i:i+2] for i in range(0, len(hex_output), 2))
                self.output_text.setPlainText(formatted_hex)
            
            QMessageBox.information(self, "Дешифрование", "Данные успешно расшифрованы!")
            self.status_bar.showMessage("Дешифрование успешно завершено")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка дешифрования", str(e))
            self.status_bar.showMessage(f"Ошибка дешифрования: {str(e)}")
    
    # Все методы режимов шифрования остаются без изменений
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
                    QMessageBox.warning(self, "Предупреждение", f"Пропущен неполный блок данных длиной {len(block)} байт")
        
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

if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    window = AES128App()
    window.show()
    sys.exit(app.exec())
