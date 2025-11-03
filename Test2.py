import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import csv
import mimetypes
import base64
import sqlite3
from PIL import Image, ImageTk

class VulnerabilityScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Тестирование и нахождение уязвимостей ПО")
        self.files = []
        self.file_types = {}
        self.selected_file = None
        self.analysis_button = None
        self.edit_button = None
        self.last_analysis_result = None

        # Инициализация базы данных
        self.conn = sqlite3.connect("files.db")
        self.create_table()

        self.setup_style()
        self.build_ui()

    def create_table(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL,
                name TEXT NOT NULL
            )
        ''')
        self.conn.commit()

    def add_file_to_db(self, file_path):
        cursor = self.conn.cursor()
        filename = os.path.basename(file_path)
        cursor.execute("INSERT INTO files (path, name) VALUES (?, ?)", (file_path, filename))
        self.conn.commit()

    def get_files_from_db(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT path FROM files")
        rows = cursor.fetchall()
        return [row[0] for row in rows]

    def load_files_from_db(self):
        db_files = self.get_files_from_db()
        for file_path in db_files:
            if os.path.exists(file_path):
                self.files.append(file_path)
                self.file_listbox.insert(tk.END, file_path)
                self.determine_file_type(file_path)

    def setup_style(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')

        main_bg = "#0D0D0D"
        accent_color = "#00FF00"
        button_color = "#00b300"
        header_bg = "#222222"
        hover_bg = "#333333"

        self.root.configure(background=main_bg)
        self.style.configure("TLabel", background=main_bg, foreground=accent_color, font=("Consolas", 12))
        self.style.configure("TButton",
                             font=("Consolas", 12, "bold"),
                             padding=6,
                             background=button_color,
                             foreground="#FFFFFF")
        self.style.map("TButton",
                       background=[('active', hover_bg)],
                       foreground=[('active', "#FFFFFF")])
        self.style.configure("Treeview",
                             background="#1A1A1A",
                             foreground="white",
                             rowheight=25,
                             font=("Consolas", 11))
        self.style.configure("Treeview.Heading",
                             background=header_bg,
                             foreground=accent_color,
                             font=("Consolas", 12, "bold"))
        self.style.configure("Vertical.TScrollbar", background="#222222")
        self.style.configure("TFrame", background=main_bg)

    def build_ui(self):
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        label = ttk.Label(main_frame, text="🕵️‍♂️  Инструментарий для тестирования файлов", font=("Consolas", 16, "bold"))
        label.pack(pady=10)

        self.add_button = ttk.Button(main_frame, text="🚀 Добавить файл для сканирования", command=self.add_file)
        self.add_button.pack(pady=5, fill=tk.X)

        list_frame = ttk.Frame(main_frame)
        list_frame.pack(pady=5, fill=tk.BOTH, expand=True)

        self.file_listbox = tk.Listbox(list_frame, height=8, font=("Consolas", 11), borderwidth=1, relief="solid")
        self.file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0,5))
        self.file_listbox.bind('<<ListboxSelect>>', self.on_select)

        scrollbar_files = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.file_listbox.yview, style="Vertical.TScrollbar")
        scrollbar_files.pack(side=tk.RIGHT, fill=tk.Y)
        self.file_listbox.config(yscrollcommand=scrollbar_files.set)

        self.scan_button = ttk.Button(main_frame, text="🎯 Запустить сканирование", command=self.start_scan)
        self.scan_button.pack(pady=5, fill=tk.X)

        # Новая кнопка "Редактировать файл"
        self.edit_button = ttk.Button(main_frame, text="✏️ Редактировать файл", command=self.edit_file)
        self.edit_button.pack(pady=5)
        self.edit_button.config(state=tk.DISABLED)

        result_frame = ttk.Frame(main_frame)
        result_frame.pack(pady=10, fill=tk.BOTH, expand=True)

        result_label = ttk.Label(result_frame, text="🔍 Результаты анализа:", font=("Consolas", 14, "bold"))
        result_label.pack(anchor=tk.W)

        self.result_canvas = tk.Canvas(result_frame, bg="#0D0D0D", borderwidth=1, relief="solid")
        self.result_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.result_scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.result_canvas.yview, style="Vertical.TScrollbar")
        self.result_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.result_container = ttk.Frame(self.result_canvas)
        self.result_container.bind(
            "<Configure>",
            lambda e: self.result_canvas.configure(
                scrollregion=self.result_canvas.bbox("all")
            )
        )

        self.result_canvas.create_window((0, 0), window=self.result_container, anchor="nw")
        self.result_canvas.configure(yscrollcommand=self.result_scrollbar.set)

        self.update_analysis_button()

        # Загрузить файлы из базы при запуске
        self.load_files_from_db()

    def add_file(self):
        file_path = filedialog.askopenfilename(title="Выберите файл для анализа")
        if file_path:
            self.files.append(file_path)
            self.file_listbox.insert(tk.END, file_path)
            self.determine_file_type(file_path)
            self.add_file_to_db(file_path)  # Сохраняем в базу

            self.file_listbox.selection_clear(0, tk.END)
            self.file_listbox.selection_set(tk.END)
            self.on_select(None)

    def determine_file_type(self, file_path):
        extension = os.path.splitext(file_path)[1].lower()
        text_extensions = ['.txt', '.md', '.log', '.csv', '.json', '.xml', '.html', '.py', '.java', '.c', '.cpp', '.js']
        code_extensions = ['.py', '.java', '.c', '.cpp', '.js', '.rb', '.go', '.php']

        if extension in text_extensions:
            self.file_types[file_path] = 'text'
        elif extension in code_extensions:
            self.file_types[file_path] = 'code'
        else:
            self.file_types[file_path] = 'unknown'

    def start_scan(self):
        for widget in self.result_container.winfo_children():
            widget.destroy()

        if not self.files:
            messagebox.showwarning("Нет файлов", "Пожалуйста, добавьте хотя бы один файл для сканирования.")
            return

        self.show_status_message("🚧 Начинается сканирование...\n")
        # Проверка на вирусы и анализ
        for file in self.files:
            # Проверяем файл на вирусы (имитируем)
            is_infected = self.check_file_for_viruses(file)
            if is_infected:
                result_text = "Обнаружена потенциальная угроза!"
            else:
                result_text = "Уязвимостей не обнаружено."
            self.show_result_block(file, "Анализ файла...", result_text)
        self.show_status_message("✅ Сканы завершены.\n")

    def check_file_for_viruses(self, file_path):
        ext = os.path.splitext(file_path)[1].lower()
        if ext == '.exe':
            return True
        return False

    def show_status_message(self, message):
        label = ttk.Label(self.result_container, text=message, foreground="#00FF00", font=("Consolas", 11))
        label.pack(anchor=tk.W, pady=2, padx=5)

    def show_result_block(self, filename, analysis, vulnerabilities):
        frame = ttk.Frame(self.result_container, relief="ridge", borderwidth=1, padding=8)
        frame.pack(fill=tk.X, pady=4, padx=5)

        filename_label = ttk.Label(frame, text=os.path.basename(filename),
                                   font=("Consolas", 12, "bold"),
                                   background="#0D0D0D", foreground="#00FF00")
        filename_label.pack(anchor=tk.W)

        analysis_label = ttk.Label(frame, text=analysis,
                                   font=("Consolas", 11),
                                   background="#0D0D0D", foreground="#FFFFFF")
        analysis_label.pack(anchor=tk.W, pady=2)

        vuln_label = ttk.Label(frame, text=vulnerabilities,
                               font=("Consolas", 11),
                               foreground="#FF00FF", background="#0D0D0D")
        vuln_label.pack(anchor=tk.W, pady=2)

    def on_select(self, event):
        selection = self.file_listbox.curselection()
        if selection:
            index = selection[0]
            self.selected_file = self.files[index]
            self.update_analysis_button()
            self.update_edit_button()
        else:
            self.selected_file = None
            self.update_edit_button()

    def update_analysis_button(self):
        if hasattr(self, 'analysis_button') and self.analysis_button:
            self.analysis_button.destroy()
        self.analysis_button = ttk.Button(
            self.root,
            text="📝 Анализ",
            command=lambda: self.show_analysis_or_content(self.selected_file)
        )
        self.analysis_button.pack(pady=5)

    def update_edit_button(self):
        if self.selected_file:
            mime_type, _ = mimetypes.guess_type(self.selected_file)
            ext = os.path.splitext(self.selected_file)[1].lower()
            if mime_type and (mime_type.startswith('text') or ext == '.csv'):
                self.edit_button.config(state=tk.NORMAL)
            else:
                self.edit_button.config(state=tk.DISABLED)
        else:
            self.edit_button.config(state=tk.DISABLED)

    def edit_file(self):
        if not self.selected_file:
            messagebox.showwarning("Нет файла", "Выберите файл для редактирования.")
            return

        ext = os.path.splitext(self.selected_file)[1].lower()
        mime_type, _ = mimetypes.guess_type(self.selected_file)

        if mime_type and (mime_type.startswith('text') or ext == '.csv'):
            try:
                with open(self.selected_file, 'r', encoding='utf-8') as f:
                    content = f.read()
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось открыть файл: {e}")
                return

            editor_win = tk.Toplevel(self.root)
            editor_win.title(f"Редактирование файла: {os.path.basename(self.selected_file)}")
            editor_win.geometry("900x600")
            editor_win.configure(background="#0D0D0D")

            text_widget = tk.Text(editor_win, wrap=tk.WORD, font=("Consolas", 11), bg="#000000", fg="#00FF00")
            text_widget.insert(tk.END, content)
            text_widget.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
            text_widget.focus_set()  # Устанавливаем фокус
            text_widget.mark_set("insert", "1.0")  # Перемещаем курсор в начало

            # Горячие клавиши
            def undo(event=None):
                try:
                    text_widget.edit_undo()
                except:
                    pass
                return "break"

            def cut(event=None):
                text_widget.event_generate("<<Cut>>")
                return "break"

            def copy(event=None):
                text_widget.event_generate("<<Copy>>")
                return "break"

            def paste(event=None):
                text_widget.event_generate("<<Paste>>")
                return "break"

            def save_file():
                new_content = text_widget.get("1.0", tk.END)
                try:
                    with open(self.selected_file, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    messagebox.showinfo("Сохранено", "Файл успешно сохранен.")
                except Exception as e:
                    messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {e}")

            def download_file():
                save_path = filedialog.asksaveasfilename(
                    title="Сохранить файл как",
                    initialfile=os.path.basename(self.selected_file),
                    defaultextension=ext
                )
                if save_path:
                    try:
                        with open(save_path, 'w', encoding='utf-8') as f:
                            f.write(text_widget.get("1.0", tk.END))
                        messagebox.showinfo("Скачано", "Файл успешно сохранен.")
                    except Exception as e:
                        messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {e}")

            # Горячие клавиши
            text_widget.bind("<Control-z>", undo)
            text_widget.bind("<Control-x>", cut)
            text_widget.bind("<Control-c>", copy)
            text_widget.bind("<Control-v>", paste)

            # Также привязываем горячие клавиши к всему окну, чтобы они работали глобально при фокусе
            editor_win.bind_all("<Control-z>", undo)
            editor_win.bind_all("<Control-x>", cut)
            editor_win.bind_all("<Control-c>", copy)
            editor_win.bind_all("<Control-v>", paste)

            btn_frame = ttk.Frame(editor_win)
            btn_frame.pack(pady=5)

            save_btn = ttk.Button(btn_frame, text="💾 Сохранить", command=save_file)
            save_btn.pack(side=tk.LEFT, padx=5)

            download_btn = ttk.Button(btn_frame, text="📥 Скачать", command=download_file)
            download_btn.pack(side=tk.LEFT, padx=5)
        else:
            messagebox.showinfo("Недоступно", "Редактирование этого типа файла не поддерживается.")

    def show_analysis_or_content(self, file_path):
        if not file_path:
            messagebox.showwarning("Нет файла", "Выберите файл для анализа.")
            return

        mime_type, _ = mimetypes.guess_type(file_path)
        if mime_type:
            if mime_type.startswith('image'):
                self.show_image_metadata(file_path)
                return
            elif mime_type.startswith('video'):
                self.show_video_metadata(file_path)
                return

        # Для остальных — показываем полный контент без ограничения
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except:
            messagebox.showerror("Ошибка", "Невозможно открыть файл для отображения содержания.")
            return

        top = tk.Toplevel(self.root)
        top.title("Краткое содержание файла / Таблица")
        top.geometry("900x600")
        top.configure(background="#0D0D0D")

        if file_path.lower().endswith('.csv'):
            try:
                reader = csv.reader(content.splitlines())
                headers = next(reader)

                tree = ttk.Treeview(top, show='headings', style='Treeview')
                tree["columns"] = headers
                for header in headers:
                    tree.heading(header, text=header)
                    tree.column(header, width=120, anchor=tk.CENTER)

                for row in reader:
                    tree.insert("", tk.END, values=row)

                vsb = ttk.Scrollbar(top, orient="vertical", command=tree.yview)
                hsb = ttk.Scrollbar(top, orient="horizontal", command=tree.xview)
                tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

                tree.grid(row=0, column=0, sticky='nsew')
                vsb.grid(row=0, column=1, sticky='ns')
                hsb.grid(row=1, column=0, sticky='ew')

                top.grid_rowconfigure(0, weight=1)
                top.grid_columnconfigure(0, weight=1)
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось отобразить таблицу.\n{e}")
        else:
            # Полностью показываем содержимое файла
            text_widget = tk.Text(top, wrap=tk.WORD, font=("Consolas", 11), background="#000000", foreground="#00FF00")
            text_widget.insert(tk.END, content)
            text_widget.config(state=tk.NORMAL)
            text_widget.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

    def show_image_metadata(self, file_path):
        try:
            size_bytes = os.path.getsize(file_path)
            size_kb = size_bytes / 1024
            mime_type, _ = mimetypes.guess_type(file_path)
            meta_str = f"Файл: {os.path.basename(file_path)}\n"
            meta_str += f"Медиатип: {mime_type}\n"
            meta_str += f"Размер: {size_bytes} байт ({size_kb:.2f} KB)\n"
        except Exception as e:
            meta_str = f"Ошибка получения метаданных: {e}"

        top = tk.Toplevel(self.root)
        top.title("Метаданные изображения")
        top.geometry("600x400")
        top.configure(background="#0D0D0D")

        btn_binary = ttk.Button(top, text="Перевести в двоичный код", command=lambda: self.show_binary_content(file_path))
        btn_binary.pack(pady=2)

        btn_image_text = ttk.Button(top, text="Показать изображение в текстовом формате", command=lambda: self.show_image_as_text(file_path))
        btn_image_text.pack(pady=2)

        btn_show_image = ttk.Button(top, text="Показать изображение", command=lambda: self.show_image_graphic(file_path))
        btn_show_image.pack(pady=2)

        text_widget = tk.Text(top, wrap=tk.WORD, font=("Consolas", 11), background="#000000", foreground="#00FF00")
        text_widget.insert(tk.END, meta_str)
        text_widget.config(state=tk.NORMAL)
        text_widget.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

    def show_video_metadata(self, file_path):
        try:
            size_bytes = os.path.getsize(file_path)
            size_kb = size_bytes / 1024
            mime_type, _ = mimetypes.guess_type(file_path)
            meta_str = f"Файл видео: {os.path.basename(file_path)}\n"
            meta_str += f"Медиатип: {mime_type}\n"
            meta_str += f"Размер: {size_bytes} байт ({size_kb:.2f} KB)\n"
        except Exception as e:
            meta_str = f"Ошибка получения метаданных: {e}"

        top = tk.Toplevel(self.root)
        top.title("Метаданные видео")
        top.geometry("600x400")
        top.configure(background="#0D0D0D")

        btn_binary = ttk.Button(top, text="Перевести в двоичный код", command=lambda: self.show_binary_content(file_path))
        btn_binary.pack(pady=2)

        text_widget = tk.Text(top, wrap=tk.WORD, font=("Consolas", 11), background="#000000", foreground="#00FF00")
        text_widget.insert(tk.END, meta_str)
        text_widget.config(state=tk.NORMAL)
        text_widget.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

    def show_binary_content(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            binary_str = ''.join(f"{byte:08b}" for byte in content)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось прочитать файл: {e}")
            return

        top = tk.Toplevel(self.root)
        top.title("Двоичный код файла")
        top.geometry("800x600")
        top.configure(background="#0D0D0D")

        frame = ttk.Frame(top)
        frame.pack(fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        text_widget = tk.Text(frame, wrap=tk.NONE, font=("Consolas", 9), bg="#000000", fg="#00FF00",
                              yscrollcommand=scrollbar.set)
        line_length = 64
        lines = [binary_str[i:i+line_length] for i in range(0, len(binary_str), line_length)]
        text_widget.insert(tk.END, '\n'.join(lines))
        text_widget.config(state=tk.NORMAL)
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar.config(command=text_widget.yview)

    def show_image_as_text(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            encoded_str = base64.b64encode(content).decode('utf-8')
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось прочитать файл: {e}")
            return

        top = tk.Toplevel(self.root)
        top.title("Изображение в виде текста (Base64)")
        top.geometry("800x600")
        top.configure(background="#0D0D0D")

        frame = ttk.Frame(top)
        frame.pack(fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        text_widget = tk.Text(frame, wrap=tk.NONE, font=("Consolas", 8), bg="#000000", fg="#00FF00",
                              yscrollcommand=scrollbar.set)
        max_line_length = 80
        lines = [encoded_str[i:i+max_line_length] for i in range(0, len(encoded_str), max_line_length)]
        text_widget.insert(tk.END, '\n'.join(lines))
        text_widget.config(state=tk.NORMAL)
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar.config(command=text_widget.yview)

    def show_image_graphic(self, file_path):
        # Показываем изображение в графическом виде
        try:
            img = Image.open(file_path)
            img.thumbnail((800, 600))
            img_tk = ImageTk.PhotoImage(img)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось открыть изображение: {e}")
            return

        top = tk.Toplevel(self.root)
        top.title("Графическое изображение")
        top.geometry("800x600")
        top.configure(background="#0D0D0D")

        label = ttk.Label(top, image=img_tk)
        label.image = img_tk  # сохранить ссылку
        label.pack(expand=True, fill=tk.BOTH)

        btn_close = ttk.Button(top, text="Закрыть", command=top.destroy)
        btn_close.pack(pady=5)

    def show_image_ascii_art(self, file_path):
        # Создает ASCII-арт из изображения
        try:
            img = Image.open(file_path)
            img = img.convert('L')  # черно-белое изображение
            img.thumbnail((80, 40))
            pixels = list(img.getdata())
            chars = "@%#*+=-:. "
            new_width = img.width
            new_height = img.height
            ascii_str = ""
            for y in range(new_height):
                for x in range(new_width):
                    pixel = pixels[y * new_width + x]
                    ascii_char = chars[pixel * len(chars) // 256]
                    ascii_str += ascii_char
                ascii_str += "\n"
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось создать ASCII-арт: {e}")
            return

        top = tk.Toplevel(self.root)
        top.title("ASCII-арт изображения")
        top.geometry("800x600")
        top.configure(background="#0D0D0D")

        text_widget = tk.Text(top, wrap=tk.NONE, font=("Consolas", 6), bg="#000000", fg="#00FF00")
        text_widget.insert(tk.END, ascii_str)
        text_widget.config(state=tk.NORMAL)
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        btn_show_orig = ttk.Button(top, text="Показать оригинальное изображение", command=lambda: self.show_image_graphic(file_path))
        btn_show_orig.pack(pady=5)

    def on_closing(self):
        # Закрываем соединение с базой при закрытии приложения
        self.conn.close()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("1024x768")
    app = VulnerabilityScannerApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()