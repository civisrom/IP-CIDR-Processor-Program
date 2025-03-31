import os
import re
import sys
import ipaddress
import requests
import argparse
from urllib.parse import urlparse
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import yaml
from pathlib import Path
import platform

class IPCIDRProcessor:
    def __init__(self):
        self.ip_pattern_v4 = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b')
        self.ip_pattern_v6 = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}/\d{1,3}\b|(?:[0-9a-fA-F]{1,4}:){0,7}[0-9a-fA-F]{1,4}/\d{1,3}\b')
        self.config_file = 'ip_cidr_config.yaml'
        self.output_folder = 'output'
        self.default_config = {
            'masks': [
                {'name': 'default', 'prefix': '', 'suffix': '', 'separator': '\n'},
                {'name': 'clash', 'prefix': 'IP-CIDR,', 'suffix': ',no-resolve', 'separator': '\n'},
                {'name': 'custom', 'prefix': '[', 'suffix': ']', 'separator': ', '}
            ],
            'default_mask': 'default'
        }
        self.config = self.load_config()
        
        # Создаем папку для выходных файлов, если она не существует
        if not os.path.exists(self.output_folder):
            os.makedirs(self.output_folder)

    def load_config(self):
        """Загрузка конфигурации из файла или создание конфигурации по умолчанию"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f)
                return config
            except Exception as e:
                print(f"Ошибка при загрузке конфигурации: {e}")
                return self.default_config
        else:
            # Создаем файл конфигурации по умолчанию
            self.save_config(self.default_config)
            return self.default_config

    def save_config(self, config):
        """Сохранение конфигурации в файл"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
            return True
        except Exception as e:
            print(f"Ошибка при сохранении конфигурации: {e}")
            return False

    def extract_ips(self, text):
        """Извлечение IP-адресов в CIDR формате из текста"""
        ips_v4 = self.ip_pattern_v4.findall(text)
        ips_v6 = self.ip_pattern_v6.findall(text)
        return ips_v4 + ips_v6

    def process_file(self, file_path):
        """Обработка файла и извлечение IP-адресов"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            return self.extract_ips(content)
        except Exception as e:
            print(f"Ошибка при обработке файла {file_path}: {e}")
            return []

    def download_file(self, url):
        """Загрузка файла по URL"""
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            return response.text
        except Exception as e:
            print(f"Ошибка при загрузке файла по URL {url}: {e}")
            return ""

    def apply_mask(self, ips, mask_name):
        """Применение маски к IP-адресам"""
        mask = next((m for m in self.config['masks'] if m['name'] == mask_name), None)
        if not mask:
            print(f"Маска '{mask_name}' не найдена, используем маску по умолчанию")
            mask = next((m for m in self.config['masks'] if m['name'] == self.config['default_mask']), self.config['masks'][0])
        
        formatted_ips = [f"{mask['prefix']}{ip}{mask['suffix']}" for ip in ips]
        return mask['separator'].join(formatted_ips)

    def save_results(self, ips, output_file, mask_name=None):
        """Сохранение результатов в файл с применением маски"""
        if not ips:
            print("Нет IP-адресов для сохранения")
            return False
        
        if mask_name:
            content = self.apply_mask(ips, mask_name)
        else:
            content = '\n'.join(ips)
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Результаты сохранены в файл: {output_file}")
            return True
        except Exception as e:
            print(f"Ошибка при сохранении результатов: {e}")
            return False

    def add_mask(self, name, prefix, suffix, separator):
        """Добавление новой маски в конфигурацию"""
        new_mask = {
            'name': name,
            'prefix': prefix,
            'suffix': suffix,
            'separator': separator
        }
        
        # Проверяем, существует ли маска с таким именем
        for i, mask in enumerate(self.config['masks']):
            if mask['name'] == name:
                self.config['masks'][i] = new_mask
                break
        else:
            self.config['masks'].append(new_mask)
        
        return self.save_config(self.config)

    def get_masks(self):
        """Получение списка доступных масок"""
        return [mask['name'] for mask in self.config['masks']]

    def set_default_mask(self, mask_name):
        """Установка маски по умолчанию"""
        if mask_name in self.get_masks():
            self.config['default_mask'] = mask_name
            return self.save_config(self.config)
        return False

    def merge_files(self, file_paths, output_file, mask_name=None):
        """Объединение нескольких файлов в один"""
        all_ips = []
        for file_path in file_paths:
            ips = self.process_file(file_path)
            all_ips.extend(ips)
        
        # Удаляем дубликаты
        all_ips = list(set(all_ips))
        
        return self.save_results(all_ips, output_file, mask_name)


class ConsoleUI:
    def __init__(self, processor):
        self.processor = processor
    
    def clear_screen(self):
        """Очистка экрана консоли"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_header(self):
        """Вывод заголовка программы"""
        self.clear_screen()
        print("=" * 60)
        print("      IP CIDR Processor - Обработка IP-адресов в CIDR формате")
        print("=" * 60)
        print()
    
    def main_menu(self):
        """Главное меню программы"""
        while True:
            self.print_header()
            print("Главное меню:")
            print("1. Обработать локальные файлы")
            print("2. Скачать и обработать файлы по URL")
            print("3. Объединить файлы")
            print("4. Настройки масок")
            print("5. Выход")
            
            choice = input("\nВыберите действие (1-5): ")
            
            if choice == '1':
                self.process_local_files()
            elif choice == '2':
                self.process_url_files()
            elif choice == '3':
                self.merge_files()
            elif choice == '4':
                self.mask_settings()
            elif choice == '5':
                print("Выход из программы...")
                break
            else:
                print("Неверный выбор. Пожалуйста, введите число от 1 до 5.")
                input("Нажмите Enter для продолжения...")
    
    def process_local_files(self):
        """Обработка локальных файлов"""
        self.print_header()
        print("Обработка локальных файлов:")
        print("Укажите пути к файлам через запятую или пробел.")
        file_paths_input = input("Пути к файлам: ")
        
        file_paths = re.split(r'[,\s]+', file_paths_input.strip())
        file_paths = [path.strip() for path in file_paths if path.strip()]
        
        if not file_paths:
            print("Не указаны пути к файлам.")
            input("Нажмите Enter для продолжения...")
            return
        
        # Проверяем существование файлов
        valid_paths = []
        for path in file_paths:
            if os.path.exists(path) and os.path.isfile(path):
                valid_paths.append(path)
            else:
                print(f"Файл не найден: {path}")
        
        if not valid_paths:
            print("Нет доступных файлов для обработки.")
            input("Нажмите Enter для продолжения...")
            return
        
        print(f"\nНайдено {len(valid_paths)} файлов для обработки.")
        
        # Выбор маски
        masks = self.processor.get_masks()
        print("\nДоступные маски:")
        for i, mask in enumerate(masks):
            print(f"{i+1}. {mask}")
        
        mask_choice = input(f"\nВыберите маску (1-{len(masks)}) или оставьте пустым для маски по умолчанию: ")
        selected_mask = None
        if mask_choice.strip() and mask_choice.isdigit() and 1 <= int(mask_choice) <= len(masks):
            selected_mask = masks[int(mask_choice) - 1]
        else:
            selected_mask = self.processor.config['default_mask']
        
        print(f"Выбрана маска: {selected_mask}")
        
        # Обработка каждого файла
        all_ips = []
        for path in valid_paths:
            print(f"\nОбработка файла: {path}")
            ips = self.processor.process_file(path)
            if ips:
                print(f"Найдено {len(ips)} IP-адресов в CIDR формате.")
                all_ips.extend(ips)
            else:
                print("IP-адреса в CIDR формате не найдены.")
        
        # Удаляем дубликаты
        all_ips = list(set(all_ips))
        print(f"\nВсего уникальных IP-адресов: {len(all_ips)}")
        
        # Выбор способа сохранения
        print("\nВыберите способ сохранения:")
        print("1. Сохранить в один файл")
        print("2. Сохранить каждый исходный файл отдельно")
        save_choice = input("Выберите способ сохранения (1-2): ")
        
        if save_choice == '1':
            output_file = input("Введите имя выходного файла (по умолчанию: combined_ips.txt): ")
            if not output_file.strip():
                output_file = "combined_ips.txt"
            output_path = os.path.join(self.processor.output_folder, output_file)
            success = self.processor.save_results(all_ips, output_path, selected_mask)
            if success:
                print(f"Все IP-адреса сохранены в файл: {output_path}")
        elif save_choice == '2':
            for path in valid_paths:
                ips = self.processor.process_file(path)
                if ips:
                    base_name = os.path.basename(path)
                    output_file = f"processed_{base_name}"
                    output_path = os.path.join(self.processor.output_folder, output_file)
                    success = self.processor.save_results(ips, output_path, selected_mask)
                    if success:
                        print(f"IP-адреса из {path} сохранены в файл: {output_path}")
        else:
            print("Неверный выбор. Результаты не сохранены.")
        
        input("\nНажмите Enter для продолжения...")
    
    def process_url_files(self):
        """Обработка файлов по URL"""
        self.print_header()
        print("Обработка файлов по URL:")
        print("Укажите URL файлов через запятую или пробел.")
        urls_input = input("URL файлов: ")
        
        urls = re.split(r'[,\s]+', urls_input.strip())
        urls = [url.strip() for url in urls if url.strip()]
        
        if not urls:
            print("Не указаны URL файлов.")
            input("Нажмите Enter для продолжения...")
            return
        
        # Выбор маски
        masks = self.processor.get_masks()
        print("\nДоступные маски:")
        for i, mask in enumerate(masks):
            print(f"{i+1}. {mask}")
        
        mask_choice = input(f"\nВыберите маску (1-{len(masks)}) или оставьте пустым для маски по умолчанию: ")
        selected_mask = None
        if mask_choice.strip() and mask_choice.isdigit() and 1 <= int(mask_choice) <= len(masks):
            selected_mask = masks[int(mask_choice) - 1]
        else:
            selected_mask = self.processor.config['default_mask']
        
        print(f"Выбрана маска: {selected_mask}")
        
        # Обработка каждого URL
        all_ips = []
        for url in urls:
            print(f"\nЗагрузка файла по URL: {url}")
            content = self.processor.download_file(url)
            if content:
                ips = self.processor.extract_ips(content)
                if ips:
                    print(f"Найдено {len(ips)} IP-адресов в CIDR формате.")
                    all_ips.extend(ips)
                    
                    # Создаем имя файла на основе URL
                    url_parts = urlparse(url)
                    file_name = os.path.basename(url_parts.path)
                    if not file_name:
                        file_name = url_parts.netloc.replace('.', '_') + ".txt"
                    
                    output_file = f"url_{file_name}"
                    output_path = os.path.join(self.processor.output_folder, output_file)
                    self.processor.save_results(ips, output_path, selected_mask)
                    print(f"IP-адреса сохранены в файл: {output_path}")
                else:
                    print("IP-адреса в CIDR формате не найдены.")
            else:
                print("Не удалось загрузить файл.")
        
        # Удаляем дубликаты
        all_ips = list(set(all_ips))
        print(f"\nВсего уникальных IP-адресов: {len(all_ips)}")
        
        # Спрашиваем, нужно ли сохранить все IP в один файл
        save_all = input("\nСохранить все IP-адреса в один файл? (y/n): ")
        if save_all.lower() == 'y':
            output_file = input("Введите имя выходного файла (по умолчанию: combined_urls.txt): ")
            if not output_file.strip():
                output_file = "combined_urls.txt"
            output_path = os.path.join(self.processor.output_folder, output_file)
            success = self.processor.save_results(all_ips, output_path, selected_mask)
            if success:
                print(f"Все IP-адреса сохранены в файл: {output_path}")
        
        input("\nНажмите Enter для продолжения...")
    
    def merge_files(self):
        """Объединение файлов"""
        self.print_header()
        print("Объединение файлов:")
        print("Укажите пути к файлам через запятую или пробел.")
        file_paths_input = input("Пути к файлам: ")
        
        file_paths = re.split(r'[,\s]+', file_paths_input.strip())
        file_paths = [path.strip() for path in file_paths if path.strip()]
        
        if not file_paths:
            print("Не указаны пути к файлам.")
            input("Нажмите Enter для продолжения...")
            return
        
        # Проверяем существование файлов
        valid_paths = []
        for path in file_paths:
            if os.path.exists(path) and os.path.isfile(path):
                valid_paths.append(path)
            else:
                print(f"Файл не найден: {path}")
        
        if not valid_paths:
            print("Нет доступных файлов для объединения.")
            input("Нажмите Enter для продолжения...")
            return
        
        print(f"\nНайдено {len(valid_paths)} файлов для объединения.")
        
        # Выбор маски
        masks = self.processor.get_masks()
        print("\nДоступные маски:")
        for i, mask in enumerate(masks):
            print(f"{i+1}. {mask}")
        
        mask_choice = input(f"\nВыберите маску (1-{len(masks)}) или оставьте пустым для маски по умолчанию: ")
        selected_mask = None
        if mask_choice.strip() and mask_choice.isdigit() and 1 <= int(mask_choice) <= len(masks):
            selected_mask = masks[int(mask_choice) - 1]
        else:
            selected_mask = self.processor.config['default_mask']
        
        print(f"Выбрана маска: {selected_mask}")
        
        output_file = input("Введите имя выходного файла (по умолчанию: merged_ips.txt): ")
        if not output_file.strip():
            output_file = "merged_ips.txt"
        output_path = os.path.join(self.processor.output_folder, output_file)
        
        success = self.processor.merge_files(valid_paths, output_path, selected_mask)
        if success:
            print(f"Файлы объединены и сохранены в: {output_path}")
        
        input("\nНажмите Enter для продолжения...")
    
    def mask_settings(self):
        """Настройка масок"""
        while True:
            self.print_header()
            print("Настройка масок:")
            print("1. Просмотр доступных масок")
            print("2. Добавление/изменение маски")
            print("3. Установка маски по умолчанию")
            print("4. Возврат в главное меню")
            
            choice = input("\nВыберите действие (1-4): ")
            
            if choice == '1':
                # Просмотр масок
                self.print_header()
                print("Доступные маски:")
                masks = self.processor.config['masks']
                for i, mask in enumerate(masks):
                    default_mark = " (по умолчанию)" if mask['name'] == self.processor.config['default_mask'] else ""
                    print(f"\n{i+1}. {mask['name']}{default_mark}")
                    print(f"   Префикс: '{mask['prefix']}'")
                    print(f"   Суффикс: '{mask['suffix']}'")
                    separator_display = mask['separator'].replace('\n', '\\n')
                    print(f"   Разделитель: '{separator_display}'")
                    
                    # Пример применения маски
                    example_ip = "192.168.1.0/24"
                    example = f"{mask['prefix']}{example_ip}{mask['suffix']}"
                    print(f"   Пример: '{example}'")
                
                input("\nНажмите Enter для продолжения...")
            
            elif choice == '2':
                # Добавление/изменение маски
                self.print_header()
                print("Добавление/изменение маски:")
                
                # Показываем текущие маски
                print("\nТекущие маски:")
                masks = self.processor.get_masks()
                for i, mask in enumerate(masks):
                    print(f"{i+1}. {mask}")
                
                # Спрашиваем, хочет ли пользователь изменить существующую маску
                edit_existing = input("\nИзменить существующую маску? (y/n): ")
                
                if edit_existing.lower() == 'y':
                    mask_idx = input(f"Выберите маску для изменения (1-{len(masks)}): ")
                    if mask_idx.isdigit() and 1 <= int(mask_idx) <= len(masks):
                        name = masks[int(mask_idx) - 1]
                    else:
                        print("Неверный выбор. Операция отменена.")
                        input("Нажмите Enter для продолжения...")
                        continue
                else:
                    name = input("\nВведите имя новой маски: ")
                    if not name.strip():
                        print("Имя маски не может быть пустым. Операция отменена.")
                        input("Нажмите Enter для продолжения...")
                        continue
                
                prefix = input("Введите префикс (то, что будет перед IP): ")
                suffix = input("Введите суффикс (то, что будет после IP): ")
                
                separator_choice = input("\nВыберите разделитель:\n1. Новая строка\n2. Запятая и пробел\n3. Пользовательский\nВыбор (1-3): ")
                
                if separator_choice == '1':
                    separator = '\n'
                elif separator_choice == '2':
                    separator = ', '
                elif separator_choice == '3':
                    separator = input("Введите разделитель (\\n для новой строки): ")
                    separator = separator.replace('\\n', '\n')
                else:
                    print("Неверный выбор. Используется разделитель по умолчанию (новая строка).")
                    separator = '\n'
                
                success = self.processor.add_mask(name, prefix, suffix, separator)
                if success:
                    print(f"Маска '{name}' успешно {'изменена' if edit_existing.lower() == 'y' else 'добавлена'}.")
                else:
                    print(f"Ошибка при {'изменении' if edit_existing.lower() == 'y' else 'добавлении'} маски.")
                
                input("\nНажмите Enter для продолжения...")
            
            elif choice == '3':
                # Установка маски по умолчанию
                self.print_header()
                print("Установка маски по умолчанию:")
                
                masks = self.processor.get_masks()
                print("\nДоступные маски:")
                for i, mask in enumerate(masks):
                    default_mark = " (по умолчанию)" if mask == self.processor.config['default_mask'] else ""
                    print(f"{i+1}. {mask}{default_mark}")
                
                mask_idx = input(f"\nВыберите маску для установки по умолчанию (1-{len(masks)}): ")
                if mask_idx.isdigit() and 1 <= int(mask_idx) <= len(masks):
                    selected_mask = masks[int(mask_idx) - 1]
                    success = self.processor.set_default_mask(selected_mask)
                    if success:
                        print(f"Маска '{selected_mask}' установлена по умолчанию.")
                    else:
                        print("Ошибка при установке маски по умолчанию.")
                else:
                    print("Неверный выбор. Операция отменена.")
                
                input("\nНажмите Enter для продолжения...")
            
            elif choice == '4':
                # Возврат в главное меню
                break
            
            else:
                print("Неверный выбор. Пожалуйста, введите число от 1 до 4.")
                input("Нажмите Enter для продолжения...")


class GUI:
    def __init__(self, processor):
        self.processor = processor
        self.root = tk.Tk()
        self.root.title("IP CIDR Processor")
        self.root.geometry("800x600")
        self.selected_files = []
        self.selected_urls = []
        
        # Создаем вкладки
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Вкладки
        self.tab_local = ttk.Frame(self.notebook)
        self.tab_url = ttk.Frame(self.notebook)
        self.tab_merge = ttk.Frame(self.notebook)
        self.tab_settings = ttk.Frame(self.notebook)
        
        self.notebook.add(self.tab_local, text="Локальные файлы")
        self.notebook.add(self.tab_url, text="URL файлы")
        self.notebook.add(self.tab_merge, text="Объединение")
        self.notebook.add(self.tab_settings, text="Настройки")
        
        # Создаем интерфейс для каждой вкладки
        self.setup_local_tab()
        self.setup_url_tab()
        self.setup_merge_tab()
        self.setup_settings_tab()
    
    def setup_local_tab(self):
        """Настройка вкладки для обработки локальных файлов"""
        # Верхняя часть - выбор файлов
        frame_files = ttk.LabelFrame(self.tab_local, text="Выбор файлов")
        frame_files.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Список файлов
        frame_list = ttk.Frame(frame_files)
        frame_list.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Полоса прокрутки
        scrollbar = ttk.Scrollbar(frame_list)
        scrollbar.pack(side='right', fill='y')
        
        # Список файлов
        self.listbox_files = tk.Listbox(frame_list, yscrollcommand=scrollbar.set)
        self.listbox_files.pack(side='left', fill='both', expand=True)
        scrollbar.config(command=self.listbox_files.yview)
        
        # Кнопки для управления файлами
        frame_buttons = ttk.Frame(frame_files)
        frame_buttons.pack(fill='x', pady=5)
        
        btn_add_files = ttk.Button(frame_buttons, text="Добавить файлы", command=self.add_local_files)
        btn_add_files.pack(side='left', padx=5)
        
        btn_clear_files = ttk.Button(frame_buttons, text="Очистить список", command=self.clear_local_files)
        btn_clear_files.pack(side='left', padx=5)
        
        # Настройки обработки
        frame_settings = ttk.LabelFrame(self.tab_local, text="Настройки обработки")
        frame_settings.pack(fill='x', padx=10, pady=5)
        
        # Выбор маски
        frame_mask = ttk.Frame(frame_settings)
        frame_mask.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(frame_mask, text="Маска:").pack(side='left', padx=5)
        
        self.combo_local_mask = ttk.Combobox(frame_mask, values=self.processor.get_masks(), state="readonly")
        self.combo_local_mask.pack(side='left', fill='x', expand=True, padx=5)
        self.combo_local_mask.set(self.processor.config['default_mask'])
        
        # Выбор способа сохранения
        frame_save = ttk.Frame(frame_settings)
        frame_save.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(frame_save, text="Сохранение:").pack(side='left', padx=5)
        
        self.var_save_mode = tk.StringVar(value="combined")
        rb_combined = ttk.Radiobutton(frame_save, text="В один файл", variable=self.var_save_mode, value="combined")
        rb_combined.pack(side='left', padx=5)
        
        # Continuing from where the code left off

        rb_separate = ttk.Radiobutton(frame_save, text="Отдельными файлами", variable=self.var_save_mode, value="separate")
        rb_separate.pack(side='left', padx=5)
        
        # Имя выходного файла
        frame_output = ttk.Frame(frame_settings)
        frame_output.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(frame_output, text="Имя выходного файла:").pack(side='left', padx=5)
        
        self.entry_local_output = ttk.Entry(frame_output)
        self.entry_local_output.pack(side='left', fill='x', expand=True, padx=5)
        self.entry_local_output.insert(0, "combined_ips.txt")
        
        # Кнопка обработки
        btn_process = ttk.Button(self.tab_local, text="Обработать файлы", command=self.process_local_files)
        btn_process.pack(pady=10)
        
        # Лог обработки
        frame_log = ttk.LabelFrame(self.tab_local, text="Лог обработки")
        frame_log.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Полоса прокрутки для лога
        scrollbar_log = ttk.Scrollbar(frame_log)
        scrollbar_log.pack(side='right', fill='y')
        
        # Текстовое поле для лога
        self.text_local_log = tk.Text(frame_log, yscrollcommand=scrollbar_log.set, height=10)
        self.text_local_log.pack(side='left', fill='both', expand=True)
        scrollbar_log.config(command=self.text_local_log.yview)
    
    def setup_url_tab(self):
        """Настройка вкладки для обработки файлов по URL"""
        # Верхняя часть - ввод URL
        frame_urls = ttk.LabelFrame(self.tab_url, text="Ввод URL")
        frame_urls.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Список URL
        frame_list = ttk.Frame(frame_urls)
        frame_list.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Полоса прокрутки
        scrollbar = ttk.Scrollbar(frame_list)
        scrollbar.pack(side='right', fill='y')
        
        # Список URL
        self.listbox_urls = tk.Listbox(frame_list, yscrollcommand=scrollbar.set)
        self.listbox_urls.pack(side='left', fill='both', expand=True)
        scrollbar.config(command=self.listbox_urls.yview)
        
        # Добавление URL
        frame_add_url = ttk.Frame(frame_urls)
        frame_add_url.pack(fill='x', pady=5)
        
        self.entry_url = ttk.Entry(frame_add_url)
        self.entry_url.pack(side='left', fill='x', expand=True, padx=5)
        
        btn_add_url = ttk.Button(frame_add_url, text="Добавить URL", command=self.add_url)
        btn_add_url.pack(side='left', padx=5)
        
        # Кнопки для управления URL
        frame_buttons = ttk.Frame(frame_urls)
        frame_buttons.pack(fill='x', pady=5)
        
        btn_remove_url = ttk.Button(frame_buttons, text="Удалить выбранный", command=self.remove_url)
        btn_remove_url.pack(side='left', padx=5)
        
        btn_clear_urls = ttk.Button(frame_buttons, text="Очистить список", command=self.clear_urls)
        btn_clear_urls.pack(side='left', padx=5)
        
        # Настройки обработки
        frame_settings = ttk.LabelFrame(self.tab_url, text="Настройки обработки")
        frame_settings.pack(fill='x', padx=10, pady=5)
        
        # Выбор маски
        frame_mask = ttk.Frame(frame_settings)
        frame_mask.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(frame_mask, text="Маска:").pack(side='left', padx=5)
        
        self.combo_url_mask = ttk.Combobox(frame_mask, values=self.processor.get_masks(), state="readonly")
        self.combo_url_mask.pack(side='left', fill='x', expand=True, padx=5)
        self.combo_url_mask.set(self.processor.config['default_mask'])
        
        # Выбор способа сохранения
        frame_save = ttk.Frame(frame_settings)
        frame_save.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(frame_save, text="Сохранение:").pack(side='left', padx=5)
        
        self.var_url_save_mode = tk.StringVar(value="separate")
        rb_combined = ttk.Radiobutton(frame_save, text="В один файл", variable=self.var_url_save_mode, value="combined")
        rb_combined.pack(side='left', padx=5)
        
        rb_separate = ttk.Radiobutton(frame_save, text="Отдельными файлами", variable=self.var_url_save_mode, value="separate")
        rb_separate.pack(side='left', padx=5)
        
        # Имя выходного файла
        frame_output = ttk.Frame(frame_settings)
        frame_output.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(frame_output, text="Имя выходного файла:").pack(side='left', padx=5)
        
        self.entry_url_output = ttk.Entry(frame_output)
        self.entry_url_output.pack(side='left', fill='x', expand=True, padx=5)
        self.entry_url_output.insert(0, "combined_urls.txt")
        
        # Кнопка обработки
        btn_process = ttk.Button(self.tab_url, text="Обработать URL", command=self.process_urls)
        btn_process.pack(pady=10)
        
        # Лог обработки
        frame_log = ttk.LabelFrame(self.tab_url, text="Лог обработки")
        frame_log.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Полоса прокрутки для лога
        scrollbar_log = ttk.Scrollbar(frame_log)
        scrollbar_log.pack(side='right', fill='y')
        
        # Текстовое поле для лога
        self.text_url_log = tk.Text(frame_log, yscrollcommand=scrollbar_log.set, height=10)
        self.text_url_log.pack(side='left', fill='both', expand=True)
        scrollbar_log.config(command=self.text_url_log.yview)
    
    def setup_merge_tab(self):
        """Настройка вкладки для объединения файлов"""
        # Верхняя часть - выбор файлов
        frame_files = ttk.LabelFrame(self.tab_merge, text="Выбор файлов для объединения")
        frame_files.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Список файлов
        frame_list = ttk.Frame(frame_files)
        frame_list.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Полоса прокрутки
        scrollbar = ttk.Scrollbar(frame_list)
        scrollbar.pack(side='right', fill='y')
        
        # Список файлов
        self.listbox_merge_files = tk.Listbox(frame_list, yscrollcommand=scrollbar.set)
        self.listbox_merge_files.pack(side='left', fill='both', expand=True)
        scrollbar.config(command=self.listbox_merge_files.yview)
        
        # Кнопки для управления файлами
        frame_buttons = ttk.Frame(frame_files)
        frame_buttons.pack(fill='x', pady=5)
        
        btn_add_files = ttk.Button(frame_buttons, text="Добавить файлы", command=self.add_merge_files)
        btn_add_files.pack(side='left', padx=5)
        
        btn_clear_files = ttk.Button(frame_buttons, text="Очистить список", command=self.clear_merge_files)
        btn_clear_files.pack(side='left', padx=5)
        
        # Настройки объединения
        frame_settings = ttk.LabelFrame(self.tab_merge, text="Настройки объединения")
        frame_settings.pack(fill='x', padx=10, pady=5)
        
        # Выбор маски
        frame_mask = ttk.Frame(frame_settings)
        frame_mask.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(frame_mask, text="Маска:").pack(side='left', padx=5)
        
        self.combo_merge_mask = ttk.Combobox(frame_mask, values=self.processor.get_masks(), state="readonly")
        self.combo_merge_mask.pack(side='left', fill='x', expand=True, padx=5)
        self.combo_merge_mask.set(self.processor.config['default_mask'])
        
        # Имя выходного файла
        frame_output = ttk.Frame(frame_settings)
        frame_output.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(frame_output, text="Имя выходного файла:").pack(side='left', padx=5)
        
        self.entry_merge_output = ttk.Entry(frame_output)
        self.entry_merge_output.pack(side='left', fill='x', expand=True, padx=5)
        self.entry_merge_output.insert(0, "merged_ips.txt")
        
        # Кнопка объединения
        btn_merge = ttk.Button(self.tab_merge, text="Объединить файлы", command=self.merge_selected_files)
        btn_merge.pack(pady=10)
        
        # Лог обработки
        frame_log = ttk.LabelFrame(self.tab_merge, text="Лог обработки")
        frame_log.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Полоса прокрутки для лога
        scrollbar_log = ttk.Scrollbar(frame_log)
        scrollbar_log.pack(side='right', fill='y')
        
        # Текстовое поле для лога
        self.text_merge_log = tk.Text(frame_log, yscrollcommand=scrollbar_log.set, height=10)
        self.text_merge_log.pack(side='left', fill='both', expand=True)
        scrollbar_log.config(command=self.text_merge_log.yview)
    
    def setup_settings_tab(self):
        """Настройка вкладки для настроек масок"""
        # Верхняя часть - список масок
        frame_masks = ttk.LabelFrame(self.tab_settings, text="Доступные маски")
        frame_masks.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Список масок
        frame_list = ttk.Frame(frame_masks)
        frame_list.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Полоса прокрутки
        scrollbar = ttk.Scrollbar(frame_list)
        scrollbar.pack(side='right', fill='y')
        
        # Список масок
        self.listbox_masks = tk.Listbox(frame_list, yscrollcommand=scrollbar.set)
        self.listbox_masks.pack(side='left', fill='both', expand=True)
        scrollbar.config(command=self.listbox_masks.yview)
        
        # Обновление списка масок
        self.update_mask_list()
        
        # Кнопки для управления масками
        frame_buttons = ttk.Frame(frame_masks)
        frame_buttons.pack(fill='x', pady=5)
        
        btn_edit_mask = ttk.Button(frame_buttons, text="Редактировать маску", command=self.edit_mask)
        btn_edit_mask.pack(side='left', padx=5)
        
        btn_set_default = ttk.Button(frame_buttons, text="Установить по умолчанию", command=self.set_default_mask)
        btn_set_default.pack(side='left', padx=5)
        
        # Добавление/изменение маски
        frame_edit = ttk.LabelFrame(self.tab_settings, text="Добавление/изменение маски")
        frame_edit.pack(fill='x', padx=10, pady=5)
        
        # Имя маски
        frame_name = ttk.Frame(frame_edit)
        frame_name.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(frame_name, text="Имя маски:").pack(side='left', padx=5)
        
        self.entry_mask_name = ttk.Entry(frame_name)
        self.entry_mask_name.pack(side='left', fill='x', expand=True, padx=5)
        
        # Префикс
        frame_prefix = ttk.Frame(frame_edit)
        frame_prefix.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(frame_prefix, text="Префикс:").pack(side='left', padx=5)
        
        self.entry_mask_prefix = ttk.Entry(frame_prefix)
        self.entry_mask_prefix.pack(side='left', fill='x', expand=True, padx=5)
        
        # Суффикс
        frame_suffix = ttk.Frame(frame_edit)
        frame_suffix.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(frame_suffix, text="Суффикс:").pack(side='left', padx=5)
        
        self.entry_mask_suffix = ttk.Entry(frame_suffix)
        self.entry_mask_suffix.pack(side='left', fill='x', expand=True, padx=5)
        
        # Разделитель
        frame_separator = ttk.Frame(frame_edit)
        frame_separator.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(frame_separator, text="Разделитель:").pack(side='left', padx=5)
        
        self.var_separator = tk.StringVar(value="newline")
        rb_newline = ttk.Radiobutton(frame_separator, text="Новая строка", variable=self.var_separator, value="newline")
        rb_newline.pack(side='left', padx=5)
        
        rb_comma = ttk.Radiobutton(frame_separator, text="Запятая и пробел", variable=self.var_separator, value="comma")
        rb_comma.pack(side='left', padx=5)
        
        rb_custom = ttk.Radiobutton(frame_separator, text="Свой:", variable=self.var_separator, value="custom")
        rb_custom.pack(side='left', padx=5)
        
        self.entry_separator = ttk.Entry(frame_separator, width=10)
        self.entry_separator.pack(side='left', padx=5)
        
        # Пример
        frame_example = ttk.Frame(frame_edit)
        frame_example.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(frame_example, text="Пример:").pack(side='left', padx=5)
        
        self.label_example = ttk.Label(frame_example, text="")
        self.label_example.pack(side='left', fill='x', expand=True, padx=5)
        
        # Привязываем обновление примера к изменению полей
        self.entry_mask_prefix.bind("<KeyRelease>", self.update_example)
        self.entry_mask_suffix.bind("<KeyRelease>", self.update_example)
        
        # Кнопки
        frame_mask_buttons = ttk.Frame(frame_edit)
        frame_mask_buttons.pack(fill='x', pady=5)
        
        btn_add_mask = ttk.Button(frame_mask_buttons, text="Добавить маску", command=self.add_mask)
        btn_add_mask.pack(side='left', padx=5)
        
        btn_clear_fields = ttk.Button(frame_mask_buttons, text="Очистить поля", command=self.clear_mask_fields)
        btn_clear_fields.pack(side='left', padx=5)
    
    def start(self):
        """Запуск графического интерфейса"""
        self.root.mainloop()
    
    # Методы для вкладки локальных файлов
    def add_local_files(self):
        """Добавление локальных файлов"""
        files = filedialog.askopenfilenames(title="Выберите файлы")
        if files:
            for file in files:
                if file not in self.selected_files:
                    self.selected_files.append(file)
                    self.listbox_files.insert(tk.END, file)
    
    def clear_local_files(self):
        """Очистка списка локальных файлов"""
        self.selected_files = []
        self.listbox_files.delete(0, tk.END)
    
    def process_local_files(self):
        """Обработка локальных файлов"""
        if not self.selected_files:
            messagebox.showwarning("Предупреждение", "Не выбраны файлы для обработки")
            return
        
        # Очищаем лог
        self.text_local_log.delete(1.0, tk.END)
        
        # Получаем настройки
        selected_mask = self.combo_local_mask.get()
        save_mode = self.var_save_mode.get()
        output_file = self.entry_local_output.get()
        
        if not output_file:
            output_file = "combined_ips.txt"
        
        # Обрабатываем файлы
        all_ips = []
        for file_path in self.selected_files:
            self.log_local(f"Обработка файла: {file_path}")
            ips = self.processor.process_file(file_path)
            if ips:
                self.log_local(f"Найдено {len(ips)} IP-адресов в CIDR формате")
                all_ips.extend(ips)
                
                if save_mode == "separate":
                    base_name = os.path.basename(file_path)
                    output_path = os.path.join(self.processor.output_folder, f"processed_{base_name}")
                    success = self.processor.save_results(ips, output_path, selected_mask)
                    if success:
                        self.log_local(f"Результаты сохранены в файл: {output_path}")
                    else:
                        self.log_local(f"Ошибка при сохранении в файл: {output_path}")
            else:
                self.log_local(f"IP-адреса в CIDR формате не найдены")
        
        # Удаляем дубликаты
        all_ips = list(set(all_ips))
        self.log_local(f"\nВсего уникальных IP-адресов: {len(all_ips)}")
        
        # Сохраняем в один файл, если нужно
        if save_mode == "combined" and all_ips:
            output_path = os.path.join(self.processor.output_folder, output_file)
            success = self.processor.save_results(all_ips, output_path, selected_mask)
            if success:
                self.log_local(f"Все IP-адреса сохранены в файл: {output_path}")
            else:
                self.log_local(f"Ошибка при сохранении в файл: {output_path}")
        
        self.log_local("\nОбработка завершена")
    
    def log_local(self, message):
        """Добавление сообщения в лог локальных файлов"""
        self.text_local_log.insert(tk.END, message + "\n")
        self.text_local_log.see(tk.END)
    
    # Методы для вкладки URL
    def add_url(self):
        """Добавление URL"""
        url = self.entry_url.get().strip()
        if url:
            if url not in self.selected_urls:
                self.selected_urls.append(url)
                self.listbox_urls.insert(tk.END, url)
            self.entry_url.delete(0, tk.END)
    
    def remove_url(self):
        """Удаление выбранного URL"""
        selection = self.listbox_urls.curselection()
        if selection:
            index = selection[0]
            url = self.listbox_urls.get(index)
            self.selected_urls.remove(url)
            self.listbox_urls.delete(index)
    
    def clear_urls(self):
        """Очистка списка URL"""
        self.selected_urls = []
        self.listbox_urls.delete(0, tk.END)
    
    def process_urls(self):
        """Обработка URL"""
        if not self.selected_urls:
            messagebox.showwarning("Предупреждение", "Не указаны URL для обработки")
            return
        
        # Очищаем лог
        self.text_url_log.delete(1.0, tk.END)
        
        # Получаем настройки
        selected_mask = self.combo_url_mask.get()
        save_mode = self.var_url_save_mode.get()
        output_file = self.entry_url_output.get()
        
        if not output_file:
            output_file = "combined_urls.txt"
        
        # Обрабатываем URL
        all_ips = []
        for url in self.selected_urls:
            self.log_url(f"Загрузка файла по URL: {url}")
            content = self.processor.download_file(url)
            if content:
                ips = self.processor.extract_ips(content)
                if ips:
                    self.log_url(f"Найдено {len(ips)} IP-адресов в CIDR формате")
                    all_ips.extend(ips)
                    
                    if save_mode == "separate":
                        # Создаем имя файла на основе URL
                        url_parts = urlparse(url)
                        file_name = os.path.basename(url_parts.path)
                        if not file_name:
                            file_name = url_parts.netloc.replace('.', '_') + ".txt"
                        
                        output_path = os.path.join(self.processor.output_folder, f"url_{file_name}")
                        success = self.processor.save_results(ips, output_path, selected_mask)
                        if success:
                            self.log_url(f"Результаты сохранены в файл: {output_path}")
                        else:
                            self.log_url(f"Ошибка при сохранении в файл: {output_path}")
                else:
                    self.log_url(f"IP-адреса в CIDR формате не найдены")
            else:
                self.log_url(f"Ошибка при загрузке файла")
        
        # Удаляем дубликаты
        all_ips = list(set(all_ips))
        self.log_url(f"\nВсего уникальных IP-адресов: {len(all_ips)}")
        
        # Сохраняем в один файл, если нужно
        if save_mode == "combined" and all_ips:
            output_path = os.path.join(self.processor.output_folder, output_file)
            success = self.processor.save_results(all_ips, output_path, selected_mask)
            if success:
                self.log_url(f"Все IP-адреса сохранены в файл: {output_path}")
            else:
                self.log_url(f"Ошибка при сохранении в файл: {output_path}")
        
        self.log_url("\nОбработка завершена")
    
    def log_url(self, message):
        """Добавление сообщения в лог URL"""
        self.text_url_log.insert(tk.END, message + "\n")
        self.text_url_log.see(tk.END)
    
    # Методы для вкладки объединения
    def add_merge_files(self):
        """Добавление файлов для объединения"""
        files = filedialog.askopenfilenames(title="Выберите файлы для объединения")
        for file in files:
            if file not in [self.listbox_merge_files.get(i) for i in range(self.listbox_merge_files.size())]:
                self.listbox_merge_files.insert(tk.END, file)
    
    def clear_merge_files(self):
        """Очистка списка файлов для объединения"""
        self.listbox_merge_files.delete(0, tk.END)
    
    def merge_selected_files(self):
        """Объединение выбранных файлов"""
        files = [self.listbox_merge_files.get(i) for i in range(self.listbox_merge_files.size())]
        
        if not files:
            messagebox.showwarning("Предупреждение", "Не выбраны файлы для объединения")
            return
        
        # Очищаем лог
        self.text_merge_log.delete(1.0, tk.END)
        
        # Получаем настройки
        selected_mask = self.combo_merge_mask.get()
        output_file = self.entry_merge_output.get()
        
        if not output_file:
            output_file = "merged_ips.txt"
        
        output_path = os.path.join(self.processor.output_folder, output_file)
        
        self.log_merge(f"Объединение {len(files)} файлов...")
        
        success = self.processor.merge_files(files, output_path, selected_mask)
        if success:
            self.log_merge(f"Файлы успешно объединены и сохранены в: {output_path}")
        else:
            self.log_merge("Ошибка при объединении файлов")
        
        self.log_merge("\nОбъединение завершено")
    
    def log_merge(self, message):
        """Добавление сообщения в лог объединения"""
        self.text_merge_log.insert(tk.END, message + "\n")
        self.text_merge_log.see(tk.END)
    
    # Методы для вкладки настроек
    def update_mask_list(self):
        """Обновление списка масок"""
        self.listbox_masks.delete(0, tk.END)
        
        masks = self.processor.config['masks']
        for mask in masks:
            default_mark = " (по умолчанию)" if mask['name'] == self.processor.config['default_mask'] else ""
            self.listbox_masks.insert(tk.END, f"{mask['name']}{default_mark}")
    
    def edit_mask(self):
        """Редактирование выбранной маски"""
        selection = self.listbox_masks.curselection()
        if not selection:
            messagebox.showwarning("Предупреждение", "Не выбрана маска для редактирования")
            return
        
        index = selection[0]
        mask_name = self.listbox_masks.get(index).split(" (по умолчанию)")[0]
        
        # Находим маску в конфигурации
        mask = next((m for m in self.processor.config['masks'] if m['name'] == mask_name), None)
        if not mask:
            messagebox.showerror("Ошибка", "Маска не найдена")
            return
        
        # Заполняем поля данными маски
        self.entry_mask_name.delete(0, tk.END)
        self.entry_mask_name.insert(0, mask['name'])
        
        self.entry_mask_prefix.delete(0, tk.END)
        self.entry_mask_prefix.insert(0, mask['prefix'])
        
        self.entry_mask_suffix.delete(0, tk.END)
        self.entry_mask_suffix.insert(0, mask['suffix'])
        
        # Устанавливаем разделитель
        if mask['separator'] == '\n':
            self.var_separator.set("newline")
        elif mask['separator'] == ', ':
            self.var_separator.set("comma")
        else:
            self.var_separator.set("custom")
            self.entry_separator.delete(0, tk.END)
            self.entry_separator.insert(0, mask['separator'])
        
        # Обновляем пример
        self.update_example()
    
    def set_default_mask(self):
        """Установка выбранной маски по умолчанию"""
        selection = self.listbox_masks.curselection()
        if not selection:
            messagebox.showwarning("Предупреждение", "Не выбрана маска")
            return
        
        index = selection[0]
        mask_name = self.listbox_masks.get(index).split(" (по умолчанию)")[0]
        
        if self.processor.set_default_mask(mask_name):
            messagebox.showinfo("Успех", f"Маска '{mask_name}' установлена по умолчанию")
            self.update_mask_list()
        else:
            messagebox.showerror("Ошибка", "Не удалось установить маску по умолчанию")
    
    def update_example(self, event=None):
        """Обновление примера маски"""
        prefix = self.entry_mask_prefix.get()
        suffix = self.entry_mask_suffix.get()
        example_ip = "192.168.1.0/24"
        
        self.label_example.config(text=f"{prefix}{example_ip}{suffix}")
    
    def add_mask(self):
        """Добавление новой маски"""
        name = self.entry_mask_name.get().strip()
        prefix = self.entry_mask_prefix.get()
        suffix = self.entry_mask_suffix.get()
        
        if not name:
            messagebox.showwarning("Предупреждение", "Имя маски не может быть пустым")
            return
        
        # Получаем разделитель
        separator_type = self.var_separator.get()
        if separator_type == "newline":
            separator = '\n'
        elif separator_type == "comma":
            separator = ', '
        else:
            separator = self.entry_separator.get()
        
        if self.processor.add_mask(name, prefix, suffix, separator):
            messagebox.showinfo("Успех", f"Маска '{name}' успешно добавлена")
            self.update_mask_list()
            self.clear_mask_fields()
        else:
            messagebox.showerror("Ошибка", "Не удалось добавить маску")
    
    def clear_mask_fields(self):
        """Очистка полей маски"""
        self.entry_mask_name.delete(0, tk.END)
        self.entry_mask_prefix.delete(0, tk.END)
        self.entry_mask_suffix.delete(0, tk.END)
        self.var_separator.set("newline")
        self.entry_separator.delete(0, tk.END)
        self.label_example.config(text="")


def main():
    """Основная функция программы"""
    processor = IPCIDRProcessor()
    
    # Проверяем, есть ли аргументы командной строки
    if len(sys.argv) > 1:
        # Режим командной строки
        parser = argparse.ArgumentParser(description='IP CIDR Processor - Обработка IP-адресов в CIDR формате')
        parser.add_argument('files', nargs='*', help='Файлы или URL для обработки')
        parser.add_argument('-o', '--output', help='Имя выходного файла')
        parser.add_argument('-m', '--mask', help='Имя маски для применения')
        parser.add_argument('--merge', action='store_true', help='Объединить все IP-адреса в один файл')
        parser.add_argument('--gui', action='store_true', help='Запустить графический интерфейс')
        
        args = parser.parse_args()
        
        if args.gui:
            # Запускаем GUI
            gui = GUI(processor)
            gui.start()
        else:
            # Обработка в командной строке
            if not args.files:
                print("Не указаны файлы для обработки")
                return
            
            all_ips = []
            for file_path in args.files:
                if file_path.startswith(('http://', 'https://')):
                    # Это URL
                    print(f"Загрузка файла по URL: {file_path}")
                    content = processor.download_file(file_path)
                    if content:
                        ips = processor.extract_ips(content)
                        if ips:
                            print(f"Найдено {len(ips)} IP-адресов в CIDR формате")
                            all_ips.extend(ips)
                else:
                    # Это локальный файл
                    if os.path.exists(file_path):
                        print(f"Обработка файла: {file_path}")
                        ips = processor.process_file(file_path)
                        if ips:
                            print(f"Найдено {len(ips)} IP-адресов в CIDR формате")
                            all_ips.extend(ips)
                    else:
                        print(f"Файл не найден: {file_path}")
            
            # Удаляем дубликаты
            all_ips = list(set(all_ips))
            print(f"\nВсего уникальных IP-адресов: {len(all_ips)}")
            
            if all_ips:
                output_file = args.output if args.output else "output_ips.txt"
                mask_name = args.mask if args.mask else processor.config['default_mask']
                
                if processor.save_results(all_ips, output_file, mask_name):
                    print(f"Результаты сохранены в файл: {output_file}")
                else:
                    print("Ошибка при сохранении результатов")
    else:
        # Запускаем интерактивное меню
        if platform.system() == "Linux" and "DISPLAY" not in os.environ:
            # Если нет графической среды (например, в терминале)
            console_ui = ConsoleUI(processor)
            console_ui.main_menu()
        else:
            # Пытаемся запустить GUI, если не получится - запускаем консольный интерфейс
            try:
                gui = GUI(processor)
                gui.start()
            except Exception as e:
                print(f"Не удалось запустить графический интерфейс: {e}")
                print("Запускаем консольный интерфейс...")
                console_ui = ConsoleUI(processor)
                console_ui.main_menu()


if __name__ == "__main__":
    main()
