import os
import re
import ipaddress
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import yaml

class IPCIDRProcessor:
    def __init__(self):
        self.output_folder = 'output'
        self.config_file = 'ip_cidr_config.yaml'
        self.default_config = {
            'masks': [
                {'name': 'default', 'prefix': '', 'suffix': '', 'separator': ''},
                {'name': 'clash', 'prefix': 'IP-CIDR,', 'suffix': ',no-resolve', 'separator': ''},
                {'name': 'custom', 'prefix': '[', 'suffix': ']', 'separator': ', '}
            ]
        }
        self.load_config()

    def load_config(self):
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)
        else:
            self.config = self.default_config
            self.save_config(self.config)

    def save_config(self, config):
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
        except Exception as e:
            print(f"Ошибка при сохранении конфигурации: {e}")

    def process_file(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return self.extract_ips(content)
        except Exception as e:
            print(f"Ошибка при обработке файла {file_path}: {e}")
            return []

    def extract_ips(self, text):
        pattern = r'(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?'
        return re.findall(pattern, text)

    def save_results(self, ips, output_path, mask_name):
        mask = next((m for m in self.config['masks'] if m['name'] == mask_name), None)
        if not mask:
            print(f"Маска {mask_name} не найдена.")
            return False

        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                for ip in ips:
                    f.write(f"{mask['prefix']}{ip}{mask['suffix']}{mask['separator']}\n")
            return True
        except Exception as e:
            print(f"Ошибка при сохранении результатов: {e}")
            return False

    def optimize_ip_ranges(self, cidrs):
        networks = [ipaddress.ip_network(cidr, strict=False) for cidr in cidrs]
        networks.sort(key=lambda n: (n.network_address, -n.prefixlen))

        optimized = []
        for net in networks:
            merged = False
            for i, current in enumerate(optimized):
                if current.overlaps(net):
                    try:
                        supernet = ipaddress.collapse_addresses([current, net])
                        optimized[i] = next(supernet)
                        merged = True
                        break
                    except ValueError:
                        continue
            if not merged:
                optimized.append(net)

        return [str(net) for net in optimized]


class GUI:
    def __init__(self, processor):
        self.processor = processor
        self.root = tk.Tk()
        self.root.title("IP CIDR Processor")
        self.root.geometry("800x600")

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True)

        self.setup_tabs()
        self.root.mainloop()

    def setup_tabs(self):
        self.tab_process = ttk.Frame(self.notebook)
        self.tab_optimize = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_process, text="Разложить IP")
        self.notebook.add(self.tab_optimize, text="Оптимизировать CIDR")

        self.setup_process_tab()
        self.setup_optimize_tab()

    def setup_process_tab(self):
        frame_files = ttk.LabelFrame(self.tab_process, text="Выбор файлов")
        frame_files.pack(fill='both', expand=True, padx=10, pady=5)

        self.listbox_files = tk.Listbox(frame_files)
        self.listbox_files.pack(side='left', fill='both', expand=True)

        scrollbar = ttk.Scrollbar(frame_files, orient="vertical", command=self.listbox_files.yview)
        scrollbar.pack(side='right', fill='y')
        self.listbox_files.config(yscrollcommand=scrollbar.set)

        btn_add_files = ttk.Button(frame_files, text="Добавить файлы", command=self.add_files)
        btn_add_files.pack(pady=5)

        btn_clear_files = ttk.Button(frame_files, text="Очистить список", command=self.clear_files)
        btn_clear_files.pack(pady=5)

        btn_process = ttk.Button(frame_files, text="Разложить IP", command=self.process_files)
        btn_process.pack(pady=10)

    def setup_optimize_tab(self):
        frame_files = ttk.LabelFrame(self.tab_optimize, text="Выбор файлов")
        frame_files.pack(fill='both', expand=True, padx=10, pady=5)

        self.listbox_files_optimize = tk.Listbox(frame_files)
        self.listbox_files_optimize.pack(side='left', fill='both', expand=True)

        scrollbar = ttk.Scrollbar(frame_files, orient="vertical", command=self.listbox_files_optimize.yview)
        scrollbar.pack(side='right', fill='y')
        self.listbox_files_optimize.config(yscrollcommand=scrollbar.set)

        btn_add_files = ttk.Button(frame_files, text="Добавить файлы", command=lambda: self.add_files(optimize=True))
        btn_add_files.pack(pady=5)

        btn_clear_files = ttk.Button(frame_files, text="Очистить список", command=lambda: self.clear_files(optimize=True))
        btn_clear_files.pack(pady=5)

        btn_optimize = ttk.Button(frame_files, text="Оптимизировать CIDR", command=self.optimize_files)
        btn_optimize.pack(pady=10)

    def add_files(self, optimize=False):
        files = filedialog.askopenfilenames(title="Выберите файлы")
        listbox = self.listbox_files_optimize if optimize else self.listbox_files
        for file in files:
            if file not in listbox.get(0, tk.END):
                listbox.insert(tk.END, file)

    def clear_files(self, optimize=False):
        listbox = self.listbox_files_optimize if optimize else self.listbox_files
        listbox.delete(0, tk.END)

    def process_files(self):
        files = self.listbox_files.get(0, tk.END)
        all_ips = []
        for file in files:
            ips = self.processor.process_file(file)
            all_ips.extend(ips)

        output_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if output_path:
            success = self.processor.save_results(all_ips, output_path, "default")
            if success:
                messagebox.showinfo("Успех", f"IP-адреса сохранены в файл: {output_path}")
            else:
                messagebox.showerror("Ошибка", "Ошибка при сохранении результатов.")

    def optimize_files(self):
        files = self.listbox_files_optimize.get(0, tk.END)
        all_cidrs = []
        for file in files:
            cidrs = self.processor.process_file(file)
            all_cidrs.extend(cidrs)

        optimized_cidrs = self.processor.optimize_ip_ranges(all_cidrs)

        output_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if output_path:
            success = self.processor.save_results(optimized_cidrs, output_path, "default")
            if success:
                messagebox.showinfo("Успех", f"Оптимизированные CIDR сохранены в файл: {output_path}")
            else:
                messagebox.showerror("Ошибка", "Ошибка при сохранении результатов.")


if __name__ == "__main__":
    processor = IPCIDRProcessor()
    gui = GUI(processor)
