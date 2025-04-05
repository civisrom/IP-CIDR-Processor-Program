import os
import re
import ipaddress
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import yaml
from urllib.parse import urlparse
import requests


class IPCIDRProcessor:
    def __init__(self):
        self.output_folder = 'output'
        self.config_file = 'ip_cidr_config.yaml'
        self.default_config = {
            'masks': [
                {'name': 'default', 'prefix': '', 'suffix': '', 'separator': '\n'},
                {'name': 'clash', 'prefix': 'IP-CIDR,', 'suffix': ',no-resolve', 'separator': '\n'},
                {'name': 'custom', 'prefix': '[', 'suffix': ']', 'separator': ', '}
            ],
            'default_mask': 'default',
            'custom_range_pattern': '{start}-{end}'
        }
        self.load_config()
        if not os.path.exists(self.output_folder):
            os.makedirs(self.output_folder)

    def load_config(self):
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)
        else:
            self.config = self.default_config
            self.save_config()

    def save_config(self):
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                yaml.dump(self.config, f, default_flow_style=False, allow_unicode=True)
            return True
        except Exception as e:
            print(f"Ошибка при сохранении конфигурации: {e}")
            return False

    def add_mask(self, name, prefix, suffix, separator):
        new_mask = {'name': name, 'prefix': prefix, 'suffix': suffix, 'separator': separator}
        for i, mask in enumerate(self.config['masks']):
            if mask['name'] == name:
                self.config['masks'][i] = new_mask
                break
        else:
            self.config['masks'].append(new_mask)
        return self.save_config()

    def set_default_mask(self, name):
        if any(mask['name'] == name for mask in self.config['masks']):
            self.config['default_mask'] = name
            return self.save_config()
        return False

    def get_masks(self):
        return [mask['name'] for mask in self.config['masks']]

    def extract_ips(self, text):
        pattern = r'(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?|[a-fA-F0-9:]+(?:/\d{1,3})?'
        return re.findall(pattern, text)

    def sort_ip_addresses(self, ip_list):
        ipv4_list = []
        ipv6_list = []
        for ip in ip_list:
            try:
                network = ipaddress.ip_network(ip, strict=False)
                if network.version == 4:
                    ipv4_list.append(ip)
                else:
                    ipv6_list.append(ip)
            except ValueError:
                continue
        return sorted(ipv4_list, key=lambda x: ipaddress.IPv4Network(x, strict=False)) + \
               sorted(ipv6_list, key=lambda x: ipaddress.IPv6Network(x, strict=False))

    def save_results_with_options(self, ips_dict, output_file, mask_name=None, include_ipv4=True, include_ipv6=True):
        ips_to_save = []
        if include_ipv4:
            ips_to_save.extend(ips_dict.get('ipv4', []))
        if include_ipv6:
            ips_to_save.extend(ips_dict.get('ipv6', []))
        if not ips_to_save:
            print("Нет выбранных IP-адресов для сохранения")
            return False

        if mask_name and mask_name != "none":
            content = self.apply_mask(ips_to_save, mask_name)
        else:
            content = ''.join(ip + '\n' for ip in ips_to_save)

        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        except Exception as e:
            print(f"Ошибка при сохранении результатов: {e}")
            return False

    def apply_mask(self, ips, mask_name):
        mask = next((m for m in self.config['masks'] if m['name'] == mask_name), None)
        if not mask:
            mask = next((m for m in self.config['masks'] if m['name'] == self.config['default_mask']),
                        self.config['masks'][0])
        return ''.join(f"{mask['prefix']}{ip}{mask['suffix']}{mask['separator']}" for ip in ips)

    def optimize_cidr_list(self, cidr_list, strict_mode=True):
        networks = [ipaddress.ip_network(cidr, strict=False) for cidr in cidr_list]
        networks.sort(key=lambda n: (n.network_address, -n.prefixlen))
        optimized = []
        for net in networks:
            merged = False
            for i, current in enumerate(optimized):
                if (current.overlaps(net) or
                        (not strict_mode and
                         (current.network_address == net.broadcast_address + 1 or
                          net.network_address == current.broadcast_address + 1))):
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

    def process_input_to_ips(self, input_text):
        cidrs = self.extract_ips(input_text)
        ranges = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}-(?:\d{1,3}\.){3}\d{1,3}\b', input_text)
        all_ips = []
        for cidr in cidrs:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                all_ips.extend(str(ip) for ip in network.hosts() or [network.network_address])
            except ValueError:
                continue
        for ip_range in ranges:
            try:
                start_ip, end_ip = ip_range.split('-')
                start = ipaddress.ip_address(start_ip.strip())
                end = ipaddress.ip_address(end_ip.strip())
                while start <= end:
                    all_ips.append(str(start))
                    start += 1
            except ValueError:
                continue
        return list(set(all_ips))

    def download_file(self, url):
        try:
            response = requests.get(url)
            response.raise_for_status()
            return response.text
        except Exception as e:
            print(f"Ошибка при загрузке файла по URL {url}: {e}")
            return ""


class GUI:
    def __init__(self, processor):
        self.processor = processor
        self.root = tk.Tk()
        self.root.title("IP CIDR Processor")
        self.root.geometry("800x600")

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True)

        self.tab_process = ttk.Frame(self.notebook)
        self.tab_optimize = ttk.Frame(self.notebook)
        self.tab_url = ttk.Frame(self.notebook)
        self.tab_settings = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_process, text="Обработка файлов")
        self.notebook.add(self.tab_optimize, text="Оптимизация CIDR")
        self.notebook.add(self.tab_url, text="URL Обработка")
        self.notebook.add(self.tab_settings, text="Настройки")

        self.setup_process_tab()
        self.setup_optimize_tab()
        self.setup_url_tab()
        self.setup_settings_tab()

        self.root.mainloop()

    def setup_process_tab(self):
        frame_files = ttk.LabelFrame(self.tab_process, text="Выбор файлов")
        frame_files.pack(fill='both', expand=True, padx=10, pady=5)

        self.listbox_files = tk.Listbox(frame_files)
        self.listbox_files.pack(side='left', fill='both', expand=True)

        scrollbar = ttk.Scrollbar(frame_files, orient="vertical", command=self.listbox_files.yview)
        scrollbar.pack(side='right', fill='y')
        self.listbox_files.config(yscrollcommand=scrollbar.set)

        btn_add_files = ttk.Button(frame_files, text="Добавить файлы", command=self.add_local_files)
        btn_add_files.pack(pady=5)

        btn_clear_files = ttk.Button(frame_files, text="Очистить список", command=self.clear_local_files)
        btn_clear_files.pack(pady=5)

        btn_process = ttk.Button(frame_files, text="Обработать файлы", command=self.process_local_files)
        btn_process.pack(pady=10)

    def setup_optimize_tab(self):
        frame_files = ttk.LabelFrame(self.tab_optimize, text="Выбор файлов")
        frame_files.pack(fill='both', expand=True, padx=10, pady=5)

        self.listbox_files_optimize = tk.Listbox(frame_files)
        self.listbox_files_optimize.pack(side='left', fill='both', expand=True)

        scrollbar = ttk.Scrollbar(frame_files, orient="vertical", command=self.listbox_files_optimize.yview)
        scrollbar.pack(side='right', fill='y')
        self.listbox_files_optimize.config(yscrollcommand=scrollbar.set)

        btn_add_files = ttk.Button(frame_files, text="Добавить файлы", command=lambda: self.add_local_files(optimize=True))
        btn_add_files.pack(pady=5)

        btn_clear_files = ttk.Button(frame_files, text="Очистить список", command=lambda: self.clear_local_files(optimize=True))
        btn_clear_files.pack(pady=5)

        btn_optimize = ttk.Button(frame_files, text="Оптимизировать CIDR", command=self.optimize_files)
        btn_optimize.pack(pady=10)

    def setup_url_tab(self):
        frame_urls = ttk.LabelFrame(self.tab_url, text="URL Обработка")
        frame_urls.pack(fill='both', expand=True, padx=10, pady=5)

        self.listbox_urls = tk.Listbox(frame_urls)
        self.listbox_urls.pack(side='left', fill='both', expand=True)

        scrollbar = ttk.Scrollbar(frame_urls, orient="vertical", command=self.listbox_urls.yview)
        scrollbar.pack(side='right', fill='y')
        self.listbox_urls.config(yscrollcommand=scrollbar.set)

        btn_add_url = ttk.Button(frame_urls, text="Добавить URL", command=self.add_url)
        btn_add_url.pack(pady=5)

        btn_clear_urls = ttk.Button(frame_urls, text="Очистить список", command=self.clear_urls)
        btn_clear_urls.pack(pady=5)

        btn_process_urls = ttk.Button(frame_urls, text="Обработать URL", command=self.process_urls)
        btn_process_urls.pack(pady=10)

    def setup_settings_tab(self):
        frame_masks = ttk.LabelFrame(self.tab_settings, text="Маски")
        frame_masks.pack(fill='both', expand=True, padx=10, pady=5)

        masks = self.processor.get_masks()
        for i, mask in enumerate(masks):
            mask_frame = ttk.Frame(frame_masks)
            mask_frame.pack(fill='x', pady=5)
            ttk.Label(mask_frame, text=f"{mask}: ").pack(side='left')
            entry_prefix = ttk.Entry(mask_frame)
            entry_prefix.pack(side='left', padx=5)
            entry_suffix = ttk.Entry(mask_frame)
            entry_suffix.pack(side='left', padx=5)
            entry_separator = ttk.Entry(mask_frame)
            entry_separator.pack(side='left', padx=5)
            btn_update = ttk.Button(mask_frame, text="Обновить",
                                    command=lambda m=mask, p=entry_prefix, s=entry_suffix, sep=entry_separator:
                                    self.update_mask(m, p.get(), s.get(), sep.get()))
            btn_update.pack(side='left', padx=5)

    def add_local_files(self, optimize=False):
        files = filedialog.askopenfilenames(title="Выберите файлы")
        listbox = self.listbox_files_optimize if optimize else self.listbox_files
        for file in files:
            if file not in listbox.get(0, tk.END):
                listbox.insert(tk.END, file)

    def clear_local_files(self, optimize=False):
        listbox = self.listbox_files_optimize if optimize else self.listbox_files
        listbox.delete(0, tk.END)

    def process_local_files(self):
        files = self.listbox_files.get(0, tk.END)
        all_ips = {'ipv4': [], 'ipv6': []}
        for file in files:
            try:
                with open(file, 'r', encoding='utf-8') as f:
                    content = f.read()
                ips = self.processor.extract_ips(content)
                sorted_ips = self.processor.sort_ip_addresses(ips)
                for ip in sorted_ips:
                    network = ipaddress.ip_network(ip, strict=False)
                    if network.version == 4:
                        all_ips['ipv4'].append(ip)
                    else:
                        all_ips['ipv6'].append(ip)
            except Exception as e:
                print(f"Ошибка при обработке файла {file}: {e}")

        output_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if output_path:
            success = self.processor.save_results_with_options(all_ips, output_path, "default", True, True)
            if success:
                messagebox.showinfo("Успех", f"IP-адреса сохранены в файл: {output_path}")
            else:
                messagebox.showerror("Ошибка", "Ошибка при сохранении результатов.")

    def optimize_files(self):
        files = self.listbox_files_optimize.get(0, tk.END)
        all_cidrs = []
        for file in files:
            try:
                with open(file, 'r', encoding='utf-8') as f:
                    content = f.read()
                cidrs = self.processor.extract_ips(content)
                all_cidrs.extend(cidrs)
            except Exception as e:
                print(f"Ошибка при обработке файла {file}: {e}")

        optimized_cidrs = self.processor.optimize_cidr_list(all_cidrs)
        output_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(optimized_cidrs))
            messagebox.showinfo("Успех", f"Оптимизированные CIDR сохранены в файл: {output_path}")

    def add_url(self):
        url = filedialog.askstring("Добавить URL", "Введите URL:")
        if url and url not in self.listbox_urls.get(0, tk.END):
            self.listbox_urls.insert(tk.END, url)

    def clear_urls(self):
        self.listbox_urls.delete(0, tk.END)

    def process_urls(self):
        urls = self.listbox_urls.get(0, tk.END)
        all_ips = {'ipv4': [], 'ipv6': []}
        for url in urls:
            content = self.processor.download_file(url)
            if content:
                ips = self.processor.extract_ips(content)
                sorted_ips = self.processor.sort_ip_addresses(ips)
                for ip in sorted_ips:
                    network = ipaddress.ip_network(ip, strict=False)
                    if network.version == 4:
                        all_ips['ipv4'].append(ip)
                    else:
                        all_ips['ipv6'].append(ip)

        output_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if output_path:
            success = self.processor.save_results_with_options(all_ips, output_path, "default", True, True)
            if success:
                messagebox.showinfo("Успех", f"IP-адреса сохранены в файл: {output_path}")
            else:
                messagebox.showerror("Ошибка", "Ошибка при сохранении результатов.")

    def update_mask(self, name, prefix, suffix, separator):
        if self.processor.add_mask(name, prefix, suffix, separator):
            messagebox.showinfo("Успех", f"Маска {name} успешно обновлена.")
        else:
            messagebox.showerror("Ошибка", f"Ошибка при обновлении маски {name}.")


if __name__ == "__main__":
    processor = IPCIDRProcessor()
    gui = GUI(processor)
