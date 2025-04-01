import os
import re
import sys
import ipaddress
from ipaddress import ip_network, ip_address
import json
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
            self.ip_pattern_v6 = re.compile(r'(?:(?:[0-9a-fA-F]{1,4}:){0,7}(?::[0-9a-fA-F]{1,4}){0,7}|(?:[0-9a-fA-F]{1,4}:){0,6}:(?::[0-9a-fA-F]{1,4}){0,6})/\d{1,3}')
            self.range_mask = "{start}-{end}"  # Маска по умолчанию для диапазонов
            self.custom_range_pattern = None   # Пользовательский шаблон для диапазонов
            self.config_file = 'ip_cidr_config.yaml'
            self.output_folder = 'output'
            self.default_config = {
                'masks': [
                    {'name': 'default', 'prefix': '', 'suffix': '', 'separator': '\n'},
                    {'name': 'clash', 'prefix': 'IP-CIDR,', 'suffix': ',no-resolve', 'separator': '\n'},
                    {'name': 'custom', 'prefix': '[', 'suffix': ']', 'separator': ', '},
                    {'name': 'v2ray', 'prefix': 'ip-cidr:', 'suffix': '', 'separator': ';'},
                    {'name': 'surge', 'prefix': 'IP-CIDR,', 'suffix': '', 'separator': '\n'},
                    {'name': 'shadowsocks', 'prefix': '', 'suffix': '@shadowsocks', 'separator': ' | '},
                    {'name': 'json', 'prefix': '{"ip": "', 'suffix': '"}', 'separator': ',\n'},
                ],
                'default_mask': 'default'
            }
            self.config = self.load_config()
            
            if not os.path.exists(self.output_folder):
                os.makedirs(self.output_folder)

    def cidr_to_range(self, cidr):
        """Преобразование CIDR в диапазон IP-адресов"""
        network = ipaddress.ip_network(cidr, strict=False)
        first_ip = network.network_address
        last_ip = network.broadcast_address
        return (str(first_ip), str(last_ip))

    def format_range(self, start_ip, end_ip, use_custom=False):
        """Форматирование диапазона с учетом маски"""
        if use_custom and self.custom_range_pattern:
            return self.custom_range_pattern.format(start=start_ip, end=end_ip)
        return self.range_mask.format(start=start_ip, end=end_ip)

    def set_range_mask(self, mask):
        """Установка маски для диапазонов"""
        if "{start}" in mask and "{end}" in mask:
            self.range_mask = mask
            return True
        return False

    def set_custom_range_pattern(self, pattern):
        """Установка пользовательского шаблона для диапазонов"""
        if "{start}" in pattern and "{end}" in pattern:
            self.custom_range_pattern = pattern
            return True
        return False

    def process_file_to_range(self, file_path, include_ipv4=True, include_ipv6=True, use_custom_range=False):
        """Обработка файла с выводом в виде диапазонов"""
        ips_dict = self.process_file(file_path)
        ranges = []
        
        if include_ipv4:
            for cidr in ips_dict['ipv4']:
                start, end = self.cidr_to_range(cidr)
                ranges.append(self.format_range(start, end, use_custom_range))
        
        if include_ipv6:
            for cidr in ips_dict['ipv6']:
                start, end = self.cidr_to_range(cidr)
                ranges.append(self.format_range(start, end, use_custom_range))
        
        return ranges

    def save_results_as_ranges(self, file_path, output_file, include_ipv4=True, include_ipv6=True, use_custom_range=False):
        """Сохранение результатов в виде диапазонов"""
        ranges = self.process_file_to_range(file_path, include_ipv4, include_ipv6, use_custom_range)
        if not ranges:
            print("Нет диапазонов для сохранения")
            return False
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(ranges))
            print(f"Диапазоны сохранены в файл: {output_file}")
            return True
        except Exception as e:
            print(f"Ошибка при сохранении диапазонов: {e}")
            return False

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

    def validate_ip_cidr(self, ip_cidr):
        """Validate if a string is a valid IP CIDR notation"""
        try:
            ipaddress.ip_network(ip_cidr, strict=False)
            return True
        except ValueError:
            return False
    
    def extract_ips(self, text):
        """Extract and validate IP addresses in CIDR format from text"""
        potential_ips_v4 = self.ip_pattern_v4.findall(text)
        potential_ips_v6 = self.ip_pattern_v6.findall(text)
        potential_ips = potential_ips_v4 + potential_ips_v6
        
        valid_ips = []
        for ip_cidr in potential_ips:
            if self.validate_ip_cidr(ip_cidr):
                valid_ips.append(ip_cidr)
        
        return valid_ips

    def process_file(self, file_path):
        """Process file and extract IP addresses"""
        try:
            if not os.path.exists(file_path):
                print(f"Файл не найден: {file_path}")
                return {'ipv4': [], 'ipv6': []}
                
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            ips = self.extract_ips(content)
            sorted_ips = self.sort_ip_addresses(ips)
            
            # Разделяем на IPv4 и IPv6
            ipv4_list = [ip for ip in sorted_ips if ipaddress.ip_network(ip, strict=False).version == 4]
            ipv6_list = [ip for ip in sorted_ips if ipaddress.ip_network(ip, strict=False).version == 6]
            
            return {'ipv4': ipv4_list, 'ipv6': ipv6_list}
        except Exception as e:
            print(f"Ошибка при обработке файла {file_path}: {e}")
            return {'ipv4': [], 'ipv6': []}
    
    def save_results_with_options(self, ips_dict, output_file, mask_name=None, include_ipv4=True, include_ipv6=True):
        """Сохранение результатов с выбором IPv4/IPv6 и опциональной маской"""
        if not (ips_dict['ipv4'] or ips_dict['ipv6']):
            print("Нет IP-адресов для сохранения")
            return False
        
        # Фильтруем по выбору IPv4/IPv6
        ips_to_save = []
        if include_ipv4:
            ips_to_save.extend(ips_dict['ipv4'])
        if include_ipv6:
            ips_to_save.extend(ips_dict['ipv6'])
        
        if not ips_to_save:
            print("Нет выбранных IP-адресов для сохранения")
            return False
        
        if mask_name and mask_name != "none":
            content = self.apply_mask(ips_to_save, mask_name)
        else:
            content = '\n'.join(ips_to_save)
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Результаты сохранены в файл: {output_file}")
            return True
        except Exception as e:
            print(f"Ошибка при сохранении результатов: {e}")
            return False

    def sort_ip_addresses(self, ip_list):
        """Sort IP addresses for consistent output"""
        # Separate IPv4 and IPv6 addresses
        ipv4_list = []
        ipv6_list = []
        
        for ip_cidr in ip_list:
            try:
                network = ipaddress.ip_network(ip_cidr, strict=False)
                if network.version == 4:
                    ipv4_list.append(ip_cidr)
                else:
                    ipv6_list.append(ip_cidr)
            except ValueError:
                # Skip invalid IP addresses
                continue
        
        # Sort each list
        sorted_ipv4 = sorted(ipv4_list, key=lambda ip: ipaddress.IPv4Network(ip, strict=False))
        sorted_ipv6 = sorted(ipv6_list, key=lambda ip: ipaddress.IPv6Network(ip, strict=False))
        
        # Return combined list with IPv4 addresses first, then IPv6
        return sorted_ipv4 + sorted_ipv6
    
    def optimize_ip_ranges(self, ip_list):
        """Consolidate overlapping CIDR ranges where possible"""
        if not ip_list:
            return []
            
        # Separate IPv4 and IPv6
        ipv4_networks = []
        ipv6_networks = []
        
        for ip_cidr in ip_list:
            try:
                network = ipaddress.ip_network(ip_cidr, strict=False)
                if network.version == 4:
                    ipv4_networks.append(network)
                else:
                    ipv6_networks.append(network)
            except ValueError:
                continue
        
        # Process IPv4 and IPv6 separately
        optimized_ipv4 = self._consolidate_networks(ipv4_networks)
        optimized_ipv6 = self._consolidate_networks(ipv6_networks)
        
        # Convert back to strings
        result = [str(net) for net in optimized_ipv4 + optimized_ipv6]
        return result
    
    def _consolidate_networks(self, networks):
            if not networks:
                return []
    
            # Сортировка сетей
            sorted_nets = sorted(networks, key=lambda net: (net.network_address, net.prefixlen))
    
            # Инициализация оптимизированного списка
            optimized = sorted_nets.copy()
            changed = True
            while changed:
                changed = False
                new_optimized = []
                i = 0
                while i < len(optimized):
                    current = optimized[i]
                    if new_optimized:
                        last = new_optimized[-1]
                        # Проверка на возможность слияния текущей сети с последней
                        if current.subnet_of(last):
                            # Текущая сеть уже покрыта
                            i += 1
                            continue
                        elif last.network_address <= current.network_address and last.broadcast_address >= current.broadcast_address:
                            # Текущая сеть уже покрыта
                            i += 1
                            continue
                        elif last.prefixlen == current.prefixlen:
                            try:
                                # Проверка на соседство
                                if last.broadcast_address + 1 == current.network_address:
                                    # Они соседние
                                    supernet = ipaddress.ip_network(f"{last.network_address}/{last.prefixlen-1}", strict=False)
                                    if supernet.network_address == last.network_address and supernet.broadcast_address == current.broadcast_address:
                                        new_optimized[-1] = supernet
                                        i += 1
                                        changed = True
                                        continue
                            except ValueError:
                                pass
                    # Если слияние не произошло, добавляем текущую сеть
                    new_optimized.append(current)
                    i += 1
    
                # Проверка на изменения
                if new_optimized != optimized:
                    optimized = new_optimized
                    changed = True
                else:
                    break
    
            return optimized

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
        """Объединение нескольких файлов в один с обработкой исключений"""
        all_ips = []
        try:
            for file_path in file_paths:
                try:
                    ips_dict = self.process_file(file_path)
                    all_ips.extend(ips_dict['ipv4'] + ips_dict['ipv6'])
                except Exception as e:
                    print(f"Ошибка при обработке файла {file_path}: {e}")
                    continue
            
            if not all_ips:
                print("Нет IP-адресов для объединения")
                return False
            
            # Удаляем дубликаты
            all_ips = list(set(all_ips))
            
            return self.save_results(all_ips, output_file, mask_name)
        except Exception as e:
            print(f"Критическая ошибка при объединении файлов: {e}")
            return False

    def expand_cidr(self, cidr, output_file=None):
        """Разложение CIDR с потоковой записью в файл или возвратом ограниченного списка"""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            num_addresses = network.num_addresses
            
            # Ограничение: если CIDR слишком большой (> 65536 адресов), требуем файл
            if num_addresses > 65536 and not output_file:
                print(f"Слишком много адресов в {cidr} ({num_addresses}). Укажите файл для записи.")
                return []
            
            if output_file:
                with open(output_file, 'a', encoding='utf-8') as f:
                    if num_addresses == 1:
                        f.write(f"{network.network_address}\n")
                    else:
                        for ip in network.hosts():
                            f.write(f"{ip}\n")
                return [f"Сохранено в {output_file}"]
            else:
                # Для небольших CIDR возвращаем список
                return [str(ip) for ip in network.hosts()] or [str(network.network_address)]
        except ValueError as e:
            print(f"Ошибка при разложении CIDR {cidr}: {e}")
            return []

    def expand_range(self, ip_range):
        """Разложение диапазона IP-адресов (например, 192.168.1.1-192.168.1.10)"""
        try:
            start_ip, end_ip = ip_range.split('-')
            start = ipaddress.ip_address(start_ip.strip())
            end = ipaddress.ip_address(end_ip.strip())
            if start.version != end.version:
                raise ValueError("Версии IP не совпадают")
            ip_list = []
            current = start
            while current <= end:
                ip_list.append(str(current))
                current = ipaddress.ip_address(int(current) + 1)
            return ip_list
        except ValueError as e:
            print(f"Ошибка при разложении диапазона {ip_range}: {e}")
            return []

    def process_input_to_ips(self, input_text, output_file=None):
        """Обработка текста с CIDR или диапазонами с потоковой записью"""
        cidrs = self.extract_ips(input_text)
        ranges = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}-(?:\d{1,3}\.){3}\d{1,3}\b', input_text)
        
        all_ips = []
        saved = False
        
        if output_file and os.path.exists(output_file):
            os.remove(output_file)  # Очищаем файл перед записью
        
        # Обработка CIDR
        for cidr in cidrs:
            ips = self.expand_cidr(cidr, output_file)
            if output_file and ips and ips[0].startswith("Сохранено"):
                saved = True
            else:
                all_ips.extend(ips)
        
        # Обработка диапазонов
        for ip_range in ranges:
            range_ips = self.expand_range(ip_range)
            if output_file:
                with open(output_file, 'a', encoding='utf-8') as f:
                    for ip in range_ips:
                        f.write(f"{ip}\n")
                saved = True
            else:
                all_ips.extend(range_ips)
        
        all_ips = sorted(list(set(all_ips)), key=ipaddress.ip_address) if not output_file else all_ips
        
        if output_file and saved:
            print(f"Все IP-адреса сохранены в файл: {output_file}")
            return all_ips, True
        return all_ips, False

    def count_ips_in_cidr(self, cidr):
        """Подсчет количества IP-адресов в CIDR"""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            # Для IPv4 возвращаем число хостов (без network и broadcast адресов)
            if network.version == 4 and network.num_addresses > 2:
                return network.num_addresses - 2
            # Для IPv6 и малых сетей IPv4 возвращаем все адреса
            return network.num_addresses
        except ValueError as e:
            print(f"Ошибка при подсчете IP в CIDR {cidr}: {e}")
            return 0
    
    def check_cidr_overlap(self, cidr1, cidr2):
        """Проверка пересечения двух CIDR"""
        try:
            net1 = ipaddress.ip_network(cidr1, strict=False)
            net2 = ipaddress.ip_network(cidr2, strict=False)
            # Проверяем, пересекаются ли сети
            return not (net1.subnet_of(net2) or net2.subnet_of(net1) or 
                       (net1.network_address > net2.broadcast_address) or 
                       (net2.network_address > net1.broadcast_address))
        except ValueError as e:
            print(f"Ошибка при проверке пересечения CIDR {cidr1} и {cidr2}: {e}")
            return False

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
        """Main menu of the program"""
        while True:
            self.print_header()
            print("Главное меню:")
            print("1. Обработать локальные файлы")
            print("2. Скачать и обработать файлы по URL")
            print("3. Объединить файлы")
            print("4. Оптимизировать IP диапазоны")
            print("5. Настройки масок")
            print("6. Выход")
            
            choice = input("\nВыберите действие (1-6): ")
            
            if choice == '1':
                self.process_local_files()
            elif choice == '2':
                self.process_url_files()
            elif choice == '3':
                self.merge_files()
            elif choice == '4':
                self.optimize_ip_ranges_menu()
            elif choice == '5':
                self.mask_settings()
            elif choice == '6':
                print("Выход из программы...")
                break
            else:
                print("Неверный выбор. Пожалуйста, введите число от 1 до 6.")
                input("Нажмите Enter для продолжения...")
    
    def optimize_ip_ranges_menu(self):
        """Menu for optimizing IP ranges"""
        self.print_header()
        print("Оптимизация IP диапазонов:")
        print("Укажите путь к файлу с IP адресами в CIDR формате.")
        file_path = input("Путь к файлу: ").strip()
        
        if not file_path:
            print("Не указан путь к файлу.")
            input("Нажмите Enter для продолжения...")
            return
            
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            print(f"Файл не найден: {file_path}")
            input("Нажмите Enter для продолжения...")
            return
            
        ips = self.processor.process_file(file_path)
        if not ips:
            print("IP-адреса в CIDR формате не найдены.")
            input("Нажмите Enter для продолжения...")
            return
            
        print(f"Найдено {len(ips)} IP-адресов в CIDR формате.")
        
        # Optimize ranges
        optimized_ips = self.processor.optimize_ip_ranges(ips)
        print(f"После оптимизации: {len(optimized_ips)} IP-адресов.")
        
        # Select mask
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
        
        # Save optimized IPs
        output_file = input("Введите имя выходного файла (по умолчанию: optimized_ips.txt): ")
        if not output_file.strip():
            output_file = "optimized_ips.txt"
        output_path = os.path.join(self.processor.output_folder, output_file)
        
        success = self.processor.save_results(optimized_ips, output_path, selected_mask)
        if success:
            print(f"Оптимизированные IP-адреса сохранены в файл: {output_path}")
        
        input("\nНажмите Enter для продолжения...")
    
    def process_local_files(self):
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
        
        # Дополнительные опции
        print("\nДополнительные опции:")
        include_ipv4 = input("Включать IPv4? (y/n, по умолчанию y): ").lower() != 'n'
        include_ipv6 = input("Включать IPv6? (y/n, по умолчанию y): ").lower() != 'n'
        use_ranges = input("Выводить как диапазоны? (y/n): ").lower() == 'y'
        use_custom = False
        if use_ranges:
            use_custom = input("Использовать пользовательский шаблон? (y/n): ").lower() == 'y'
            if use_custom:
                pattern = input("Введите шаблон (например, {start}[custom]{end}): ")
                if not self.processor.set_custom_range_pattern(pattern):
                    print("Ошибка: шаблон должен содержать {start} и {end}")
                    input("Нажмите Enter для продолжения...")
                    return
        
        # Выбор способа сохранения
        print("\nВыберите способ сохранения:")
        print("1. Сохранить в один файл")
        print("2. Сохранить каждый исходный файл отдельно")
        save_choice = input("Выберите способ сохранения (1-2): ")
        
        if use_ranges:
            all_ranges = []
            for path in valid_paths:
                print(f"\nОбработка файла: {path}")
                ranges = self.processor.process_file_to_range(path, include_ipv4, include_ipv6, use_custom)
                if ranges:
                    print(f"Найдено диапазонов: {len(ranges)}")
                    if save_choice == '2':
                        output_path = os.path.join(self.processor.output_folder, f"range_{os.path.basename(path)}")
                        try:
                            with open(output_path, 'w', encoding='utf-8') as f:
                                f.write('\n'.join(ranges))
                            print(f"Диапазоны сохранены в: {output_path}")
                        except Exception as e:
                            print(f"Ошибка при сохранении: {e}")
                    else:
                        all_ranges.extend(ranges)
                else:
                    print("Диапазоны не найдены")
            
            if save_choice == '1' and all_ranges:
                all_ranges = list(set(all_ranges))
                print(f"\nВсего уникальных диапазонов: {len(all_ranges)}")
                output_file = input("Введите имя выходного файла (по умолчанию: combined_ranges.txt): ")
                if not output_file.strip():
                    output_file = "combined_ranges.txt"
                output_path = os.path.join(self.processor.output_folder, output_file)
                try:
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write('\n'.join(all_ranges))
                    print(f"Все диапазоны сохранены в: {output_path}")
                except Exception as e:
                    print(f"Ошибка при сохранении: {e}")
        else:
            # Существующая логика для CIDR
            all_ips = []
            for path in valid_paths:
                print(f"\nОбработка файла: {path}")
                ips = self.processor.process_file(path)
                if ips['ipv4'] or ips['ipv6']:
                    print(f"Найдено IPv4: {len(ips['ipv4'])}, IPv6: {len(ips['ipv6'])}")
                    all_ips.extend(ips['ipv4'] + ips['ipv6'])
                else:
                    print("IP-адреса в CIDR формате не найдены")
            
            all_ips = list(set(all_ips))
            print(f"\nВсего уникальных IP-адресов: {len(all_ips)}")
            
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
                    if ips['ipv4'] or ips['ipv6']:
                        base_name = os.path.basename(path)
                        output_file = f"processed_{base_name}"
                        output_path = os.path.join(self.processor.output_folder, output_file)
                        success = self.processor.save_results(ips['ipv4'] + ips['ipv6'], output_path, selected_mask)
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
        self.tab_ip_expansion = ttk.Frame(self.notebook)
        
        self.notebook.add(self.tab_local, text="Локальные файлы")
        self.notebook.add(self.tab_url, text="URL файлы")
        self.notebook.add(self.tab_merge, text="Объединение")
        self.notebook.add(self.tab_settings, text="Настройки")
        self.notebook.add(self.tab_ip_expansion, text="Разложение IP")

        # Создаем интерфейс для каждой вкладки
        self.setup_local_tab()
        self.setup_url_tab()
        self.setup_merge_tab()
        self.setup_settings_tab()
        self.setup_ip_expansion_tab()

    def setup_local_tab(self):
        frame_files = ttk.LabelFrame(self.tab_local, text="Выбор файлов")
        frame_files.pack(fill='both', expand=True, padx=10, pady=5)
        
        frame_list = ttk.Frame(frame_files)
        frame_list.pack(fill='both', expand=True, padx=5, pady=5)
        
        scrollbar = ttk.Scrollbar(frame_list)
        scrollbar.pack(side='right', fill='y')
        
        self.listbox_files = tk.Listbox(frame_list, yscrollcommand=scrollbar.set)
        self.listbox_files.pack(side='left', fill='both', expand=True)
        scrollbar.config(command=self.listbox_files.yview)
        
        frame_buttons = ttk.Frame(frame_files)
        frame_buttons.pack(fill='x', pady=5)
        
        btn_add_files = ttk.Button(frame_buttons, text="Добавить файлы", command=self.add_local_files)
        btn_add_files.pack(side='left', padx=5)
        
        btn_clear_files = ttk.Button(frame_buttons, text="Очистить список", command=self.clear_local_files)
        btn_clear_files.pack(side='left', padx=5)
        
        frame_settings = ttk.LabelFrame(self.tab_local, text="Настройки обработки")
        frame_settings.pack(fill='x', padx=10, pady=5)
        
        frame_mask = ttk.Frame(frame_settings)
        frame_mask.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(frame_mask, text="Маска:").pack(side='left', padx=5)
        
        self.combo_local_mask = ttk.Combobox(frame_mask, values=self.processor.get_masks(), state="readonly")
        self.combo_local_mask.pack(side='left', fill='x', expand=True, padx=5)
        self.combo_local_mask.set(self.processor.config['default_mask'])
        
        # Выбор типов IP для сохранения
        frame_ip_types = ttk.Frame(frame_settings)
        frame_ip_types.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(frame_ip_types, text="Сохранять:").pack(side='left', padx=5)
        self.var_ipv4 = tk.BooleanVar(value=True)
        self.var_ipv6 = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame_ip_types, text="IPv4", variable=self.var_ipv4).pack(side='left', padx=5)
        ttk.Checkbutton(frame_ip_types, text="IPv6", variable=self.var_ipv6).pack(side='left', padx=5)
        
        frame_save = ttk.Frame(frame_settings)
        frame_save.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(frame_save, text="Сохранение:").pack(side='left', padx=5)
        
        self.var_save_mode = tk.StringVar(value="combined")
        rb_combined = ttk.Radiobutton(frame_save, text="В один файл", variable=self.var_save_mode, value="combined")
        rb_combined.pack(side='left', padx=5)
        
        rb_separate = ttk.Radiobutton(frame_save, text="Отдельными файлами", variable=self.var_save_mode, value="separate")
        rb_separate.pack(side='left', padx=5)
        
        frame_output = ttk.Frame(frame_settings)
        frame_output.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(frame_output, text="Имя выходного файла:").pack(side='left', padx=5)
        
        self.entry_local_output = ttk.Entry(frame_output)
        self.entry_local_output.pack(side='left', fill='x', expand=True, padx=5)
        self.entry_local_output.insert(0, "combined_ips.txt")
        
        btn_process = ttk.Button(self.tab_local, text="Обработать файлы", command=self.process_local_files)
        btn_process.pack(pady=10)
        
        frame_log = ttk.LabelFrame(self.tab_local, text="Лог обработки")
        frame_log.pack(fill='both', expand=True, padx=10, pady=5)
        
        scrollbar_log = ttk.Scrollbar(frame_log)
        scrollbar_log.pack(side='right', fill='y')
        
        self.text_local_log = tk.Text(frame_log, yscrollcommand=scrollbar_log.set, height=10)
        self.text_local_log.pack(side='left', fill='both', expand=True)
        scrollbar_log.config(command=self.text_local_log.yview)
    
        # Добавляем опции для диапазонов
        frame_range = ttk.Frame(frame_settings)
        frame_range.pack(fill='x', padx=5, pady=5)
        
        self.var_use_ranges = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame_range, text="Выводить как диапазоны", variable=self.var_use_ranges).pack(side='left', padx=5)
        
        self.var_use_custom_range = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame_range, text="Использовать пользовательский шаблон", variable=self.var_use_custom_range).pack(side='left', padx=5)
        
        self.entry_range_pattern = ttk.Entry(frame_range)
        self.entry_range_pattern.pack(side='left', fill='x', expand=True, padx=5)
        self.entry_range_pattern.insert(0, "{start}-{end}")

    def setup_url_tab(self):
        """Настройка вкладки для обработки файлов по URL"""
        frame_urls = ttk.LabelFrame(self.tab_url, text="Ввод URL")
        frame_urls.pack(fill='both', expand=True, padx=10, pady=5)
        
        frame_list = ttk.Frame(frame_urls)
        frame_list.pack(fill='both', expand=True, padx=5, pady=5)
        
        scrollbar = ttk.Scrollbar(frame_list)
        scrollbar.pack(side='right', fill='y')
        
        self.listbox_urls = tk.Listbox(frame_list, yscrollcommand=scrollbar.set)
        self.listbox_urls.pack(side='left', fill='both', expand=True)
        scrollbar.config(command=self.listbox_urls.yview)
        
        frame_add_url = ttk.Frame(frame_urls)
        frame_add_url.pack(fill='x', pady=5)
        
        self.entry_url = ttk.Entry(frame_add_url)
        self.entry_url.pack(side='left', fill='x', expand=True, padx=5)
        
        btn_add_url = ttk.Button(frame_add_url, text="Добавить URL", command=self.add_url)
        btn_add_url.pack(side='left', padx=5)
        
        frame_buttons = ttk.Frame(frame_urls)
        frame_buttons.pack(fill='x', pady=5)
        
        btn_remove_url = ttk.Button(frame_buttons, text="Удалить выбранный", command=self.remove_url)
        btn_remove_url.pack(side='left', padx=5)
        
        btn_clear_urls = ttk.Button(frame_buttons, text="Очистить список", command=self.clear_urls)
        btn_clear_urls.pack(side='left', padx=5)
        
        frame_settings = ttk.LabelFrame(self.tab_url, text="Настройки обработки")
        frame_settings.pack(fill='x', padx=10, pady=5)
        
        frame_mask = ttk.Frame(frame_settings)
        frame_mask.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(frame_mask, text="Маска:").pack(side='left', padx=5)
        
        self.combo_url_mask = ttk.Combobox(frame_mask, values=self.processor.get_masks(), state="readonly")
        self.combo_url_mask.pack(side='left', fill='x', expand=True, padx=5)
        self.combo_url_mask.set(self.processor.config['default_mask'])
        
        # Выбор типов IP для сохранения
        frame_ip_types = ttk.Frame(frame_settings)
        frame_ip_types.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(frame_ip_types, text="Сохранять:").pack(side='left', padx=5)
        self.var_url_ipv4 = tk.BooleanVar(value=True)
        self.var_url_ipv6 = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame_ip_types, text="IPv4", variable=self.var_url_ipv4).pack(side='left', padx=5)
        ttk.Checkbutton(frame_ip_types, text="IPv6", variable=self.var_url_ipv6).pack(side='left', padx=5)
        
        frame_save = ttk.Frame(frame_settings)
        frame_save.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(frame_save, text="Сохранение:").pack(side='left', padx=5)
        
        self.var_url_save_mode = tk.StringVar(value="separate")
        rb_combined = ttk.Radiobutton(frame_save, text="В один файл", variable=self.var_url_save_mode, value="combined")
        rb_combined.pack(side='left', padx=5)
        
        rb_separate = ttk.Radiobutton(frame_save, text="Отдельными файлами", variable=self.var_url_save_mode, value="separate")
        rb_separate.pack(side='left', padx=5)
        
        frame_output = ttk.Frame(frame_settings)
        frame_output.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(frame_output, text="Имя выходного файла:").pack(side='left', padx=5)
        
        self.entry_url_output = ttk.Entry(frame_output)
        self.entry_url_output.pack(side='left', fill='x', expand=True, padx=5)
        self.entry_url_output.insert(0, "combined_urls.txt")
        
        btn_process = ttk.Button(self.tab_url, text="Обработать URL", command=self.process_urls)
        btn_process.pack(pady=10)
        
        frame_log = ttk.LabelFrame(self.tab_url, text="Лог обработки")
        frame_log.pack(fill='both', expand=True, padx=10, pady=5)
        
        scrollbar_log = ttk.Scrollbar(frame_log)
        scrollbar_log.pack(side='right', fill='y')
        
        self.text_url_log = tk.Text(frame_log, yscrollcommand=scrollbar_log.set, height=10)
        self.text_url_log.pack(side='left', fill='both', expand=True)
        scrollbar_log.config(command=self.text_url_log.yview)
    
        frame_range = ttk.Frame(frame_settings)
        frame_range.pack(fill='x', padx=5, pady=5)
        
        self.var_url_use_ranges = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame_range, text="Выводить как диапазоны", variable=self.var_url_use_ranges).pack(side='left', padx=5)
        
        self.var_url_use_custom_range = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame_range, text="Использовать пользовательский шаблон", variable=self.var_url_use_custom_range).pack(side='left', padx=5)
        
        self.entry_url_range_pattern = ttk.Entry(frame_range)
        self.entry_url_range_pattern.pack(side='left', fill='x', expand=True, padx=5)
        self.entry_url_range_pattern.insert(0, "{start}-{end}")

    def setup_merge_tab(self):
        frame_files = ttk.LabelFrame(self.tab_merge, text="Выбор файлов для объединения")
        frame_files.pack(fill='both', expand=True, padx=10, pady=5)
        
        frame_list = ttk.Frame(frame_files)
        frame_list.pack(fill='both', expand=True, padx=5, pady=5)
        
        scrollbar = ttk.Scrollbar(frame_list)
        scrollbar.pack(side='right', fill='y')
        
        self.listbox_merge_files = tk.Listbox(frame_list, yscrollcommand=scrollbar.set)
        self.listbox_merge_files.pack(side='left', fill='both', expand=True)
        scrollbar.config(command=self.listbox_merge_files.yview)
        
        frame_buttons = ttk.Frame(frame_files)
        frame_buttons.pack(fill='x', pady=5)
        
        btn_add_files = ttk.Button(frame_buttons, text="Добавить файлы", command=self.add_merge_files)
        btn_add_files.pack(side='left', padx=5)
        
        btn_clear_files = ttk.Button(frame_buttons, text="Очистить список", command=self.clear_merge_files)
        btn_clear_files.pack(side='left', padx=5)
        
        frame_settings = ttk.LabelFrame(self.tab_merge, text="Настройки объединения")
        frame_settings.pack(fill='x', padx=10, pady=5)
        
        frame_mask = ttk.Frame(frame_settings)
        frame_mask.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(frame_mask, text="Маска:").pack(side='left', padx=5)
        
        masks = ["none"] + self.processor.get_masks()  # Добавляем опцию "без маски"
        self.combo_merge_mask = ttk.Combobox(frame_mask, values=masks, state="readonly")
        self.combo_merge_mask.pack(side='left', fill='x', expand=True, padx=5)
        self.combo_merge_mask.set(self.processor.config['default_mask'])
        
        # Выбор типов IP для сохранения
        frame_ip_types = ttk.Frame(frame_settings)
        frame_ip_types.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(frame_ip_types, text="Сохранять:").pack(side='left', padx=5)
        self.var_merge_ipv4 = tk.BooleanVar(value=True)
        self.var_merge_ipv6 = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame_ip_types, text="IPv4", variable=self.var_merge_ipv4).pack(side='left', padx=5)
        ttk.Checkbutton(frame_ip_types, text="IPv6", variable=self.var_merge_ipv6).pack(side='left', padx=5)
        
        frame_output = ttk.Frame(frame_settings)
        frame_output.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(frame_output, text="Имя выходного файла:").pack(side='left', padx=5)
        
        self.entry_merge_output = ttk.Entry(frame_output)
        self.entry_merge_output.pack(side='left', fill='x', expand=True, padx=5)
        self.entry_merge_output.insert(0, "merged_ips.txt")
        
        btn_merge = ttk.Button(self.tab_merge, text="Объединить файлы", command=self.merge_selected_files)
        btn_merge.pack(pady=10)
        
        frame_log = ttk.LabelFrame(self.tab_merge, text="Лог обработки")
        frame_log.pack(fill='both', expand=True, padx=10, pady=5)
        
        scrollbar_log = ttk.Scrollbar(frame_log)
        scrollbar_log.pack(side='right', fill='y')
        
        self.text_merge_log = tk.Text(frame_log, yscrollcommand=scrollbar_log.set, height=10)
        self.text_merge_log.pack(side='left', fill='both', expand=True)
        scrollbar_log.config(command=self.text_merge_log.yview)
    
        frame_range = ttk.Frame(frame_settings)
        frame_range.pack(fill='x', padx=5, pady=5)
        
        self.var_merge_use_ranges = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame_range, text="Выводить как диапазоны", variable=self.var_merge_use_ranges).pack(side='left', padx=5)
        
        self.var_merge_use_custom_range = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame_range, text="Использовать пользовательский шаблон", variable=self.var_merge_use_custom_range).pack(side='left', padx=5)
        
        self.entry_merge_range_pattern = ttk.Entry(frame_range)
        self.entry_merge_range_pattern.pack(side='left', fill='x', expand=True, padx=5)
        self.entry_merge_range_pattern.insert(0, "{start}-{end}")

    def setup_settings_tab(self):
        frame_masks = ttk.LabelFrame(self.tab_settings, text="Доступные маски")
        frame_masks.pack(fill='both', expand=True, padx=10, pady=5)
        
        frame_list = ttk.Frame(frame_masks)
        frame_list.pack(fill='both', expand=True, padx=5, pady=5)
        
        scrollbar = ttk.Scrollbar(frame_list)
        scrollbar.pack(side='right', fill='y')
        
        self.listbox_masks = tk.Listbox(frame_list, yscrollcommand=scrollbar.set)
        self.listbox_masks.pack(side='left', fill='both', expand=True)
        scrollbar.config(command=self.listbox_masks.yview)
        
        self.update_mask_list()
        
        frame_buttons = ttk.Frame(frame_masks)
        frame_buttons.pack(fill='x', pady=5)
        
        btn_edit_mask = ttk.Button(frame_buttons, text="Редактировать маску", command=self.edit_mask)
        btn_edit_mask.pack(side='left', padx=5)
        
        btn_set_default = ttk.Button(frame_buttons, text="Установить по умолчанию", command=self.set_default_mask)
        btn_set_default.pack(side='left', padx=5)
        
        frame_edit = ttk.LabelFrame(self.tab_settings, text="Добавление/изменение маски")
        frame_edit.pack(fill='x', padx=10, pady=5)
        
        frame_name = ttk.Frame(frame_edit)
        frame_name.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(frame_name, text="Имя маски:").pack(side='left', padx=5)
        
        self.entry_mask_name = ttk.Entry(frame_name)
        self.entry_mask_name.pack(side='left', fill='x', expand=True, padx=5)
        
        frame_prefix = ttk.Frame(frame_edit)
        frame_prefix.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(frame_prefix, text="Префикс:").pack(side='left', padx=5)
        
        self.entry_mask_prefix = ttk.Entry(frame_prefix)
        self.entry_mask_prefix.pack(side='left', fill='x', expand=True, padx=5)
        
        frame_suffix = ttk.Frame(frame_edit)
        frame_suffix.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(frame_suffix, text="Суффикс:").pack(side='left', padx=5)
        
        self.entry_mask_suffix = ttk.Entry(frame_suffix)
        self.entry_mask_suffix.pack(side='left', fill='x', expand=True, padx=5)
        
        frame_separator = ttk.Frame(frame_edit)
        frame_separator.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(frame_separator, text="Разделитель:").pack(side='left', padx=5)
        
        self.var_separator = tk.StringVar(value="newline")
        separators = [
            ("Новая строка", "newline", "\n"),
            ("Запятая и пробел", "comma", ", "),
            ("Точка с запятой", "semicolon", ";"),
            ("Вертикальная черта", "pipe", "|"),
            ("Табуляция", "tab", "\t"),
            ("Свой:", "custom", "")
        ]
        
        for label, value, sep in separators:
            if value == "custom":
                frame_custom = ttk.Frame(frame_separator)
                frame_custom.pack(side='left', padx=5)
                ttk.Radiobutton(frame_custom, text=label, variable=self.var_separator, value=value).pack(side='left')
                self.entry_separator = ttk.Entry(frame_custom, width=10)
                self.entry_separator.pack(side='left', padx=5)
            else:
                ttk.Radiobutton(frame_separator, text=label, variable=self.var_separator, value=value).pack(side='left', padx=5)
        
        frame_examples = ttk.Frame(frame_edit)
        frame_examples.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(frame_examples, text="Примеры:").pack(side='left', padx=5)
        
        self.label_example1 = ttk.Label(frame_examples, text="", wraplength=700)
        self.label_example1.pack(side='top', fill='x', padx=5)
        
        self.label_example2 = ttk.Label(frame_examples, text="", wraplength=700)
        self.label_example2.pack(side='top', fill='x', padx=5)
        
        self.entry_mask_prefix.bind("<KeyRelease>", self.update_example)
        self.entry_mask_suffix.bind("<KeyRelease>", self.update_example)
        self.entry_separator.bind("<KeyRelease>", self.update_example)
        self.var_separator.trace_add("write", lambda *args: self.update_example())
        
        frame_mask_buttons = ttk.Frame(frame_edit)
        frame_mask_buttons.pack(fill='x', pady=5)
        
        btn_add_mask = ttk.Button(frame_mask_buttons, text="Добавить маску", command=self.add_mask)
        btn_add_mask.pack(side='left', padx=5)
        
        btn_clear_fields = ttk.Button(frame_mask_buttons, text="Очистить поля", command=self.clear_mask_fields)
        btn_clear_fields.pack(side='left', padx=5)

        frame_range_settings = ttk.LabelFrame(self.tab_settings, text="Настройки диапазонов")
        frame_range_settings.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(frame_range_settings, text="Маска диапазона:").pack(side='left', padx=5)
        self.entry_range_mask = ttk.Entry(frame_range_settings)
        self.entry_range_mask.pack(side='left', fill='x', expand=True, padx=5)
        self.entry_range_mask.insert(0, self.processor.range_mask)
        
        ttk.Label(frame_range_settings, text="Пример: 192.168.1.0-192.168.1.255").pack(side='left', padx=5)
        
        btn_save_range_mask = ttk.Button(frame_range_settings, text="Сохранить", command=self.save_range_mask)
        btn_save_range_mask.pack(side='left', padx=5)

    def save_range_mask(self):
            mask = self.entry_range_mask.get()
            if self.processor.set_range_mask(mask):
                messagebox.showinfo("Успех", "Маска диапазона сохранена")
            else:
                messagebox.showerror("Ошибка", "Маска должна содержать {start} и {end}")

    def update_example(self, event=None):
        prefix = self.entry_mask_prefix.get()
        suffix = self.entry_mask_suffix.get()
        
        separator_type = self.var_separator.get()
        separators = {
            "newline": "\n",
            "comma": ", ",
            "semicolon": ";",
            "pipe": "|",
            "tab": "\t",
            "custom": self.entry_separator.get()
        }
        separator = separators.get(separator_type, "\n")
        separator_display = separator.replace('\n', '\\n')
        
        example_ip1 = "192.168.1.0/24"
        example_ip2 = "2001:db8::/32"
        
        self.label_example1.config(text=f"IPv4: {prefix}{example_ip1}{suffix}")
        self.label_example2.config(text=f"IPv6: {prefix}{example_ip2}{suffix} (разделитель: '{separator_display}' между записями)")
    
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
        if not self.selected_files:
            messagebox.showwarning("Предупреждение", "Не выбраны файлы для обработки")
            return
        
        self.text_local_log.delete(1.0, tk.END)
        
        selected_mask = self.combo_local_mask.get()
        save_mode = self.var_save_mode.get()
        output_file = self.entry_local_output.get()
        include_ipv4 = self.var_ipv4.get()
        include_ipv6 = self.var_ipv6.get()
        
        use_ranges = self.var_use_ranges.get()
        use_custom_range = self.var_use_custom_range.get()
        range_pattern = self.entry_range_pattern.get()
        
        if not output_file:
            output_file = "combined_ips.txt"
        
        if use_custom_range:
            if not self.processor.set_custom_range_pattern(range_pattern):
                self.log_local("Ошибка: пользовательский шаблон диапазона должен содержать {start} и {end}")
                return
        
        if use_ranges:
            all_ranges = []
            for file_path in self.selected_files:
                self.log_local(f"Обработка файла: {file_path}")
                ranges = self.processor.process_file_to_range(file_path, include_ipv4, include_ipv6, use_custom_range)
                if ranges:
                    self.log_local(f"Найдено диапазонов: {len(ranges)}")
                    if save_mode == "separate":
                        output_path = os.path.join(self.processor.output_folder, f"range_{os.path.basename(file_path)}")
                        success = self.processor.save_results_as_ranges(file_path, output_path, include_ipv4, include_ipv6, use_custom_range)
                        if success:
                            self.log_local(f"Диапазоны сохранены в файл: {output_path}")
                        else:
                            self.log_local(f"Ошибка при сохранении в файл: {output_path}")
                    else:
                        all_ranges.extend(ranges)
                else:
                    self.log_local("Диапазоны не найдены")
            
            if save_mode == "combined" and all_ranges:
                all_ranges = list(set(all_ranges))  # Удаляем дубликаты
                self.log_local(f"Всего уникальных диапазонов: {len(all_ranges)}")
                output_path = os.path.join(self.processor.output_folder, output_file)
                try:
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write('\n'.join(all_ranges))
                    self.log_local(f"Все диапазоны сохранены в файл: {output_path}")
                except Exception as e:
                    self.log_local(f"Ошибка при сохранении: {e}")
        else:
            # Существующая логика для CIDR
            all_ips = {'ipv4': [], 'ipv6': []}
            for file_path in self.selected_files:
                self.log_local(f"Обработка файла: {file_path}")
                ips_dict = self.processor.process_file(file_path)
                if ips_dict['ipv4'] or ips_dict['ipv6']:
                    self.log_local(f"Найдено IPv4: {len(ips_dict['ipv4'])}, IPv6: {len(ips_dict['ipv6'])}")
                    all_ips['ipv4'].extend(ips_dict['ipv4'])
                    all_ips['ipv6'].extend(ips_dict['ipv6'])
                    
                    if save_mode == "separate":
                        base_name = os.path.basename(file_path)
                        output_path = os.path.join(self.processor.output_folder, f"processed_{base_name}")
                        success = self.processor.save_results_with_options(ips_dict, output_path, selected_mask, include_ipv4, include_ipv6)
                        if success:
                            self.log_local(f"Результаты сохранены в файл: {output_path}")
                        else:
                            self.log_local(f"Ошибка при сохранении в файл: {output_path}")
                else:
                    self.log_local("IP-адреса в CIDR формате не найдены")
            
            all_ips['ipv4'] = list(set(all_ips['ipv4']))
            all_ips['ipv6'] = list(set(all_ips['ipv6']))
            self.log_local(f"\nВсего уникальных IP-адресов: IPv4: {len(all_ips['ipv4'])}, IPv6: {len(all_ips['ipv6'])}")
            
            if save_mode == "combined" and (all_ips['ipv4'] or all_ips['ipv6']):
                output_path = os.path.join(self.processor.output_folder, output_file)
                success = self.processor.save_results_with_options(all_ips, output_path, selected_mask, include_ipv4, include_ipv6)
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
        if not self.selected_urls:
            messagebox.showwarning("Предупреждение", "Не указаны URL для обработки")
            return
        
        self.text_url_log.delete(1.0, tk.END)
        
        selected_mask = self.combo_url_mask.get()
        save_mode = self.var_url_save_mode.get()
        output_file = self.entry_url_output.get()
        include_ipv4 = self.var_url_ipv4.get()
        include_ipv6 = self.var_url_ipv6.get()
        
        use_ranges = self.var_url_use_ranges.get()
        use_custom_range = self.var_url_use_custom_range.get()
        range_pattern = self.entry_url_range_pattern.get()
        
        if not output_file:
            output_file = "combined_urls.txt"
        
        if use_custom_range:
            if not self.processor.set_custom_range_pattern(range_pattern):
                self.log_url("Ошибка: пользовательский шаблон диапазона должен содержать {start} и {end}")
                return
        
        if use_ranges:
            all_ranges = []
            for url in self.selected_urls:
                self.log_url(f"Загрузка файла по URL: {url}")
                content = self.processor.download_file(url)
                if content:
                    ips = self.processor.extract_ips(content)
                    ranges = []
                    for ip in ips:
                        start, end = self.processor.cidr_to_range(ip)
                        ranges.append(self.processor.format_range(start, end, use_custom_range))
                    if ranges:
                        self.log_url(f"Найдено {len(ranges)} диапазонов")
                        if save_mode == "separate":
                            url_parts = urlparse(url)
                            file_name = os.path.basename(url_parts.path) or url_parts.netloc.replace('.', '_') + ".txt"
                            output_path = os.path.join(self.processor.output_folder, f"range_url_{file_name}")
                            try:
                                with open(output_path, 'w', encoding='utf-8') as f:
                                    f.write('\n'.join(ranges))
                                self.log_url(f"Диапазоны сохранены в файл: {output_path}")
                            except Exception as e:
                                self.log_url(f"Ошибка при сохранении: {e}")
                        else:
                            all_ranges.extend(ranges)
                    else:
                        self.log_url("Диапазоны не найдены")
                else:
                    self.log_url("Ошибка при загрузке файла")
            
            if save_mode == "combined" and all_ranges:
                all_ranges = list(set(all_ranges))
                self.log_url(f"Всего уникальных диапазонов: {len(all_ranges)}")
                output_path = os.path.join(self.processor.output_folder, output_file)
                try:
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write('\n'.join(all_ranges))
                    self.log_url(f"Все диапазоны сохранены в файл: {output_path}")
                except Exception as e:
                    self.log_url(f"Ошибка при сохранении: {e}")
        else:
            # Существующая логика для CIDR
            all_ips = {'ipv4': [], 'ipv6': []}
            for url in self.selected_urls:
                self.log_url(f"Загрузка файла по URL: {url}")
                content = self.processor.download_file(url)
                if content:
                    ips = self.processor.extract_ips(content)
                    ips_dict = {'ipv4': [], 'ipv6': []}
                    for ip in ips:
                        network = ipaddress.ip_network(ip, strict=False)
                        if network.version == 4:
                            ips_dict['ipv4'].append(ip)
                        elif network.version == 6:
                            ips_dict['ipv6'].append(ip)
                    
                    if ips_dict['ipv4'] or ips_dict['ipv6']:
                        self.log_url(f"Найдено IPv4: {len(ips_dict['ipv4'])}, IPv6: {len(ips_dict['ipv6'])}")
                        all_ips['ipv4'].extend(ips_dict['ipv4'])
                        all_ips['ipv6'].extend(ips_dict['ipv6'])
                        
                        if save_mode == "separate":
                            url_parts = urlparse(url)
                            file_name = os.path.basename(url_parts.path) or url_parts.netloc.replace('.', '_') + ".txt"
                            output_path = os.path.join(self.processor.output_folder, f"url_{file_name}")
                            success = self.processor.save_results_with_options(ips_dict, output_path, selected_mask, include_ipv4, include_ipv6)
                            if success:
                                self.log_url(f"Результаты сохранены в файл: {output_path}")
                            else:
                                self.log_url(f"Ошибка при сохранении в файл: {output_path}")
                    else:
                        self.log_url("IP-адреса в CIDR формате не найдены")
                else:
                    self.log_url("Ошибка при загрузке файла")
            
            all_ips['ipv4'] = list(set(all_ips['ipv4']))
            all_ips['ipv6'] = list(set(all_ips['ipv6']))
            self.log_url(f"\nВсего уникальных IP-адресов: IPv4: {len(all_ips['ipv4'])}, IPv6: {len(all_ips['ipv6'])}")
            
            if save_mode == "combined" and (all_ips['ipv4'] or all_ips['ipv6']):
                output_path = os.path.join(self.processor.output_folder, output_file)
                success = self.processor.save_results_with_options(all_ips, output_path, selected_mask, include_ipv4, include_ipv6)
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
        files = [self.listbox_merge_files.get(i) for i in range(self.listbox_merge_files.size())]
        
        if not files:
            messagebox.showwarning("Предупреждение", "Не выбраны файлы для объединения")
            return
        
        self.text_merge_log.delete(1.0, tk.END)
        
        selected_mask = self.combo_merge_mask.get()
        output_file = self.entry_merge_output.get()
        include_ipv4 = self.var_merge_ipv4.get()
        include_ipv6 = self.var_merge_ipv6.get()
        
        use_ranges = self.var_merge_use_ranges.get()
        use_custom_range = self.var_merge_use_custom_range.get()
        range_pattern = self.entry_merge_range_pattern.get()
        
        if not output_file:
            output_file = "merged_ips.txt"
        
        if use_custom_range:
            if not self.processor.set_custom_range_pattern(range_pattern):
                self.log_merge("Ошибка: пользовательский шаблон диапазона должен содержать {start} и {end}")
                return
        
        output_path = os.path.join(self.processor.output_folder, output_file)
        
        if use_ranges:
            all_ranges = []
            self.log_merge(f"Объединение {len(files)} файлов...")
            for file_path in files:
                ranges = self.processor.process_file_to_range(file_path, include_ipv4, include_ipv6, use_custom_range)
                all_ranges.extend(ranges)
            
            all_ranges = list(set(all_ranges))
            self.log_merge(f"Найдено уникальных диапазонов: {len(all_ranges)}")
            
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(all_ranges))
                self.log_merge(f"Диапазоны успешно объединены и сохранены в: {output_path}")
            except Exception as e:
                self.log_merge(f"Ошибка при сохранении: {e}")
        else:
            # Существующая логика для CIDR
            self.log_merge(f"Объединение {len(files)} файлов...")
            all_ips = {'ipv4': [], 'ipv6': []}
            for file_path in files:
                ips_dict = self.processor.process_file(file_path)
                all_ips['ipv4'].extend(ips_dict['ipv4'])
                all_ips['ipv6'].extend(ips_dict['ipv6'])
            
            all_ips['ipv4'] = list(set(all_ips['ipv4']))
            all_ips['ipv6'] = list(set(all_ips['ipv6']))
            self.log_merge(f"Найдено уникальных IP-адресов: IPv4: {len(all_ips['ipv4'])}, IPv6: {len(all_ips['ipv6'])}")
            
            success = self.processor.save_results_with_options(all_ips, output_path, selected_mask, include_ipv4, include_ipv6)
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
        selection = self.listbox_masks.curselection()
        if not selection:
            messagebox.showwarning("Предупреждение", "Не выбрана маска для редактирования")
            return
        
        index = selection[0]
        mask_name = self.listbox_masks.get(index).split(" (по умолчанию)")[0]
        
        mask = next((m for m in self.processor.config['masks'] if m['name'] == mask_name), None)
        if not mask:
            messagebox.showerror("Ошибка", "Маска не найдена")
            return
        
        self.entry_mask_name.delete(0, tk.END)
        self.entry_mask_name.insert(0, mask['name'])
        
        self.entry_mask_prefix.delete(0, tk.END)
        self.entry_mask_prefix.insert(0, mask['prefix'])
        
        self.entry_mask_suffix.delete(0, tk.END)
        self.entry_mask_suffix.insert(0, mask['suffix'])
        
        if mask['separator'] == '\n':
            self.var_separator.set("newline")
        elif mask['separator'] == ', ':
            self.var_separator.set("comma")
        elif mask['separator'] == ';':
            self.var_separator.set("semicolon")
        elif mask['separator'] == '|':
            self.var_separator.set("pipe")
        elif mask['separator'] == '\t':
            self.var_separator.set("tab")
        else:
            self.var_separator.set("custom")
            self.entry_separator.delete(0, tk.END)
            self.entry_separator.insert(0, mask['separator'])
        
        self.update_example()  # Вызываем исправленный метод
    
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
        prefix = self.entry_mask_prefix.get()
        suffix = self.entry_mask_suffix.get()
        
        separator_type = self.var_separator.get()
        separators = {
            "newline": "\n",
            "comma": ", ",
            "semicolon": ";",
            "pipe": "|",
            "tab": "\t",
            "custom": self.entry_separator.get()
        }
        separator = separators.get(separator_type, "\n")
        separator_display = separator.replace('\n', '\\n')
        
        example_ip1 = "192.168.1.0/24"
        example_ip2 = "2001:db8::/32"
        
        self.label_example1.config(text=f"IPv4: {prefix}{example_ip1}{suffix}")
        self.label_example2.config(text=f"IPv6: {prefix}{example_ip2}{suffix} (разделитель: '{separator_display}' между записями)")
    
    def add_mask(self):
        name = self.entry_mask_name.get().strip()
        prefix = self.entry_mask_prefix.get()
        suffix = self.entry_mask_suffix.get()
        
        if not name:
            messagebox.showwarning("Предупреждение", "Имя маски не может быть пустым")
            return
        
        separator_type = self.var_separator.get()
        separators = {
            "newline": "\n",
            "comma": ", ",
            "semicolon": ";",
            "pipe": "|",
            "tab": "\t",
            "custom": self.entry_separator.get()
        }
        separator = separators.get(separator_type, "\n")
        
        if self.processor.add_mask(name, prefix, suffix, separator):
            messagebox.showinfo("Успех", f"Маска '{name}' успешно добавлена")
            self.update_mask_list()
            self.clear_mask_fields()
        else:
            messagebox.showerror("Ошибка", "Не удалось добавить маску")
    
    def clear_mask_fields(self):
        self.entry_mask_name.delete(0, tk.END)
        self.entry_mask_prefix.delete(0, tk.END)
        self.entry_mask_suffix.delete(0, tk.END)
        self.var_separator.set("newline")
        self.entry_separator.delete(0, tk.END)
        self.label_example1.config(text="")
        self.label_example2.config(text="")

    def setup_ip_expansion_tab(self):
        """Настройка вкладки для разложения IP"""
        frame_input = ttk.LabelFrame(self.tab_ip_expansion, text="Ввод CIDR или диапазона")
        frame_input.pack(fill='both', expand=True, padx=10, pady=5)
        self.text_ip_input = tk.Text(frame_input, height=5)
        self.text_ip_input.pack(fill='both', expand=True, padx=5, pady=5)
        
        frame_settings = ttk.LabelFrame(self.tab_ip_expansion, text="Настройки")
        frame_settings.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(frame_settings, text="Выходной файл:").pack(side='left', padx=5)
        self.entry_ip_output = ttk.Entry(frame_settings)
        self.entry_ip_output.pack(side='left', fill='x', expand=True, padx=5)
        self.entry_ip_output.insert(0, "expanded_ips.txt")
        
        # Добавляем опции анализа
        frame_analysis = ttk.Frame(frame_settings)
        frame_analysis.pack(fill='x', pady=5)
        
        self.var_count_ips = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame_analysis, text="Подсчитать IP", variable=self.var_count_ips).pack(side='left', padx=5)
        
        ttk.Label(frame_analysis, text="Сравнить с CIDR:").pack(side='left', padx=5)
        self.entry_compare_cidr = ttk.Entry(frame_analysis, width=20)
        self.entry_compare_cidr.pack(side='left', padx=5)
        
        btn_process = ttk.Button(frame_settings, text="Разложить IP", command=self.expand_ips)
        btn_process.pack(side='left', padx=5)
        
        frame_output = ttk.LabelFrame(self.tab_ip_expansion, text="Результат")
        frame_output.pack(fill='both', expand=True, padx=10, pady=5)
        scrollbar = ttk.Scrollbar(frame_output)
        scrollbar.pack(side='right', fill='y')
        self.text_ip_output = tk.Text(frame_output, yscrollcommand=scrollbar.set, height=10)
        self.text_ip_output.pack(fill='both', expand=True)
        scrollbar.config(command=self.text_ip_output.yview)

    def expand_ips(self):
        """Разложение введенных CIDR и диапазонов"""
        self.text_ip_output.delete(1.0, tk.END)
        input_text = self.text_ip_input.get("1.0", tk.END).strip()
        if not input_text:
            messagebox.showwarning("Предупреждение", "Введите CIDR или диапазон")
            return
        
        output_file = self.entry_ip_output.get().strip()
        output_path = os.path.join(self.processor.output_folder, output_file) if output_file else None
        
        # Получаем значения опций
        count_ips = self.var_count_ips.get()
        compare_cidr = self.entry_compare_cidr.get().strip()
        
        # Обработка ввода
        ips, saved = self.processor.process_input_to_ips(input_text, output_path)
        
        if ips:
            self.text_ip_output.insert(tk.END, f"Найдено IP-адресов: {len(ips)}\n")
            
            # Если включена опция подсчета IP в CIDR
            if count_ips:
                cidrs = self.processor.extract_ips(input_text)
                for cidr in cidrs:
                    try:
                        count = self.processor.count_ips_in_cidr(cidr)
                        self.text_ip_output.insert(tk.END, f"{cidr}: {count} IP-адресов\n")
                    except Exception as e:
                        self.text_ip_output.insert(tk.END, f"Ошибка при подсчете IP для {cidr}: {str(e)}\n")
            
            # Если указан CIDR для сравнения
            if compare_cidr:
                try:
                    # Проверяем, является ли строка корректным CIDR
                    test_network = ipaddress.ip_network(compare_cidr, strict=False)
                    
                    cidrs = self.processor.extract_ips(input_text)
                    for cidr in cidrs:
                        try:
                            overlap = self.processor.check_cidr_overlap(cidr, compare_cidr)
                            self.text_ip_output.insert(tk.END, f"Пересечение {cidr} с {compare_cidr}: {'Да' if overlap else 'Нет'}\n")
                        except Exception as e:
                            self.text_ip_output.insert(tk.END, f"Ошибка при проверке пересечения {cidr} с {compare_cidr}: {str(e)}\n")
                except ValueError:
                    self.text_ip_output.insert(tk.END, f"Ошибка: {compare_cidr} не является корректным CIDR\n")
            
            # Выводим первые 100 IP
            self.text_ip_output.insert(tk.END, "\n".join(ips[:100]))
            if len(ips) > 100:
                self.text_ip_output.insert(tk.END, "\n... (показаны первые 100 адресов)")
            
            # Если файл был сохранен
            if saved:
                self.text_ip_output.insert(tk.END, f"\nВсе IP сохранены в: {output_path}")
        else:
            self.text_ip_output.insert(tk.END, "IP-адреса не найдены")

def main():
    processor = IPCIDRProcessor()
    
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(
            description='IP CIDR Processor - Обработка IP-адресов в CIDR формате',
            epilog='''
            Примеры использования:
              python script.py file1.txt file2.txt -o output.txt -m clash
                - Обработать два файла и сохранить с маской "clash".
              python script.py https://example.com/ips.txt -o ips.txt
                - Скачать и обработать IP из URL.
              python script.py file1.txt file2.txt --merge -o merged.txt
                - Объединить IP из файлов в один выходной файл.
              python script.py --gui
                - Запустить графический интерфейс.

            Полезные команды Linux для работы с терминалом:
              ls -l -> dir (Windows) - Показать список файлов.
              cat file.txt - Просмотр содержимого файла (type file.txt в Windows).
              grep "pattern" file.txt - Поиск в файле (findstr в Windows).
              python script.py file.txt > output.txt - Перенаправить вывод в файл.
              python script.py file.txt 2> errors.txt - Перенаправить ошибки в файл.
              python script.py file.txt | tee output.txt - Просмотр и сохранение вывода.
            ''',
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        parser.add_argument('files', nargs='*', help='Файлы или URL для обработки (локальные пути или http/https ссылки)')
        parser.add_argument('-o', '--output', help='Имя выходного файла (по умолчанию: output_ips.txt)')
        parser.add_argument('-m', '--mask', help='Имя маски для применения (см. конфигурацию в ip_cidr_config.yaml)')
        parser.add_argument('--merge', action='store_true', help='Объединить все IP-адреса из файлов в один выходной файл')
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
