import os
import re
import copy
import hashlib
import yaml
import signal
import psutil
import atexit
import multiprocessing
import concurrent.futures
import threading
import ipaddress
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import requests
from typing import List, Dict, Set, Union, Tuple, Optional
from urllib.parse import urlparse

# Try to import tkinterdnd2 for drag and drop support
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    try:
        from tkinterdnd2 import DND_TEXT
    except ImportError:
        DND_TEXT = DND_FILES
    TKDND_AVAILABLE = True
except ImportError:
    TKDND_AVAILABLE = False
    DND_TEXT = None


SUPPORTED_DROP_EXTENSIONS = ('.txt', '.log', '.dat', '.csv')


class IPCIDRProcessor:
    def __init__(self):
        """Initialize the IP CIDR processor with configuration settings."""
        self.output_folder = 'output'
        self.config_file = 'ip_cidr_config.yaml'
        self.default_config = {
            'masks': [
                # Basic masks
                {'name': 'default', 'category': 'Basic', 'prefix': '', 'suffix': '', 'separator': '\n', 'description': 'Plain IP list, one per line'},
                {'name': 'custom', 'category': 'Basic', 'prefix': '[', 'suffix': ']', 'separator': ', ', 'description': 'Bracket-wrapped, comma separated'},
                {'name': 'space-separated', 'category': 'Basic', 'prefix': '', 'suffix': '', 'separator': ' ', 'description': 'Space separated list'},

                # Clash and derivatives
                {'name': 'clash', 'category': 'Clash', 'prefix': 'IP-CIDR,', 'suffix': ',no-resolve', 'separator': '\n', 'description': 'Clash IP-CIDR format'},
                {'name': 'clash-resolve', 'category': 'Clash', 'prefix': 'IP-CIDR,', 'suffix': '', 'separator': '\n', 'description': 'Clash IP-CIDR with resolve'},
                {'name': 'clash-ipv6', 'category': 'Clash', 'prefix': 'IP-CIDR6,', 'suffix': ',no-resolve', 'separator': '\n', 'description': 'Clash IPv6 format'},

                # Surge
                {'name': 'surge', 'category': 'Surge', 'prefix': 'IP-CIDR,', 'suffix': '', 'separator': '\n', 'description': 'Surge IP-CIDR format'},
                {'name': 'surge-ipv6', 'category': 'Surge', 'prefix': 'IP-CIDR6,', 'suffix': '', 'separator': '\n', 'description': 'Surge IPv6 format'},

                # Quantumult X
                {'name': 'quantumult-x', 'category': 'Quantumult', 'prefix': 'IP-CIDR,', 'suffix': ',REJECT', 'separator': '\n', 'description': 'Quantumult X reject format'},
                {'name': 'quantumult-x-direct', 'category': 'Quantumult', 'prefix': 'IP-CIDR,', 'suffix': ',DIRECT', 'separator': '\n', 'description': 'Quantumult X direct format'},

                # Shadowrocket
                {'name': 'shadowrocket', 'category': 'Shadowrocket', 'prefix': 'IP-CIDR,', 'suffix': '', 'separator': '\n', 'description': 'Shadowrocket format'},

                # Programming formats
                {'name': 'json-array', 'category': 'Programming', 'prefix': '  "', 'suffix': '"', 'separator': ',\n', 'description': 'JSON array format'},
                {'name': 'python-list', 'category': 'Programming', 'prefix': '    "', 'suffix': '"', 'separator': ',\n', 'description': 'Python list format'},
                {'name': 'csv', 'category': 'Programming', 'prefix': '', 'suffix': '', 'separator': ',', 'description': 'CSV format'},
                {'name': 'yaml-list', 'category': 'Programming', 'prefix': '  - ', 'suffix': '', 'separator': '\n', 'description': 'YAML list format'},

                # Firewall formats
                {'name': 'iptables-drop', 'category': 'Firewall', 'prefix': 'iptables -A INPUT -s ', 'suffix': ' -j DROP', 'separator': '\n', 'description': 'iptables DROP rule'},
                {'name': 'iptables-accept', 'category': 'Firewall', 'prefix': 'iptables -A INPUT -s ', 'suffix': ' -j ACCEPT', 'separator': '\n', 'description': 'iptables ACCEPT rule'},
                {'name': 'ufw-deny', 'category': 'Firewall', 'prefix': 'ufw deny from ', 'suffix': '', 'separator': '\n', 'description': 'UFW deny rule'},
                {'name': 'ufw-allow', 'category': 'Firewall', 'prefix': 'ufw allow from ', 'suffix': '', 'separator': '\n', 'description': 'UFW allow rule'},

                # Router formats
                {'name': 'mikrotik', 'category': 'Router', 'prefix': '/ip firewall address-list add list=blocked address=', 'suffix': '', 'separator': '\n', 'description': 'MikroTik address list'},
                {'name': 'cisco-acl', 'category': 'Router', 'prefix': 'deny ip ', 'suffix': ' any', 'separator': '\n', 'description': 'Cisco ACL deny'},

                # DNS/AdBlock formats
                {'name': 'hosts', 'category': 'DNS', 'prefix': '0.0.0.0 ', 'suffix': '', 'separator': '\n', 'description': 'Hosts file format'},
                {'name': 'dnsmasq', 'category': 'DNS', 'prefix': 'address=/', 'suffix': '/0.0.0.0', 'separator': '\n', 'description': 'Dnsmasq format'},

                # Other formats
                {'name': 'quoted', 'category': 'Other', 'prefix': '"', 'suffix': '"', 'separator': ',\n', 'description': 'Quoted with commas'},
                {'name': 'single-quoted', 'category': 'Other', 'prefix': "'", 'suffix': "'", 'separator': ',\n', 'description': 'Single quoted with commas'},
                {'name': 'html-list', 'category': 'Other', 'prefix': '<li>', 'suffix': '</li>', 'separator': '\n', 'description': 'HTML list items'},
                {'name': 'markdown-list', 'category': 'Other', 'prefix': '- ', 'suffix': '', 'separator': '\n', 'description': 'Markdown list format'},
            ],
            'default_mask': 'default',
            'custom_range_pattern': '{start}-{end}'
        }
        
        if not os.path.exists(self.output_folder):
            os.makedirs(self.output_folder)
        
        self.load_config()

    def load_config(self) -> None:
        """Load configuration from file or create with defaults."""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    loaded_config = yaml.safe_load(f)
                self.config = self._normalize_config(loaded_config)
            else:
                self.config = copy.deepcopy(self.default_config)
                self.save_config()
        except Exception as e:
            print(f"Error loading configuration: {e}")
            self.config = copy.deepcopy(self.default_config)

    def _normalize_config(self, config: Optional[Dict]) -> Dict:
        """Validate and normalize a loaded configuration."""
        if not isinstance(config, dict):
            return copy.deepcopy(self.default_config)

        normalized = copy.deepcopy(self.default_config)
        masks = config.get('masks')
        valid_masks = []
        seen_names = set()

        if isinstance(masks, list):
            for mask in masks:
                if not isinstance(mask, dict):
                    continue
                name = str(mask.get('name', '')).strip()
                if not name or name in seen_names:
                    continue
                seen_names.add(name)
                valid_masks.append({
                    'name': name,
                    'prefix': str(mask.get('prefix', '')),
                    'suffix': str(mask.get('suffix', '')),
                    'separator': str(mask.get('separator', '\n')),
                    'category': str(mask.get('category', 'Custom')),
                    'description': str(mask.get('description', ''))
                })

        if valid_masks:
            normalized['masks'] = valid_masks

        mask_names = {mask['name'] for mask in normalized['masks']}
        default_mask = config.get('default_mask')
        if isinstance(default_mask, str) and default_mask in mask_names:
            normalized['default_mask'] = default_mask

        custom_range_pattern = config.get('custom_range_pattern')
        if isinstance(custom_range_pattern, str):
            normalized['custom_range_pattern'] = custom_range_pattern

        return normalized

    def save_config(self) -> bool:
        """Save current configuration to file."""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                yaml.dump(self.config, f, default_flow_style=False, allow_unicode=True)
            return True
        except Exception as e:
            print(f"Error saving configuration: {e}")
            return False

    def add_mask(self, name: str, prefix: str, suffix: str, separator: str,
                 category: str = 'Custom', description: str = '') -> bool:
        """Add or update a mask in the configuration."""
        if not name:
            return False

        new_mask = {
            'name': name,
            'prefix': prefix,
            'suffix': suffix,
            'separator': separator,
            'category': category,
            'description': description
        }
        for i, mask in enumerate(self.config['masks']):
            if mask['name'] == name:
                self.config['masks'][i] = new_mask
                break
        else:
            self.config['masks'].append(new_mask)
        return self.save_config()

    def remove_mask(self, name: str) -> bool:
        """Remove a mask from the configuration."""
        if name == 'default':
            return False
        for i, mask in enumerate(self.config['masks']):
            if mask['name'] == name:
                self.config['masks'].pop(i)
                return self.save_config()
        return False

    def set_default_mask(self, name: str) -> bool:
        """Set the default mask to use."""
        if any(mask['name'] == name for mask in self.config['masks']):
            self.config['default_mask'] = name
            return self.save_config()
        return False

    def get_masks(self) -> List[Dict]:
        """Get all available masks."""
        return self.config['masks']

    def get_mask_names(self) -> List[str]:
        """Get list of mask names."""
        return [mask['name'] for mask in self.config['masks']]

    def get_mask_by_name(self, name: str) -> Dict:
        """Get a specific mask by name."""
        for mask in self.config['masks']:
            if mask['name'] == name:
                return mask
        return next((m for m in self.config['masks'] if m['name'] == self.config['default_mask']),
                    self.config['masks'][0])

    def get_mask_categories(self) -> List[str]:
        """Get list of unique mask categories."""
        categories = set()
        for mask in self.config['masks']:
            category = mask.get('category', 'Custom')
            categories.add(category)
        return sorted(list(categories))

    def get_masks_by_category(self, category: str) -> List[Dict]:
        """Get all masks in a specific category."""
        return [mask for mask in self.config['masks'] if mask.get('category', 'Custom') == category]

    def duplicate_mask(self, original_name: str, new_name: str) -> bool:
        """Duplicate an existing mask with a new name."""
        original = self.get_mask_by_name(original_name)
        if not original or not new_name:
            return False

        new_mask = {
            'name': new_name,
            'prefix': original.get('prefix', ''),
            'suffix': original.get('suffix', ''),
            'separator': original.get('separator', '\n'),
            'category': 'Custom',  # User duplicates go to Custom category
            'description': f"Copy of {original_name}"
        }
        self.config['masks'].append(new_mask)
        return self.save_config()

    def extract_ips(self, text: str, include_ipv4: bool = True, include_ipv6: bool = True) -> List[str]:
        """Extract IPv4 and/or IPv6 addresses and CIDR notations from text based on settings."""
        text_without_ranges = self._remove_range_spans(text, include_ipv4, include_ipv6)
        return self._extract_valid_ip_tokens(text_without_ranges, include_ipv4, include_ipv6)
    
    def extract_ip_ranges(self, text: str, include_ipv4: bool = True, include_ipv6: bool = True) -> List[str]:
        """Extract IPv4 and/or IPv6 ranges from text based on settings."""
        return [f"{start}-{end}" for start, end, _, _ in self._extract_ip_ranges_with_spans(text, include_ipv4, include_ipv6)]

    def _extract_ip_ranges_with_spans(self, text: str, include_ipv4: bool = True,
                                      include_ipv6: bool = True) -> List[Tuple[str, str, int, int]]:
        """Extract valid IP ranges with text spans so endpoints are not double-counted."""
        ranges = []
        ip_token = r'[0-9A-Fa-f:.]+'
        range_pattern = re.compile(
            rf'(?<![0-9A-Fa-f:.])({ip_token})\s*-\s*({ip_token})(?![0-9A-Fa-f:.])'
        )

        for match in range_pattern.finditer(text):
            start_ip = match.group(1).strip()
            end_ip = match.group(2).strip()
            try:
                start = ipaddress.ip_address(start_ip)
                end = ipaddress.ip_address(end_ip)
            except ValueError:
                continue

            if start.version != end.version:
                continue
            if start.version == 4 and not include_ipv4:
                continue
            if start.version == 6 and not include_ipv6:
                continue

            ranges.append((str(start), str(end), match.start(), match.end()))

        return ranges

    def _remove_range_spans(self, text: str, include_ipv4: bool = True, include_ipv6: bool = True) -> str:
        """Replace IP range text with spaces before extracting standalone IPs."""
        spans = self._extract_ip_ranges_with_spans(text, include_ipv4, include_ipv6)
        if not spans:
            return text

        chars = list(text)
        for _, _, start, end in spans:
            chars[start:end] = ' ' * (end - start)
        return ''.join(chars)

    def _extract_valid_ip_tokens(self, text: str, include_ipv4: bool = True, include_ipv6: bool = True) -> List[str]:
        """Extract syntactic candidates and keep only values accepted by ipaddress."""
        if not include_ipv4 and not include_ipv6:
            return []

        results = []
        seen = set()
        candidates = []
        claimed_spans = []

        def spans_overlap(first: Tuple[int, int], second: Tuple[int, int]) -> bool:
            return max(first[0], second[0]) < min(first[1], second[1])

        def add_token(token: str, span: Tuple[int, int]) -> None:
            normalized = self._normalize_ip_token(token, include_ipv4, include_ipv6)
            if normalized and normalized not in seen:
                seen.add(normalized)
                results.append(normalized)
                claimed_spans.append(span)

        if include_ipv4:
            octet = r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
            ipv4_pattern = re.compile(
                rf'(?<![A-Za-z0-9_.-])({octet}(?:\.{octet}){{3}}(?:/\d{{1,2}})?)(?![A-Za-z0-9_.-])'
            )
            for match in ipv4_pattern.finditer(text):
                candidates.append((match.start(1), match.end(1), 1, match.group(1)))

        if include_ipv6:
            ipv6_pattern = re.compile(
                r'(?<![A-Za-z0-9:.])([0-9A-Fa-f:.]*:[0-9A-Fa-f:.]+(?:/\d{1,3})?)(?![A-Za-z0-9:.])'
            )
            for match in ipv6_pattern.finditer(text):
                candidates.append((match.start(1), match.end(1), 0, match.group(1)))

        for start, end, _, token in sorted(candidates, key=lambda item: (item[0], item[2], -(item[1] - item[0]))):
            span = (start, end)
            if any(spans_overlap(span, claimed) for claimed in claimed_spans):
                continue
            add_token(token, span)

        return results

    def _normalize_ip_token(self, token: str, include_ipv4: bool = True, include_ipv6: bool = True) -> Optional[str]:
        """Return a normalized IP/CIDR token, or None if it is invalid or filtered out."""
        try:
            if '/' in token:
                network = ipaddress.ip_network(token, strict=False)
                if network.version == 4 and not include_ipv4:
                    return None
                if network.version == 6 and not include_ipv6:
                    return None
                return str(network)

            address = ipaddress.ip_address(token)
            if address.version == 4 and not include_ipv4:
                return None
            if address.version == 6 and not include_ipv6:
                return None
            return str(address)
        except ValueError:
            return None

    def is_valid_ipv4(self, ip: str) -> bool:
        """Check if string is a valid IPv4 address."""
        try:
            ipaddress.IPv4Address(ip)
            return True
        except ValueError:
            return False

    def is_valid_ipv4_cidr(self, cidr: str) -> bool:
        """Check if string is a valid IPv4 CIDR notation."""
        try:
            ipaddress.IPv4Network(cidr, strict=False)
            return True
        except ValueError:
            return False

    def is_valid_ipv6(self, ip: str) -> bool:
        """Check if string is a valid IPv6 address."""
        try:
            ipaddress.IPv6Address(ip)
            return True
        except ValueError:
            return False

    def is_valid_ipv6_cidr(self, cidr: str) -> bool:
        """Check if string is a valid IPv6 CIDR notation."""
        try:
            ipaddress.IPv6Network(cidr, strict=False)
            return True
        except ValueError:
            return False

    def sort_ip_addresses(self, ip_list: List[str]) -> List[str]:
        """Sort a list of IPv4 and IPv6 addresses and CIDR notations."""
        ipv4_entries = []
        ipv6_entries = []
        for ip in ip_list:
            try:
                if '/' in ip:
                    try:
                        network = ipaddress.IPv4Network(ip, strict=False)
                        ipv4_entries.append((ip, int(network.network_address)))
                    except ValueError:
                        network = ipaddress.IPv6Network(ip, strict=False)
                        ipv6_entries.append((ip, int(network.network_address)))
                else:
                    try:
                        address = ipaddress.IPv4Address(ip)
                        ipv4_entries.append((f"{ip}/32", int(address)))
                    except ValueError:
                        address = ipaddress.IPv6Address(ip)
                        ipv6_entries.append((f"{ip}/128", int(address)))
            except ValueError:
                continue
        ipv4_entries.sort(key=lambda x: x[1])
        ipv6_entries.sort(key=lambda x: x[1])
        return [ip for ip, _ in ipv4_entries] + [ip for ip, _ in ipv6_entries]

    def range_to_cidrs(self, start_ip: str, end_ip: str) -> List[str]:
        """Convert an IP range to a list of CIDR notations."""
        try:
            try:
                start = ipaddress.IPv4Address(start_ip)
                end = ipaddress.IPv4Address(end_ip)
                if start > end:
                    start, end = end, start
                return [str(cidr) for cidr in ipaddress.summarize_address_range(start, end)]
            except ValueError:
                start = ipaddress.IPv6Address(start_ip)
                end = ipaddress.IPv6Address(end_ip)
                if start > end:
                    start, end = end, start
                return [str(cidr) for cidr in ipaddress.summarize_address_range(start, end)]
        except Exception as e:
            print(f"Error converting range to CIDR: {e}")
            return []

    def cidr_to_range(self, cidr: str) -> Tuple[str, str]:
        """Convert a CIDR notation to an IP range."""
        try:
            try:
                network = ipaddress.IPv4Network(cidr, strict=False)
            except ValueError:
                network = ipaddress.IPv6Network(cidr, strict=False)
            return str(network.network_address), str(network.broadcast_address)
        except Exception as e:
            print(f"Error converting CIDR to range: {e}")
            return ("", "")

    def optimize_cidr_list(self, cidr_list: List[str], aggressive: bool = False) -> List[str]:
        """
        Optimize a list of CIDR notations by combining adjacent networks.
        Works with both IPv4 and IPv6.
        """
        try:
            # Separate IPv4 and IPv6 networks
            ipv4_networks = []
            ipv6_networks = []
            
            for cidr in cidr_list:
                try:
                    # Try IPv4 first
                    network = ipaddress.IPv4Network(cidr, strict=False)
                    ipv4_networks.append(network)
                except ValueError:
                    # Try IPv6
                    try:
                        network = ipaddress.IPv6Network(cidr, strict=False)
                        ipv6_networks.append(network)
                    except ValueError:
                        # Invalid CIDR, skip
                        continue
            
            # Process IPv4 networks
            optimized_ipv4 = []
            if ipv4_networks:
                # Sort networks by address and prefix length
                ipv4_networks.sort(key=lambda n: (n.network_address, -n.prefixlen))
                
                optimized_ipv4 = list(ipaddress.collapse_addresses(ipv4_networks))
            
            # Process IPv6 networks
            optimized_ipv6 = []
            if ipv6_networks:
                # Sort networks by address and prefix length
                ipv6_networks.sort(key=lambda n: (n.network_address, -n.prefixlen))
                
                optimized_ipv6 = list(ipaddress.collapse_addresses(ipv6_networks))
            
            # Combine and return results
            return [str(net) for net in optimized_ipv4 + optimized_ipv6]
                    
        except Exception as e:
            print(f"Error optimizing CIDR list: {e}")
            return cidr_list
    
    def _optimize_network_list(self, networks, aggressive: bool = False):
        """Helper method for optimize_cidr_list to handle the actual optimization logic."""
        return list(ipaddress.collapse_addresses(networks)) if networks else []

    def apply_mask(self, ips: List[str], mask_name: str) -> str:
        """Apply a mask to format a list of IP addresses."""
        mask = self.get_mask_by_name(mask_name)
        
        formatted_ips = []
        for ip in ips:
            formatted_ips.append(f"{mask['prefix']}{ip}{mask['suffix']}")
            
        return mask['separator'].join(formatted_ips)

    def process_input_to_ips(self, input_text: str, include_ipv4: bool = True, include_ipv6: bool = True) -> List[str]:
        """Process input text to extract IPs, CIDR notations, and ranges."""
        cidrs = self.extract_ips(input_text, include_ipv4, include_ipv6)
        ranges = self.extract_ip_ranges(input_text, include_ipv4, include_ipv6)
        
        all_ips = []
        for cidr in cidrs:
            try:
                network = self._token_to_network(cidr, include_ipv4, include_ipv6)
                if network is None:
                    continue
                all_ips.append(str(network))
            except ValueError:
                continue
        
        for ip_range in ranges:
            try:
                start_ip, end_ip = ip_range.split('-')
                cidrs_from_range = self.range_to_cidrs(start_ip, end_ip)
                all_ips.extend(cidrs_from_range)
            except ValueError:
                continue
        
        return list(set(all_ips))

    def _token_to_network(self, token: str, include_ipv4: bool = True, include_ipv6: bool = True):
        """Convert an IP or CIDR token to a network using host masks for single IPs."""
        try:
            if '/' in token:
                network = ipaddress.ip_network(token, strict=False)
            else:
                address = ipaddress.ip_address(token)
                prefix = 32 if address.version == 4 else 128
                network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)

            if network.version == 4 and not include_ipv4:
                return None
            if network.version == 6 and not include_ipv6:
                return None
            return network
        except ValueError:
            return None

    def download_file(self, url: str) -> str:
        """Download a file from a URL."""
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            return response.text
        except Exception as e:
            print(f"Error downloading file from URL {url}: {e}")
            return ""

    def batch_process_files(self, input_files: List[str], output_folder: str, mask_name: str, 
                            optimize: bool = False, aggressive: bool = False, 
                            include_ipv4: bool = True, include_ipv6: bool = True,
                            progress_callback=None, stop_event=None) -> Dict[str, int]:
        """
        Process multiple files in batch mode using multiprocessing.
        
        Args:
            input_files: List of file paths to process
            output_folder: Directory to save output files
            mask_name: Name of mask to apply
            optimize: Whether to optimize CIDRs
            aggressive: Whether to use aggressive optimization
            include_ipv4: Whether to include IPv4 addresses
            include_ipv6: Whether to include IPv6 addresses
            progress_callback: Optional function to call with progress updates (processed_files, total_files)
            stop_event: Optional multiprocessing.Event to signal stop
            
        Returns:
            Dictionary with statistics about the process
        """
        stats = {
            'files_processed': 0,
            'total_ips_found': 0,
            'unique_ips': 0,
            'optimized_networks': 0,
            'errors': []
        }
        
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)
        
        total_files = len(input_files)
        if total_files == 0:
            return stats
        
        # No signal handling here - it should be in the main thread
        
        max_workers = max(1, (os.cpu_count() or 1) // 4)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Создаем задачи для каждого файла
            futures = {
                executor.submit(self.process_single_file, file, output_folder, mask_name, 
                                optimize, aggressive, include_ipv4, include_ipv6): file
                for file in input_files
            }
            
            # Обрабатываем завершенные задачи
            for future in concurrent.futures.as_completed(futures):
                if stop_event and stop_event.is_set():
                    # Если установлен сигнал остановки, отменяем все еще не начатые задачи
                    for f in futures:
                        f.cancel()
                    break
                try:
                    result = future.result()
                    stats['files_processed'] += result['files_processed']
                    stats['total_ips_found'] += result['total_ips_found']
                    stats['unique_ips'] += result['unique_ips']
                    stats['optimized_networks'] += result['optimized_networks']
                    stats['errors'].extend(result['errors'])
                    
                    if progress_callback:
                        progress_callback(stats['files_processed'], total_files)
                except Exception as e:
                    stats['errors'].append(f"Processing error {futures[future]}: {str(e)}")
        
        return stats

    def export_config(self, file_path: str) -> bool:
        """Export current configuration to a file."""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                yaml.dump(self.config, f, default_flow_style=False, allow_unicode=True)
            return True
        except Exception as e:
            print(f"Error exporting configuration: {e}")
            return False
    
    def import_config(self, file_path: str) -> bool:
        """Import configuration from a file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                new_config = yaml.safe_load(f)

            if not isinstance(new_config, dict):
                return False
            if not isinstance(new_config.get('masks'), list):
                return False

            # Apply new configuration
            self.config = self._normalize_config(new_config)
            self.save_config()
            return True
        except Exception as e:
            print(f"Error importing configuration: {e}")
            return False

    def process_single_file(self, file_path: str, output_folder: str, mask_name: str, 
                           optimize: bool, aggressive: bool, include_ipv4: bool, include_ipv6: bool) -> Dict[str, int]:
        """Process a single file and return its stats for multiprocessing."""
        stats = {
            'files_processed': 0,
            'total_ips_found': 0,
            'unique_ips': 0,
            'optimized_networks': 0,
            'errors': []
        }
        
        try:
            file_name = os.path.basename(file_path)
            unique_suffix = hashlib.md5(os.path.abspath(file_path).encode('utf-8')).hexdigest()[:8]
            name, ext = os.path.splitext(file_name)
            file_name = f"{name}_{unique_suffix}{ext}"
            output_file = os.path.join(output_folder, f"processed_{file_name}")
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            all_cidrs = self.process_input_to_ips(content, include_ipv4, include_ipv6)
            stats['total_ips_found'] = len(all_cidrs)
            
            unique_cidrs = list(set(all_cidrs))
            stats['unique_ips'] = len(unique_cidrs)
            
            if optimize:
                optimized_cidrs = self.optimize_cidr_list(unique_cidrs, aggressive)
                sorted_cidrs = self.sort_ip_addresses(optimized_cidrs)
                stats['optimized_networks'] = len(sorted_cidrs)
            else:
                sorted_cidrs = self.sort_ip_addresses(unique_cidrs)
            
            formatted_content = self.apply_mask(sorted_cidrs, mask_name)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(formatted_content)
            
            stats['files_processed'] = 1
        
        except Exception as e:
            stats['errors'].append(f"Error processing {file_path}: {str(e)}")
        
        return stats

class IPCIDRProcessorGUI:
    def __init__(self, processor: IPCIDRProcessor):
        """Initialize the GUI for the IP CIDR processor."""
        self.processor = processor

        # Use TkinterDnD if available for drag and drop support
        if TKDND_AVAILABLE:
            self.root = TkinterDnD.Tk()
        else:
            self.root = tk.Tk()

        self.root.title("IP CIDR Processor" + (" (Drag & Drop Enabled)" if TKDND_AVAILABLE else ""))
        self.root.geometry("900x700")
    
        # Register cleanup on exit
        atexit.register(self.cleanup)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Create main notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create tabs
        self.tab_process = ttk.Frame(self.notebook)
        self.tab_ranges = ttk.Frame(self.notebook)
        self.tab_optimize = ttk.Frame(self.notebook)
        self.tab_url = ttk.Frame(self.notebook)
        self.tab_batch = ttk.Frame(self.notebook)  # New batch tab
        self.tab_masks = ttk.Frame(self.notebook)
        self.tab_config = ttk.Frame(self.notebook)  # New config tab
        
        # Add tabs to notebook
        self.notebook.add(self.tab_process, text="Process Files")
        self.notebook.add(self.tab_ranges, text="IP Ranges")
        self.notebook.add(self.tab_optimize, text="Optimize CIDR")
        self.notebook.add(self.tab_url, text="URL Processing")
        self.notebook.add(self.tab_batch, text="Batch Processing")  # New batch tab
        self.notebook.add(self.tab_masks, text="Mask Settings")
        self.notebook.add(self.tab_config, text="Configuration")  # New config tab
        
        # Set up tabs
        self.setup_process_tab()
        self.setup_ranges_tab()
        self.setup_optimize_tab()
        self.setup_url_tab()
        self.setup_batch_tab()  # Setup batch tab
        self.setup_masks_tab()
        self.setup_config_tab()  # Setup config tab
        
        # Add IPv6 checkbox to relevant tabs
        self.add_ip_version_options()

        # Setup keyboard shortcuts
        self.setup_keyboard_shortcuts()

        # Setup status bar
        self.setup_status_bar()

        # Update status bar
        self.update_status_bar()

        # Start the main loop
        self.root.mainloop()
    
    def enable_drag_and_drop(self, listbox: tk.Listbox, listbox_type: str = "files"):
        """Enable drag and drop for a listbox.

        Args:
            listbox: The listbox widget to enable drag and drop on
            listbox_type: Type of listbox ("files" or "urls")
        """
        if TKDND_AVAILABLE:
            # Use tkinterdnd2 for proper drag and drop support
            drop_type = DND_TEXT if listbox_type == "urls" else DND_FILES
            listbox.drop_target_register(drop_type)
            listbox.dnd_bind('<<Drop>>', lambda e: self._on_drop(e, listbox, listbox_type))

            # Add visual feedback
            def on_drag_enter(event):
                listbox.config(bg='#e8f4f8')
                return event.action

            def on_drag_leave(event):
                listbox.config(bg='white')
                return event.action

            listbox.dnd_bind('<<DragEnter>>', on_drag_enter)
            listbox.dnd_bind('<<DragLeave>>', on_drag_leave)
        else:
            # Fallback: Add a label to indicate that drag and drop is not available
            # But still keep the manual file selection working
            pass

    def _on_drop(self, event, listbox: tk.Listbox, listbox_type: str):
        """Handle drop event for files or URLs.

        Args:
            event: The drop event
            listbox: The target listbox
            listbox_type: Type of listbox ("files" or "urls")
        """
        # Reset background color
        listbox.config(bg='white')

        # Get dropped files or text tokens. splitlist handles Tk's brace-quoted paths.
        dropped_items = self.root.tk.splitlist(event.data)

        if listbox_type == "files":
            # Add files to listbox
            for file in dropped_items:
                file = file.strip('{}')  # Remove curly braces if present
                if os.path.isfile(file) and self._is_supported_drop_file(file) and file not in listbox.get(0, tk.END):
                    listbox.insert(tk.END, file)
                elif os.path.isdir(file):
                    # If it's a directory, add all text files from it
                    for root, dirs, filenames in os.walk(file):
                        for filename in filenames:
                            if self._is_supported_drop_file(filename):
                                filepath = os.path.join(root, filename)
                                if filepath not in listbox.get(0, tk.END):
                                    listbox.insert(tk.END, filepath)
        elif listbox_type == "urls":
            # For URL listbox, treat dropped text as URLs
            for item in dropped_items:
                item = item.strip('{}')
                if self.validate_url(item):
                    if item not in listbox.get(0, tk.END):
                        listbox.insert(tk.END, item)

        return event.action

    def _is_supported_drop_file(self, file_path: str) -> bool:
        """Return True when a dropped file has a supported text-list extension."""
        return file_path.lower().endswith(SUPPORTED_DROP_EXTENSIONS)

    def add_ip_version_options(self):
        """Add IPv4 and IPv6 support options to relevant tabs."""
        tabs = {
            'process': self.tab_process,
            'ranges': self.tab_ranges,
            'optimize': self.tab_optimize,
            'url': self.tab_url,
            'batch': self.tab_batch
        }
        for tab_name, tab_frame in tabs.items():
            ip_frame = ttk.Frame(tab_frame)
            ip_frame.pack(fill='x', padx=10, pady=5)

            ipv4_var = tk.BooleanVar(value=True)  # Default to True for backward compatibility
            setattr(self, f"{tab_name}_ipv4_var", ipv4_var)
            chk_ipv4 = ttk.Checkbutton(ip_frame, text="Include IPv4", variable=ipv4_var)
            chk_ipv4.pack(side='left', padx=5)

            ipv6_var = tk.BooleanVar(value=True)  # Default to True as before
            setattr(self, f"{tab_name}_ipv6_var", ipv6_var)
            chk_ipv6 = ttk.Checkbutton(ip_frame, text="Include IPv6", variable=ipv6_var)
            chk_ipv6.pack(side='left', padx=5)

    def setup_keyboard_shortcuts(self):
        """Setup keyboard shortcuts for common operations."""
        # Ctrl+O - Open/Add files
        self.root.bind('<Control-o>', lambda e: self.add_files_shortcut())

        # Ctrl+S - Save results (if on appropriate tab)
        self.root.bind('<Control-s>', lambda e: self.save_shortcut())

        # Delete - Remove selected items from listbox
        self.root.bind('<Delete>', lambda e: self.delete_selected_items())

        # Ctrl+A - Select all in current listbox
        self.root.bind('<Control-a>', lambda e: self.select_all_items())

        # F5 - Refresh/Process
        self.root.bind('<F5>', lambda e: self.process_shortcut())

        # Ctrl+Q - Quit
        self.root.bind('<Control-q>', lambda e: self.on_closing())

    def add_files_shortcut(self):
        """Add files via keyboard shortcut based on current tab."""
        current_tab = self.notebook.index(self.notebook.select())
        if current_tab == 0:  # Process Files
            self.add_local_files()
        elif current_tab == 2:  # Optimize
            self.add_local_files(optimize=True)
        elif current_tab == 3:  # URL
            self.add_url()
        elif current_tab == 4:  # Batch
            self.add_local_files(batch=True)

    def save_shortcut(self):
        """Save results via keyboard shortcut based on current tab."""
        current_tab = self.notebook.index(self.notebook.select())
        if current_tab == 1:  # IP Ranges tab
            self.save_results()

    def delete_selected_items(self):
        """Delete selected items from the current listbox."""
        current_tab = self.notebook.index(self.notebook.select())
        listbox = None

        if current_tab == 0:  # Process Files
            listbox = self.listbox_files
        elif current_tab == 2:  # Optimize
            listbox = self.listbox_files_optimize
        elif current_tab == 3:  # URL
            listbox = self.listbox_urls
        elif current_tab == 4:  # Batch
            listbox = self.listbox_batch_files

        if listbox:
            selection = listbox.curselection()
            if selection:
                for index in reversed(selection):
                    listbox.delete(index)

    def select_all_items(self):
        """Select all items in the current listbox."""
        current_tab = self.notebook.index(self.notebook.select())
        listbox = None

        if current_tab == 0:  # Process Files
            listbox = self.listbox_files
        elif current_tab == 2:  # Optimize
            listbox = self.listbox_files_optimize
        elif current_tab == 3:  # URL
            listbox = self.listbox_urls
        elif current_tab == 4:  # Batch
            listbox = self.listbox_batch_files

        if listbox:
            listbox.select_set(0, tk.END)

    def process_shortcut(self):
        """Process files via F5 shortcut based on current tab."""
        current_tab = self.notebook.index(self.notebook.select())
        if current_tab == 0:  # Process Files
            self.process_local_files()
        elif current_tab == 2:  # Optimize
            self.optimize_files()
        elif current_tab == 3:  # URL
            self.process_urls()
        elif current_tab == 4:  # Batch
            self.process_batch_files()

    def add_context_menu(self, listbox: tk.Listbox, listbox_type: str = "files"):
        """Add context menu to a listbox.

        Args:
            listbox: The listbox widget
            listbox_type: Type of listbox ("files" or "urls")
        """
        context_menu = tk.Menu(listbox, tearoff=0)

        if listbox_type == "files":
            context_menu.add_command(label="Add Files...", command=lambda: self.add_files_for_listbox(listbox))
            context_menu.add_separator()

        context_menu.add_command(label="Remove Selected", command=lambda: self.remove_selected_from_listbox(listbox))
        context_menu.add_command(label="Clear All", command=lambda: listbox.delete(0, tk.END))
        context_menu.add_separator()
        context_menu.add_command(label="Select All", command=lambda: listbox.select_set(0, tk.END))

        if listbox_type == "files":
            context_menu.add_separator()
            context_menu.add_command(label="Open File Location", command=lambda: self.open_file_location(listbox))

        def show_context_menu(event):
            try:
                context_menu.tk_popup(event.x_root, event.y_root)
            finally:
                context_menu.grab_release()

        listbox.bind("<Button-3>", show_context_menu)  # Right-click
        listbox.bind("<Control-Button-1>", show_context_menu)  # Ctrl+Click for macOS

    def add_files_for_listbox(self, listbox: tk.Listbox):
        """Add files to a specific listbox."""
        files = filedialog.askopenfilenames(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        for file in files:
            if file not in listbox.get(0, tk.END):
                listbox.insert(tk.END, file)

    def remove_selected_from_listbox(self, listbox: tk.Listbox):
        """Remove selected items from a listbox."""
        selection = listbox.curselection()
        for index in reversed(selection):
            listbox.delete(index)

    def open_file_location(self, listbox: tk.Listbox):
        """Open the file location of the selected item."""
        selection = listbox.curselection()
        if selection:
            file_path = listbox.get(selection[0])
            if os.path.exists(file_path):
                folder_path = os.path.dirname(file_path)
                # Open folder in file explorer (cross-platform)
                if os.name == 'nt':  # Windows
                    os.startfile(folder_path)
                elif os.name == 'posix':  # Linux/Mac
                    import subprocess
                    if 'darwin' in os.uname().sysname.lower():  # macOS
                        subprocess.Popen(['open', folder_path])
                    else:  # Linux
                        subprocess.Popen(['xdg-open', folder_path])

    def setup_status_bar(self):
        """Setup status bar at the bottom of the window."""
        self.status_frame = ttk.Frame(self.root)
        self.status_frame.pack(side='bottom', fill='x')

        # Status label
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(self.status_frame, textvariable=self.status_var, relief='sunken', anchor='w')
        self.status_label.pack(side='left', fill='x', expand=True, padx=2, pady=2)

        # File count label
        self.file_count_var = tk.StringVar(value="Files: 0")
        self.file_count_label = ttk.Label(self.status_frame, textvariable=self.file_count_var, relief='sunken', anchor='center', width=15)
        self.file_count_label.pack(side='right', padx=2, pady=2)

    def update_status_bar(self, message: str = "Ready"):
        """Update the status bar with current information.

        Args:
            message: Status message to display
        """
        self.status_var.set(message)

        # Update file count based on current tab
        current_tab = self.notebook.index(self.notebook.select())
        count = 0

        if current_tab == 0:  # Process Files
            count = self.listbox_files.size()
        elif current_tab == 2:  # Optimize
            count = self.listbox_files_optimize.size()
        elif current_tab == 3:  # URL
            count = self.listbox_urls.size()
        elif current_tab == 4:  # Batch
            count = self.listbox_batch_files.size()

        if current_tab in [0, 2, 4]:  # File tabs
            self.file_count_var.set(f"Files: {count}")
        elif current_tab == 3:  # URL tab
            self.file_count_var.set(f"URLs: {count}")
        else:
            self.file_count_var.set("")

        if not hasattr(self, '_status_update_scheduled'):
            self._status_update_scheduled = True

            def refresh_status_bar():
                self._status_update_scheduled = False
                self.update_status_bar(self.status_var.get())

            self.root.after(500, refresh_status_bar)

    def validate_url(self, url: str) -> bool:
        """Validate if a string is a valid URL.

        Args:
            url: URL string to validate

        Returns:
            True if valid, False otherwise
        """
        try:
            parsed = urlparse(url.strip())
            if parsed.scheme not in ('http', 'https'):
                return False
            if not parsed.hostname:
                return False
            if parsed.port is not None and not (0 < parsed.port <= 65535):
                return False
            hostname = parsed.hostname
            if ':' in hostname:
                ipaddress.IPv6Address(hostname)
            elif re.fullmatch(r'[\d.]+', hostname):
                ipaddress.IPv4Address(hostname)
            elif hostname != 'localhost':
                labels = hostname.rstrip('.').split('.')
                if not labels or any(
                    not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                    for label in labels
                ):
                    return False
            return True
        except ValueError:
            return False

    def setup_process_tab(self):
        """Set up the file processing tab."""
        frame_files = ttk.LabelFrame(self.tab_process, text="Select Files (Drag & Drop Supported)" if TKDND_AVAILABLE else "Select Files")
        frame_files.pack(fill='both', expand=True, padx=10, pady=5)

        self.listbox_files = tk.Listbox(frame_files)
        self.listbox_files.pack(side='left', fill='both', expand=True)

        scrollbar = ttk.Scrollbar(frame_files, orient="vertical", command=self.listbox_files.yview)
        scrollbar.pack(side='right', fill='y')
        self.listbox_files.config(yscrollcommand=scrollbar.set)

        # Enable drag and drop
        self.enable_drag_and_drop(self.listbox_files, "files")

        # Add context menu
        self.add_context_menu(self.listbox_files, "files")

        btn_frame = ttk.Frame(self.tab_process)
        btn_frame.pack(fill='x', padx=10, pady=5)
        
        btn_add_files = ttk.Button(btn_frame, text="Add Files", command=self.add_local_files)
        btn_add_files.pack(side='left', padx=5)
        
        btn_clear_files = ttk.Button(btn_frame, text="Clear List", command=self.clear_local_files)
        btn_clear_files.pack(side='left', padx=5)
        
        output_frame = ttk.LabelFrame(self.tab_process, text="Output Options")
        output_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(output_frame, text="Apply Mask:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.process_mask_var = tk.StringVar(value=self.processor.config['default_mask'])
        self.process_mask_combo = ttk.Combobox(output_frame, textvariable=self.process_mask_var)
        self.process_mask_combo['values'] = self.processor.get_mask_names()
        self.process_mask_combo.grid(row=0, column=1, padx=5, pady=5, sticky='w')
        
        btn_process = ttk.Button(self.tab_process, text="Process Files", command=self.process_local_files)
        btn_process.pack(pady=10)

    def setup_ranges_tab(self):
        """Set up the IP ranges conversion tab."""
        range_to_cidr_frame = ttk.LabelFrame(self.tab_ranges, text="Convert IP Range to CIDR")
        range_to_cidr_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(range_to_cidr_frame, text="Start IP:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.range_start_var = tk.StringVar()
        ttk.Entry(range_to_cidr_frame, textvariable=self.range_start_var, width=40).grid(row=0, column=1, padx=5, pady=5, sticky='w')
        
        ttk.Label(range_to_cidr_frame, text="End IP:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.range_end_var = tk.StringVar()
        ttk.Entry(range_to_cidr_frame, textvariable=self.range_end_var, width=40).grid(row=1, column=1, padx=5, pady=5, sticky='w')
        
        btn_convert_to_cidr = ttk.Button(range_to_cidr_frame, text="Convert to CIDR", command=self.convert_range_to_cidr)
        btn_convert_to_cidr.grid(row=2, column=0, columnspan=2, padx=5, pady=5)
        
        cidr_to_range_frame = ttk.LabelFrame(self.tab_ranges, text="Convert CIDR to IP Range")
        cidr_to_range_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(cidr_to_range_frame, text="CIDR:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.cidr_var = tk.StringVar()
        ttk.Entry(cidr_to_range_frame, textvariable=self.cidr_var, width=40).grid(row=0, column=1, padx=5, pady=5, sticky='w')
        
        btn_convert_to_range = ttk.Button(cidr_to_range_frame, text="Convert to Range", command=self.convert_cidr_to_range)
        btn_convert_to_range.grid(row=1, column=0, columnspan=2, padx=5, pady=5)
        
        results_frame = ttk.LabelFrame(self.tab_ranges, text="Results")
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.results_text = tk.Text(results_frame, wrap='word', height=15)
        self.results_text.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.results_text.yview)
        scrollbar.pack(side='right', fill='y')
        self.results_text.config(yscrollcommand=scrollbar.set)
        
        btn_frame = ttk.Frame(self.tab_ranges)
        btn_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(btn_frame, text="Copy Results", command=self.copy_results).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Clear Results", command=self.clear_results).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Save Results", command=self.save_results).pack(side='right', padx=5)

    def setup_optimize_tab(self):
        """Set up the CIDR optimization tab."""
        frame_files = ttk.LabelFrame(self.tab_optimize, text="Select Files with CIDR Notations (Drag & Drop Supported)" if TKDND_AVAILABLE else "Select Files with CIDR Notations")
        frame_files.pack(fill='both', expand=True, padx=10, pady=5)

        self.listbox_files_optimize = tk.Listbox(frame_files)
        self.listbox_files_optimize.pack(side='left', fill='both', expand=True)

        scrollbar = ttk.Scrollbar(frame_files, orient="vertical", command=self.listbox_files_optimize.yview)
        scrollbar.pack(side='right', fill='y')
        self.listbox_files_optimize.config(yscrollcommand=scrollbar.set)

        # Enable drag and drop
        self.enable_drag_and_drop(self.listbox_files_optimize, "files")

        # Add context menu
        self.add_context_menu(self.listbox_files_optimize, "files")

        btn_frame = ttk.Frame(self.tab_optimize)
        btn_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(btn_frame, text="Add Files", command=lambda: self.add_local_files(optimize=True)).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Clear List", command=lambda: self.clear_local_files(optimize=True)).pack(side='left', padx=5)
        
        output_frame = ttk.LabelFrame(self.tab_optimize, text="Optimization Options")
        output_frame.pack(fill='x', padx=10, pady=5)
        
        self.aggressive_var = tk.BooleanVar()
        ttk.Checkbutton(output_frame, text="Aggressive Optimization", variable=self.aggressive_var).pack(anchor='w', padx=5, pady=5)
        
        ttk.Label(output_frame, text="Apply Mask:").pack(anchor='w', padx=5, pady=5)
        self.optimize_mask_var = tk.StringVar(value=self.processor.config['default_mask'])
        self.optimize_mask_combo = ttk.Combobox(output_frame, textvariable=self.optimize_mask_var)
        self.optimize_mask_combo['values'] = self.processor.get_mask_names()
        self.optimize_mask_combo.pack(anchor='w', padx=5, pady=5)
        
        ttk.Button(self.tab_optimize, text="Optimize CIDR", command=self.optimize_files).pack(pady=10)

    def setup_url_tab(self):
        """Set up the URL processing tab."""
        frame_urls = ttk.LabelFrame(self.tab_url, text="URL Processing (Drag & Drop Supported)" if TKDND_AVAILABLE else "URL Processing")
        frame_urls.pack(fill='both', expand=True, padx=10, pady=5)

        self.listbox_urls = tk.Listbox(frame_urls)
        self.listbox_urls.pack(side='left', fill='both', expand=True)

        scrollbar = ttk.Scrollbar(frame_urls, orient="vertical", command=self.listbox_urls.yview)
        scrollbar.pack(side='right', fill='y')
        self.listbox_urls.config(yscrollcommand=scrollbar.set)

        # Enable drag and drop for URLs (can drop text files or URLs)
        self.enable_drag_and_drop(self.listbox_urls, "urls")

        # Add context menu
        self.add_context_menu(self.listbox_urls, "urls")

        btn_frame = ttk.Frame(self.tab_url)
        btn_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(btn_frame, text="Add URL", command=self.add_url).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Clear URLs", command=self.clear_urls).pack(side='left', padx=5)
        
        output_frame = ttk.LabelFrame(self.tab_url, text="Output Options")
        output_frame.pack(fill='x', padx=10, pady=5)
        
        self.url_optimize_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(output_frame, text="Optimize CIDR Results", variable=self.url_optimize_var).pack(anchor='w', padx=5, pady=5)
        
        ttk.Label(output_frame, text="Apply Mask:").pack(anchor='w', padx=5, pady=5)
        self.url_mask_var = tk.StringVar(value=self.processor.config['default_mask'])
        self.url_mask_combo = ttk.Combobox(output_frame, textvariable=self.url_mask_var)
        self.url_mask_combo['values'] = self.processor.get_mask_names()
        self.url_mask_combo.pack(anchor='w', padx=5, pady=5)
        
        ttk.Button(self.tab_url, text="Process URLs", command=self.process_urls).pack(pady=10)

    def setup_masks_tab(self):
        """Set up the mask settings tab with enhanced UI."""
        # Top toolbar for filtering
        toolbar_frame = ttk.Frame(self.tab_masks)
        toolbar_frame.pack(fill='x', padx=10, pady=5)

        ttk.Label(toolbar_frame, text="Filter by Category:").pack(side='left', padx=5)
        self.mask_category_filter = tk.StringVar(value="All")
        self.mask_category_combo = ttk.Combobox(toolbar_frame, textvariable=self.mask_category_filter, width=15, state='readonly')
        self.mask_category_combo['values'] = ['All'] + self.processor.get_mask_categories()
        self.mask_category_combo.pack(side='left', padx=5)
        self.mask_category_combo.bind('<<ComboboxSelected>>', lambda e: self.update_mask_display(self.mask_frame))

        ttk.Button(toolbar_frame, text="Refresh", command=lambda: self.update_mask_display(self.mask_frame)).pack(side='left', padx=5)

        # Main masks display frame
        masks_frame = ttk.LabelFrame(self.tab_masks, text="Current Masks")
        masks_frame.pack(fill='both', expand=True, padx=10, pady=5)

        canvas = tk.Canvas(masks_frame)
        scrollbar = ttk.Scrollbar(masks_frame, orient="vertical", command=canvas.yview)
        self.mask_frame = ttk.Frame(canvas)

        self.mask_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.mask_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.update_mask_display(self.mask_frame)

        # New mask creation frame
        new_mask_frame = ttk.LabelFrame(self.tab_masks, text="Create New Mask")
        new_mask_frame.pack(fill='x', padx=10, pady=5)

        # Row 0: Name
        ttk.Label(new_mask_frame, text="Name:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.new_mask_name = tk.StringVar()
        ttk.Entry(new_mask_frame, textvariable=self.new_mask_name, width=30).grid(row=0, column=1, padx=5, pady=5, sticky='w')

        # Row 1: Category
        ttk.Label(new_mask_frame, text="Category:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.new_mask_category = tk.StringVar(value="Custom")
        category_combo = ttk.Combobox(new_mask_frame, textvariable=self.new_mask_category, width=28)
        category_combo['values'] = self.processor.get_mask_categories() + ['Custom']
        category_combo.grid(row=1, column=1, padx=5, pady=5, sticky='w')

        # Row 2: Prefix
        ttk.Label(new_mask_frame, text="Prefix:").grid(row=2, column=0, padx=5, pady=5, sticky='w')
        self.new_mask_prefix = tk.StringVar()
        ttk.Entry(new_mask_frame, textvariable=self.new_mask_prefix, width=30).grid(row=2, column=1, padx=5, pady=5, sticky='w')

        # Row 3: Suffix
        ttk.Label(new_mask_frame, text="Suffix:").grid(row=3, column=0, padx=5, pady=5, sticky='w')
        self.new_mask_suffix = tk.StringVar()
        ttk.Entry(new_mask_frame, textvariable=self.new_mask_suffix, width=30).grid(row=3, column=1, padx=5, pady=5, sticky='w')

        # Row 4: Separator
        ttk.Label(new_mask_frame, text="Separator:").grid(row=4, column=0, padx=5, pady=5, sticky='w')
        self.new_mask_separator = tk.StringVar(value="\\n")
        ttk.Entry(new_mask_frame, textvariable=self.new_mask_separator, width=30).grid(row=4, column=1, padx=5, pady=5, sticky='w')

        # Row 5: Description
        ttk.Label(new_mask_frame, text="Description:").grid(row=5, column=0, padx=5, pady=5, sticky='w')
        self.new_mask_description = tk.StringVar()
        ttk.Entry(new_mask_frame, textvariable=self.new_mask_description, width=30).grid(row=5, column=1, padx=5, pady=5, sticky='w')

        # Row 6: Preview
        preview_frame = ttk.Frame(new_mask_frame)
        preview_frame.grid(row=6, column=0, columnspan=2, padx=5, pady=5, sticky='ew')

        ttk.Button(preview_frame, text="Preview", command=self.preview_mask).pack(side='left', padx=2)
        ttk.Button(preview_frame, text="Add Mask", command=self.add_new_mask).pack(side='left', padx=2)

        # Row 7: Help text
        help_text = "Note: Use \\n for newline, \\t for tab"
        ttk.Label(new_mask_frame, text=help_text, font=('Arial', 8), foreground='gray').grid(row=7, column=0, columnspan=2, padx=5, pady=2, sticky='w')

    def update_mask_display(self, parent_frame):
        """Update the display of masks in the settings tab with category filtering."""
        # Clear existing widgets
        for widget in parent_frame.winfo_children():
            widget.destroy()

        # Get filtered masks
        selected_category = self.mask_category_filter.get() if hasattr(self, 'mask_category_filter') else 'All'
        if selected_category == 'All':
            masks_to_display = self.processor.get_masks()
        else:
            masks_to_display = self.processor.get_masks_by_category(selected_category)

        # Group masks by category
        masks_by_category = {}
        for mask in masks_to_display:
            category = mask.get('category', 'Custom')
            if category not in masks_by_category:
                masks_by_category[category] = []
            masks_by_category[category].append(mask)

        row_index = 0

        # Display masks grouped by category
        for category in sorted(masks_by_category.keys()):
            # Category header
            category_label = ttk.Label(parent_frame, text=f"📁 {category}", font=('Arial', 10, 'bold'), foreground='#2E86AB')
            category_label.grid(row=row_index, column=0, columnspan=6, sticky='w', padx=5, pady=(10, 5))
            row_index += 1

            # Column headers
            headers = ["Name", "Prefix", "Suffix", "Sep", "Description", "Actions"]
            for col, header in enumerate(headers):
                ttk.Label(parent_frame, text=header, font=('Arial', 9, 'bold')).grid(row=row_index, column=col, padx=5, pady=2)
            row_index += 1

            # Display masks in this category
            for mask in masks_by_category[category]:
                # Name
                name_label = ttk.Label(parent_frame, text=mask['name'], foreground='#0066CC')
                name_label.grid(row=row_index, column=0, padx=5, pady=2, sticky='w')

                # Prefix (truncated)
                prefix_display = mask.get('prefix', '')[:15]
                if len(mask.get('prefix', '')) > 15:
                    prefix_display += '...'
                ttk.Label(parent_frame, text=prefix_display).grid(row=row_index, column=1, padx=5, pady=2, sticky='w')

                # Suffix (truncated)
                suffix_display = mask.get('suffix', '')[:15]
                if len(mask.get('suffix', '')) > 15:
                    suffix_display += '...'
                ttk.Label(parent_frame, text=suffix_display).grid(row=row_index, column=2, padx=5, pady=2, sticky='w')

                # Separator
                separator_display = mask.get('separator', '\n').replace('\n', '\\n').replace('\t', '\\t')[:8]
                ttk.Label(parent_frame, text=separator_display).grid(row=row_index, column=3, padx=5, pady=2, sticky='w')

                # Description
                description = mask.get('description', '')[:30]
                if len(mask.get('description', '')) > 30:
                    description += '...'
                desc_label = ttk.Label(parent_frame, text=description, font=('Arial', 8), foreground='gray')
                desc_label.grid(row=row_index, column=4, padx=5, pady=2, sticky='w')

                # Actions
                btn_frame = ttk.Frame(parent_frame)
                btn_frame.grid(row=row_index, column=5, padx=5, pady=2)

                btn_preview = ttk.Button(btn_frame, text="👁", width=3,
                                        command=lambda m=mask: self.preview_existing_mask(m))
                btn_preview.pack(side='left', padx=1)

                btn_edit = ttk.Button(btn_frame, text="✎", width=3,
                                     command=lambda name=mask['name']: self.edit_mask(name))
                btn_edit.pack(side='left', padx=1)

                btn_duplicate = ttk.Button(btn_frame, text="⎘", width=3,
                                          command=lambda name=mask['name']: self.duplicate_mask_dialog(name))
                btn_duplicate.pack(side='left', padx=1)

                btn_delete = ttk.Button(btn_frame, text="🗑", width=3,
                                       command=lambda name=mask['name']: self.delete_mask(name))
                btn_delete.pack(side='left', padx=1)

                # Disable delete for default mask
                if mask['name'] == 'default':
                    btn_delete['state'] = 'disabled'

                row_index += 1

        # Update comboboxes in other tabs
        self.refresh_mask_comboboxes()

    def refresh_mask_comboboxes(self):
        """Обновление всех выпадающих списков масок с учетом текущих имен."""
        mask_names = self.processor.get_mask_names()
        
        # Обновляем комбобоксы во всех вкладках
        self.process_mask_combo['values'] = mask_names
        self.optimize_mask_combo['values'] = mask_names
        self.url_mask_combo['values'] = mask_names
        self.batch_mask_combo['values'] = mask_names  # Добавлено для вкладки Batch Processing
        
        # Обновляем default_mask_combo, если он существует
        if hasattr(self, 'default_mask_combo'):
            self.default_mask_combo['values'] = mask_names
        
        # Убеждаемся, что все комбобоксы имеют корректный выбор
        if self.process_mask_var.get() not in mask_names:
            self.process_mask_combo.current(0)
        if self.optimize_mask_var.get() not in mask_names:
            self.optimize_mask_combo.current(0)
        if self.url_mask_var.get() not in mask_names:
            self.url_mask_combo.current(0)
        if self.batch_mask_var.get() not in mask_names:  # Добавлено для batch_mask_combo
            self.batch_mask_combo.current(0)
        if hasattr(self, 'default_mask_var') and self.default_mask_var.get() not in mask_names:
            self.default_mask_combo.current(0)

    def setup_batch_tab(self):
        """Настройка вкладки пакетной обработки с кнопкой Стоп."""
        # Files frame
        frame_files = ttk.LabelFrame(self.tab_batch, text="Select Files for Batch Processing (Drag & Drop Supported)" if TKDND_AVAILABLE else "Select Files for Batch Processing")
        frame_files.pack(fill='both', expand=True, padx=10, pady=5)

        self.listbox_batch_files = tk.Listbox(frame_files)
        self.listbox_batch_files.pack(side='left', fill='both', expand=True)

        scrollbar = ttk.Scrollbar(frame_files, orient="vertical", command=self.listbox_batch_files.yview)
        scrollbar.pack(side='right', fill='y')
        self.listbox_batch_files.config(yscrollcommand=scrollbar.set)

        # Enable drag and drop
        self.enable_drag_and_drop(self.listbox_batch_files, "files")

        # Add context menu
        self.add_context_menu(self.listbox_batch_files, "files")

        # Button frame
        btn_frame = ttk.Frame(self.tab_batch)
        btn_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(btn_frame, text="Add Files", 
                  command=lambda: self.add_local_files(batch=True)).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Clear List", 
                  command=lambda: self.clear_local_files(batch=True)).pack(side='left', padx=5)
        
        # Output options frame
        output_frame = ttk.LabelFrame(self.tab_batch, text="Batch Processing Options")
        output_frame.pack(fill='x', padx=10, pady=5)
        
        # Output folder
        folder_frame = ttk.Frame(output_frame)
        folder_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(folder_frame, text="Output Folder:").pack(side='left', padx=5)
        self.batch_output_folder_var = tk.StringVar(value=os.path.join(os.getcwd(), "batch_output"))
        ttk.Entry(folder_frame, textvariable=self.batch_output_folder_var, width=40).pack(side='left', padx=5, fill='x', expand=True)
        ttk.Button(folder_frame, text="Browse...", command=self.browse_batch_output_folder).pack(side='left', padx=5)
        
        # Optimization options
        optim_frame = ttk.Frame(output_frame)
        optim_frame.pack(fill='x', padx=5, pady=5)
        
        self.batch_optimize_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(optim_frame, text="Optimize CIDR", variable=self.batch_optimize_var).pack(side='left', padx=5)
        self.batch_aggressive_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(optim_frame, text="Aggressive Optimization", variable=self.batch_aggressive_var).pack(side='left', padx=5)
        
        # Mask selection
        mask_frame = ttk.Frame(output_frame)
        mask_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(mask_frame, text="Apply Mask:").pack(side='left', padx=5)
        self.batch_mask_var = tk.StringVar(value=self.processor.config['default_mask'])
        self.batch_mask_combo = ttk.Combobox(mask_frame, textvariable=self.batch_mask_var)
        self.batch_mask_combo['values'] = self.processor.get_mask_names()
        self.batch_mask_combo.pack(side='left', padx=5)
        
        # Process and Stop buttons
        process_frame = ttk.Frame(self.tab_batch)
        process_frame.pack(pady=10)
        ttk.Button(process_frame, text="Process All Files", command=self.process_batch_files).pack(side='left', padx=5)
        self.stop_button = ttk.Button(process_frame, text="Stop Processing", command=self.stop_batch_processing, state='disabled')
        self.stop_button.pack(side='left', padx=5)
        
        # Progress frame
        progress_frame = ttk.LabelFrame(self.tab_batch, text="Progress")
        progress_frame.pack(fill='x', padx=10, pady=5)
        
        self.batch_progress_var = tk.StringVar(value="Ready for batch processing")
        ttk.Label(progress_frame, textvariable=self.batch_progress_var).pack(padx=5, pady=5)
        
        self.batch_progress_bar = ttk.Progressbar(progress_frame, mode="determinate")
        self.batch_progress_bar.pack(fill='x', padx=5, pady=5)
    
    def browse_batch_output_folder(self):
        """Browse for output folder for batch processing."""
        folder = filedialog.askdirectory(title="Select Output Folder")
        if folder:
            self.batch_output_folder_var.set(folder)
    
    def process_batch_files(self):
        """Обработка файлов в пакетном режиме с возможностью остановки."""
        files = self.listbox_batch_files.get(0, tk.END)
        if not files:
            messagebox.showwarning("Warning", "No files selected for batch processing.")
            return
        
        include_ipv4 = self.batch_ipv4_var.get()
        include_ipv6 = self.batch_ipv6_var.get()
        if not include_ipv4 and not include_ipv6:
            messagebox.showwarning("Warning", "At least one IP version (IPv4 or IPv6) must be selected.")
            return
        
        output_folder = self.batch_output_folder_var.get()
        mask_name = self.batch_mask_var.get()
        optimize = self.batch_optimize_var.get()
        aggressive = self.batch_aggressive_var.get()
        
        self.batch_progress_bar["value"] = 0
        self.batch_progress_bar["maximum"] = len(files)
        self.batch_progress_var.set("Starting batch processing...")
        
        # Создаем событие остановки
        self.stop_event = multiprocessing.Event()
        
        # Set up signal handlers in main thread
        def signal_handler(signum, frame):
            if hasattr(self, 'stop_event'):
                self.stop_event.set()
                self.batch_progress_var.set("Stopping batch processing (signal received)...")
        
        # Save original handlers to restore later
        original_sigint_handler = signal.getsignal(signal.SIGINT)
        original_sigterm_handler = signal.getsignal(signal.SIGTERM)
        
        # Set handlers for SIGINT and SIGTERM
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        def update_progress(processed, total):
            # Передаем значения processed и total через параметры по умолчанию
            self.root.after(0, lambda p=processed: self.batch_progress_bar.configure(value=p))
            progress_message = f"Processing: {processed}/{total} files"
            self.root.after(0, lambda msg=progress_message: self.batch_progress_var.set(msg))
        
        def process_files_thread():
            try:
                stats = self.processor.batch_process_files(
                    files, output_folder, mask_name, optimize, aggressive, include_ipv4, include_ipv6,
                    progress_callback=update_progress,
                    stop_event=self.stop_event
                )
                # Сохраняем сообщение о завершении
                completed_message = f"Completed: {stats['files_processed']}/{len(files)} files"
                self.root.after(0, lambda msg=completed_message: self.batch_progress_var.set(msg))
                
                if stats['errors']:
                    errors_msg = "\n".join(stats['errors'][:5])
                    if len(stats['errors']) > 5:
                        errors_msg += f"\n...and {len(stats['errors']) - 5} more errors"
                    error_summary = f"Processed {stats['files_processed']} out of {len(files)} files with errors:\n\n{errors_msg}"
                    self.root.after(0, lambda msg=error_summary: messagebox.showerror(
                        "Batch Processing Errors", msg
                    ))
                else:
                    success_message = (
                        f"Successfully processed {stats['files_processed']} files.\n"
                        f"Total IPs found: {stats['total_ips_found']}.\n"
                        f"Unique IPs: {stats['unique_ips']}.\n"
                        f"Optimized networks: {stats['optimized_networks'] if optimize else 'N/A'}.\n\n"
                        f"Results saved to: {output_folder}"
                    )
                    self.root.after(0, lambda msg=success_message: messagebox.showinfo(
                        "Batch Processing Complete", msg
                    ))
            except Exception as e:
                # Сохраняем сообщение об ошибке
                error_message = str(e)
                self.root.after(0, lambda msg=error_message: self.batch_progress_var.set(f"Error: {msg}"))
                self.root.after(0, lambda msg=error_message: messagebox.showerror("Batch Processing Error", msg))
            finally:
                # Отключаем кнопку Стоп после завершения
                self.root.after(0, lambda: self.stop_button.configure(state='disabled'))
                # Restore original signal handlers
                signal.signal(signal.SIGINT, original_sigint_handler)
                signal.signal(signal.SIGTERM, original_sigterm_handler)
        
        # Активируем кнопку Стоп
        self.stop_button['state'] = 'normal'
        processing_thread = threading.Thread(target=process_files_thread, daemon=True)
        processing_thread.start()
        
        # Сохраняем ссылку на поток
        self.processing_thread = processing_thread

    def stop_batch_processing(self):
        """Остановка пакетной обработки."""
        if hasattr(self, 'stop_event'):
            self.stop_event.set()
            self.batch_progress_var.set("Stopping batch processing...")
            
            # Terminate all child processes forcefully
            current_process = psutil.Process()
            children = current_process.children(recursive=True)
            for child in children:
                try:
                    child.terminate()
                except:
                    pass
            
            # Wait for processes to terminate
            _, still_alive = psutil.wait_procs(children, timeout=3)
            
            # Kill any remaining processes
            for process in still_alive:
                try:
                    process.kill()
                except:
                    pass
            
            self.stop_button['state'] = 'disabled'

    def setup_config_tab(self):
        """Set up the configuration import/export tab."""
        config_frame = ttk.LabelFrame(self.tab_config, text="Configuration Management")
        config_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Export section
        export_frame = ttk.Frame(config_frame)
        export_frame.pack(fill='x', padx=5, pady=10)
        
        ttk.Label(export_frame, text="Export Configuration:").pack(side='left', padx=5)
        btn_export = ttk.Button(export_frame, text="Export...", command=self.export_config_gui)
        btn_export.pack(side='left', padx=10)
        
        # Import section
        import_frame = ttk.Frame(config_frame)
        import_frame.pack(fill='x', padx=5, pady=10)
        
        ttk.Label(import_frame, text="Import Configuration:").pack(side='left', padx=5)
        btn_import = ttk.Button(import_frame, text="Import...", command=self.import_config_gui)
        btn_import.pack(side='left', padx=10)
        
        # Reset section
        reset_frame = ttk.Frame(config_frame)
        reset_frame.pack(fill='x', padx=5, pady=10)
        
        ttk.Label(reset_frame, text="Reset to Default:").pack(side='left', padx=5)
        btn_reset = ttk.Button(reset_frame, text="Reset Configuration", 
                              command=self.reset_config_gui)
        btn_reset.pack(side='left', padx=10)
        
        # Warning
        ttk.Label(config_frame, 
                 text="Warning: Importing or resetting configuration will replace all current masks!",
                 foreground="red").pack(pady=10)
    
    def export_config_gui(self):
        """Export configuration to a file via GUI."""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".yaml",
            filetypes=[("YAML files", "*.yaml"), ("All files", "*.*")],
            title="Export Configuration"
        )
        
        if file_path:
            if self.processor.export_config(file_path):
                messagebox.showinfo("Success", f"Configuration exported to {file_path}")
            else:
                messagebox.showerror("Error", "Failed to export configuration")
    
    def import_config_gui(self):
        """Import configuration from a file via GUI."""
        file_path = filedialog.askopenfilename(
            filetypes=[("YAML files", "*.yaml"), ("All files", "*.*")],
            title="Import Configuration"
        )
        
        if file_path:
            if messagebox.askyesno("Confirm Import", 
                                  "Importing will replace your current configuration. Continue?"):
                if self.processor.import_config(file_path):
                    messagebox.showinfo("Success", "Configuration imported successfully")
                    self.refresh_masks()
                else:
                    messagebox.showerror("Error", "Failed to import configuration. Invalid format.")
    
    def reset_config_gui(self):
        """Reset configuration to default via GUI."""
        if messagebox.askyesno("Confirm Reset", 
                              "This will reset all settings to default. Continue?"):
            self.processor.config = copy.deepcopy(self.processor.default_config)
            self.processor.save_config()
            messagebox.showinfo("Success", "Configuration reset to default")
            self.refresh_masks()

    # File Processing Tab Methods
    def add_local_files(self, optimize=False, batch=False):
        """Add local files to the appropriate listbox."""
        files = filedialog.askopenfilenames(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        listbox = self.listbox_files_optimize if optimize else (self.listbox_batch_files if batch else self.listbox_files)
        for file in files:
            if file not in listbox.get(0, tk.END):
                listbox.insert(tk.END, file)

    def clear_local_files(self, optimize=False, batch=False):
        """Clear the appropriate files listbox."""
        listbox = self.listbox_files_optimize if optimize else (self.listbox_batch_files if batch else self.listbox_files)
        listbox.delete(0, tk.END)

    def process_local_files(self):
        """Process files to extract and format IP addresses."""
        include_ipv4 = self.process_ipv4_var.get()
        include_ipv6 = self.process_ipv6_var.get()
        if not include_ipv4 and not include_ipv6:
            messagebox.showwarning("Warning", "At least one IP version (IPv4 or IPv6) must be selected.")
            return
        
        files = self.listbox_files.get(0, tk.END)
        if not files:
            messagebox.showwarning("Warning", "No files selected.")
            return
        
        all_cidrs = []
        for file in files:
            try:
                with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                all_cidrs.extend(self.processor.process_input_to_ips(content, include_ipv4, include_ipv6))
            except Exception as e:
                messagebox.showerror("Error", f"Error processing file {file}: {e}")
                return
        
        unique_cidrs = list(set(all_cidrs))
        sorted_cidrs = self.processor.sort_ip_addresses(unique_cidrs)
        mask_name = self.process_mask_var.get()
        formatted_content = self.processor.apply_mask(sorted_cidrs, mask_name)
        
        output_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if output_path:
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(formatted_content)
                messagebox.showinfo("Success", f"Processed {len(sorted_cidrs)} IPs saved to: {output_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Error saving results: {e}")

    def convert_range_to_cidr(self):
        """Convert IP range to CIDR notation."""
        include_ipv4 = self.ranges_ipv4_var.get()
        include_ipv6 = self.ranges_ipv6_var.get()
        if not include_ipv4 and not include_ipv6:
            messagebox.showwarning("Warning", "At least one IP version (IPv4 or IPv6) must be selected.")
            return
        
        start_ip = self.range_start_var.get().strip()
        end_ip = self.range_end_var.get().strip()
        
        if not start_ip or not end_ip:
            messagebox.showwarning("Warning", "Please enter both start and end IP addresses.")
            return
        
        is_ipv6 = ':' in start_ip or ':' in end_ip
        if is_ipv6 and not include_ipv6:
            messagebox.showwarning("Warning", "IPv6 addresses are not included. Please check 'Include IPv6'.")
            return
        if not is_ipv6 and not include_ipv4:
            messagebox.showwarning("Warning", "IPv4 addresses are not included. Please check 'Include IPv4'.")
            return
        
        if is_ipv6:
            if not self.processor.is_valid_ipv6(start_ip) or not self.processor.is_valid_ipv6(end_ip):
                messagebox.showerror("Error", "Invalid IPv6 address format.")
                return
        else:
            if not self.processor.is_valid_ipv4(start_ip) or not self.processor.is_valid_ipv4(end_ip):
                messagebox.showerror("Error", "Invalid IPv4 address format.")
                return
        
        cidrs = self.processor.range_to_cidrs(start_ip, end_ip)
        if not cidrs:
            messagebox.showwarning("Warning", "Could not convert range to CIDR.")
            return
        
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "IP Range to CIDR Results:\n\n")
        self.results_text.insert(tk.END, f"Range: {start_ip} - {end_ip}\n\n")
        self.results_text.insert(tk.END, "CIDR Notations:\n")
        for cidr in cidrs:
            self.results_text.insert(tk.END, f"{cidr}\n")
    
    def convert_cidr_to_range(self):
        """Convert CIDR notation to IP range with detailed output."""
        include_ipv4 = self.ranges_ipv4_var.get()
        include_ipv6 = self.ranges_ipv6_var.get()
        if not include_ipv4 and not include_ipv6:
            messagebox.showwarning("Warning", "At least one IP version (IPv4 or IPv6) must be selected.")
            return
        
        cidr = self.cidr_var.get().strip()
        if not cidr:
            messagebox.showwarning("Warning", "Please enter a CIDR notation.")
            return
        
        is_ipv6 = ':' in cidr
        if is_ipv6 and not include_ipv6:
            messagebox.showwarning("Warning", "IPv6 CIDR is not included. Please check 'Include IPv6'.")
            return
        if not is_ipv6 and not include_ipv4:
            messagebox.showwarning("Warning", "IPv4 CIDR is not included. Please check 'Include IPv4'.")
            return
        
        try:
            # Parse the CIDR
            network = ipaddress.ip_network(cidr, strict=False)
            
            # Validate CIDR based on IP version
            if is_ipv6 and not isinstance(network, ipaddress.IPv6Network):
                raise ValueError("Invalid IPv6 CIDR notation format.")
            elif not is_ipv6 and not isinstance(network, ipaddress.IPv4Network):
                raise ValueError("Invalid IPv4 CIDR notation format.")
            
            # Get network details
            first_ip = network.network_address
            last_ip = network.broadcast_address
            prefix_length = network.prefixlen
            netmask = network.netmask if not is_ipv6 else "N/A"  # Netmask not typically used for IPv6
            
            # Convert IPs to decimal
            first_ip_decimal = int(first_ip)
            last_ip_decimal = int(last_ip)
            
            # Calculate total number of hosts
            total_hosts = network.num_addresses
            
            # Format IPs with uppercase hex for IPv6
            first_ip_str = str(first_ip).upper() if is_ipv6 else str(first_ip)
            last_ip_str = str(last_ip).upper() if is_ipv6 else str(last_ip)
            
            # Prepare output
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, "CIDR to IP Range Results:\n\n")
            self.results_text.insert(tk.END, f"CIDR Range\t{cidr}\n")
            self.results_text.insert(tk.END, f"Network\t{first_ip_str}\n")
            self.results_text.insert(tk.END, f"Broadcast\t{last_ip_str}\n")
            if not is_ipv6:
                self.results_text.insert(tk.END, f"Netmask\t{netmask}\n")
            self.results_text.insert(tk.END, f"Prefix Length\t/{prefix_length}\n")
            self.results_text.insert(tk.END, f"First IP\t{first_ip_str}\n")
            self.results_text.insert(tk.END, f"First IP (Decimal)\t{first_ip_decimal}\n")
            self.results_text.insert(tk.END, f"Last IP\t{last_ip_str}\n")
            self.results_text.insert(tk.END, f"Last IP (Decimal)\t{last_ip_decimal}\n")
            self.results_text.insert(tk.END, f"Total Host\t{total_hosts:,}\n")
            
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid CIDR notation: {e}")
        except Exception as e:
            messagebox.showerror("Error", f"Error processing CIDR: {e}")

    def copy_results(self):
        """Copy results text to clipboard."""
        self.root.clipboard_clear()
        self.root.clipboard_append(self.results_text.get(1.0, tk.END))
        messagebox.showinfo("Copied", "Results copied to clipboard.")

    def clear_results(self):
        """Clear results text."""
        self.results_text.delete(1.0, tk.END)

    def save_results(self):
        """Save results to a file."""
        content = self.results_text.get(1.0, tk.END).strip()
        if not content:
            messagebox.showwarning("Warning", "No results to save.")
            return
        output_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if output_path:
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo("Success", f"Results saved to: {output_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Error saving results: {e}")

    # CIDR Optimization Tab Methods
    def optimize_files(self):
        """Optimize CIDR notations from files."""
        include_ipv4 = self.optimize_ipv4_var.get()
        include_ipv6 = self.optimize_ipv6_var.get()
        if not include_ipv4 and not include_ipv6:
            messagebox.showwarning("Warning", "At least one IP version (IPv4 or IPv6) must be selected.")
            return
        
        files = self.listbox_files_optimize.get(0, tk.END)
        if not files:
            messagebox.showwarning("Warning", "No files selected.")
            return
        
        all_cidrs = []
        for file in files:
            try:
                with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                cidrs = self.processor.process_input_to_ips(content, include_ipv4, include_ipv6)
                all_cidrs.extend(cidrs)
            except Exception as e:
                messagebox.showerror("Error", f"Error processing file {file}: {e}")
                return
        
        unique_cidrs = list(set(all_cidrs))
        aggressive = self.aggressive_var.get()
        optimized_cidrs = self.processor.optimize_cidr_list(unique_cidrs, aggressive)
        sorted_cidrs = self.processor.sort_ip_addresses(optimized_cidrs)
        mask_name = self.optimize_mask_var.get()
        formatted_content = self.processor.apply_mask(sorted_cidrs, mask_name)
        
        output_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if output_path:
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(formatted_content)
                messagebox.showinfo("Success", f"Optimized {len(unique_cidrs)} IPs into {len(sorted_cidrs)} networks.\nResults saved to: {output_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Error saving results: {e}")

    def add_url(self):
        """Add a URL to the URL listbox with validation."""
        url = simpledialog.askstring("Add URL", "Enter URL:")
        if url:
            url = url.strip()
            if not self.validate_url(url):
                messagebox.showwarning("Invalid URL", "The entered URL is not valid. Please enter a valid URL starting with http:// or https://")
                return
            if url not in self.listbox_urls.get(0, tk.END):
                self.listbox_urls.insert(tk.END, url)
                self.update_status_bar(f"Added URL: {url[:50]}...")
            else:
                messagebox.showinfo("Duplicate", "This URL is already in the list.")

    def clear_urls(self):
        """Clear the URL listbox."""
        self.listbox_urls.delete(0, tk.END)

    def process_urls(self):
        """Process URLs to extract and format IP addresses."""
        include_ipv4 = self.url_ipv4_var.get()
        include_ipv6 = self.url_ipv6_var.get()
        if not include_ipv4 and not include_ipv6:
            messagebox.showwarning("Warning", "At least one IP version (IPv4 or IPv6) must be selected.")
            return
        
        urls = self.listbox_urls.get(0, tk.END)
        if not urls:
            messagebox.showwarning("Warning", "No URLs added.")
            return
        
        output_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if not output_path:
            return

        mask_name = self.url_mask_var.get()
        should_optimize = self.url_optimize_var.get()
        self.update_status_bar("Processing URLs...")

        def process_urls_thread():
            try:
                all_cidrs = []
                errors = []
                for url in urls:
                    content = self.processor.download_file(url)
                    if not content:
                        errors.append(f"No content downloaded from {url}")
                        continue
                    all_cidrs.extend(self.processor.process_input_to_ips(content, include_ipv4, include_ipv6))

                unique_cidrs = list(set(all_cidrs))
                if should_optimize:
                    optimized_cidrs = self.processor.optimize_cidr_list(unique_cidrs)
                    sorted_cidrs = self.processor.sort_ip_addresses(optimized_cidrs)
                else:
                    sorted_cidrs = self.processor.sort_ip_addresses(unique_cidrs)

                formatted_content = self.processor.apply_mask(sorted_cidrs, mask_name)
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(formatted_content)

                message = f"Processed {len(unique_cidrs)} IPs"
                if should_optimize:
                    message += f" and optimized to {len(sorted_cidrs)} networks"
                message += f".\nResults saved to: {output_path}"
                if errors:
                    message += f"\n\nWarnings:\n" + "\n".join(errors[:5])

                self.root.after(0, lambda: self.update_status_bar("Ready"))
                self.root.after(0, lambda msg=message: messagebox.showinfo("Success", msg))
            except Exception as e:
                error_message = str(e)
                self.root.after(0, lambda: self.update_status_bar("Ready"))
                self.root.after(0, lambda msg=error_message: messagebox.showerror("Error", f"Error processing URLs: {msg}"))

        threading.Thread(target=process_urls_thread, daemon=True).start()

    # Mask Settings Tab Methods
    def add_new_mask(self):
        """Add a new mask to the configuration."""
        name = self.new_mask_name.get().strip()
        prefix = self.new_mask_prefix.get()
        suffix = self.new_mask_suffix.get()
        separator = self.new_mask_separator.get().replace('\\n', '\n').replace('\\t', '\t')
        category = self.new_mask_category.get()
        description = self.new_mask_description.get()

        if not name:
            messagebox.showwarning("Warning", "Mask name is required.")
            return

        if self.processor.add_mask(name, prefix, suffix, separator, category, description):
            messagebox.showinfo("Success", f"Mask '{name}' added successfully.")
            self.update_mask_display(self.mask_frame)
            self.refresh_mask_comboboxes()
            # Refresh category filter
            if hasattr(self, 'mask_category_combo'):
                self.mask_category_combo['values'] = ['All'] + self.processor.get_mask_categories()
            # Clear form
            self.new_mask_name.set("")
            self.new_mask_prefix.set("")
            self.new_mask_suffix.set("")
            self.new_mask_separator.set("\\n")
            self.new_mask_category.set("Custom")
            self.new_mask_description.set("")

    def edit_mask(self, name):
        """Edit an existing mask."""
        mask = self.processor.get_mask_by_name(name)
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Edit Mask: {name}")
        dialog.geometry("450x400")

        ttk.Label(dialog, text="Name:").grid(row=0, column=0, padx=10, pady=10, sticky='w')
        name_var = tk.StringVar(value=mask['name'])
        ttk.Entry(dialog, textvariable=name_var, width=30).grid(row=0, column=1, padx=10, pady=10, sticky='w')

        ttk.Label(dialog, text="Category:").grid(row=1, column=0, padx=10, pady=10, sticky='w')
        category_var = tk.StringVar(value=mask.get('category', 'Custom'))
        category_combo = ttk.Combobox(dialog, textvariable=category_var, width=28)
        category_combo['values'] = self.processor.get_mask_categories() + ['Custom']
        category_combo.grid(row=1, column=1, padx=10, pady=10, sticky='w')

        ttk.Label(dialog, text="Prefix:").grid(row=2, column=0, padx=10, pady=10, sticky='w')
        prefix_var = tk.StringVar(value=mask.get('prefix', ''))
        ttk.Entry(dialog, textvariable=prefix_var, width=30).grid(row=2, column=1, padx=10, pady=10, sticky='w')

        ttk.Label(dialog, text="Suffix:").grid(row=3, column=0, padx=10, pady=10, sticky='w')
        suffix_var = tk.StringVar(value=mask.get('suffix', ''))
        ttk.Entry(dialog, textvariable=suffix_var, width=30).grid(row=3, column=1, padx=10, pady=10, sticky='w')

        ttk.Label(dialog, text="Separator:").grid(row=4, column=0, padx=10, pady=10, sticky='w')
        separator_var = tk.StringVar(value=mask.get('separator', '\n').replace('\n', '\\n').replace('\t', '\\t'))
        ttk.Entry(dialog, textvariable=separator_var, width=30).grid(row=4, column=1, padx=10, pady=10, sticky='w')

        ttk.Label(dialog, text="Description:").grid(row=5, column=0, padx=10, pady=10, sticky='w')
        description_var = tk.StringVar(value=mask.get('description', ''))
        ttk.Entry(dialog, textvariable=description_var, width=30).grid(row=5, column=1, padx=10, pady=10, sticky='w')

        ttk.Label(dialog, text="Note: Use \\n for newline, \\t for tab").grid(row=6, column=0, columnspan=2, padx=10, pady=5, sticky='w')

        def save_changes():
            new_name = name_var.get().strip()
            new_prefix = prefix_var.get()
            new_suffix = suffix_var.get()
            new_separator = separator_var.get().replace('\\n', '\n').replace('\\t', '\t')
            new_category = category_var.get()
            new_description = description_var.get()
            if not new_name:
                messagebox.showwarning("Warning", "Mask name is required.")
                return
            if new_name != name and any(m['name'] == new_name for m in self.processor.get_masks()):
                messagebox.showwarning("Warning", f"Mask '{new_name}' already exists.")
                return
            if new_name != name:
                self.processor.remove_mask(name)
            if self.processor.add_mask(new_name, new_prefix, new_suffix, new_separator, new_category, new_description):
                dialog.destroy()
                self.update_mask_display(self.mask_frame)
                self.refresh_mask_comboboxes()
                # Refresh category filter
                if hasattr(self, 'mask_category_combo'):
                    self.mask_category_combo['values'] = ['All'] + self.processor.get_mask_categories()

        ttk.Button(dialog, text="Save Changes", command=save_changes).grid(row=7, column=0, columnspan=2, pady=15)
        dialog.transient(self.root)
        dialog.grab_set()
        self.root.wait_window(dialog)

    def preview_mask(self):
        """Preview the mask being created with sample IPs."""
        prefix = self.new_mask_prefix.get()
        suffix = self.new_mask_suffix.get()
        separator = self.new_mask_separator.get().replace('\\n', '\n').replace('\\t', '\t')

        # Sample IPs for preview
        sample_ips = ['192.168.1.0/24', '10.0.0.0/8', '172.16.0.0/12']

        # Apply mask
        formatted = []
        for ip in sample_ips:
            formatted.append(f"{prefix}{ip}{suffix}")

        result = separator.join(formatted)

        # Show preview dialog
        preview_dialog = tk.Toplevel(self.root)
        preview_dialog.title("Mask Preview")
        preview_dialog.geometry("500x300")

        ttk.Label(preview_dialog, text="Preview with sample IPs:", font=('Arial', 10, 'bold')).pack(padx=10, pady=10, anchor='w')

        # Text widget for preview
        text_widget = tk.Text(preview_dialog, wrap='word', height=10, width=60)
        text_widget.pack(padx=10, pady=5, fill='both', expand=True)
        text_widget.insert('1.0', result)
        text_widget.config(state='disabled')

        # Copy button
        def copy_preview():
            self.root.clipboard_clear()
            self.root.clipboard_append(result)
            messagebox.showinfo("Copied", "Preview copied to clipboard", parent=preview_dialog)

        btn_frame = ttk.Frame(preview_dialog)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Copy", command=copy_preview).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Close", command=preview_dialog.destroy).pack(side='left', padx=5)

        preview_dialog.transient(self.root)
        preview_dialog.grab_set()

    def preview_existing_mask(self, mask):
        """Preview an existing mask with sample IPs."""
        prefix = mask.get('prefix', '')
        suffix = mask.get('suffix', '')
        separator = mask.get('separator', '\n')
        name = mask.get('name', 'Unknown')
        description = mask.get('description', '')

        # Sample IPs for preview
        sample_ips = ['192.168.1.0/24', '10.0.0.0/8', '172.16.0.0/12']

        # Apply mask
        formatted = []
        for ip in sample_ips:
            formatted.append(f"{prefix}{ip}{suffix}")

        result = separator.join(formatted)

        # Show preview dialog
        preview_dialog = tk.Toplevel(self.root)
        preview_dialog.title(f"Preview: {name}")
        preview_dialog.geometry("600x400")

        # Info frame
        info_frame = ttk.LabelFrame(preview_dialog, text="Mask Details")
        info_frame.pack(padx=10, pady=5, fill='x')

        ttk.Label(info_frame, text=f"Name: {name}", font=('Arial', 9, 'bold')).pack(padx=5, pady=2, anchor='w')
        ttk.Label(info_frame, text=f"Category: {mask.get('category', 'Custom')}").pack(padx=5, pady=2, anchor='w')
        if description:
            ttk.Label(info_frame, text=f"Description: {description}", font=('Arial', 8), foreground='gray').pack(padx=5, pady=2, anchor='w')

        ttk.Label(preview_dialog, text="Preview with sample IPs:", font=('Arial', 10, 'bold')).pack(padx=10, pady=5, anchor='w')

        # Text widget for preview
        text_widget = tk.Text(preview_dialog, wrap='word', height=12, width=70)
        text_widget.pack(padx=10, pady=5, fill='both', expand=True)
        text_widget.insert('1.0', result)
        text_widget.config(state='disabled')

        # Buttons
        def copy_preview():
            self.root.clipboard_clear()
            self.root.clipboard_append(result)
            messagebox.showinfo("Copied", "Preview copied to clipboard", parent=preview_dialog)

        btn_frame = ttk.Frame(preview_dialog)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Copy", command=copy_preview).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Edit", command=lambda: [preview_dialog.destroy(), self.edit_mask(name)]).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Close", command=preview_dialog.destroy).pack(side='left', padx=5)

        preview_dialog.transient(self.root)
        preview_dialog.grab_set()

    def duplicate_mask_dialog(self, original_name):
        """Show dialog to duplicate a mask with a new name."""
        new_name = simpledialog.askstring(
            "Duplicate Mask",
            f"Enter a new name for the copy of '{original_name}':",
            parent=self.root
        )

        if new_name:
            new_name = new_name.strip()
            if not new_name:
                messagebox.showwarning("Warning", "Mask name cannot be empty.")
                return

            # Check if name already exists
            if any(m['name'] == new_name for m in self.processor.get_masks()):
                messagebox.showwarning("Warning", f"A mask with name '{new_name}' already exists.")
                return

            # Duplicate the mask
            if self.processor.duplicate_mask(original_name, new_name):
                messagebox.showinfo("Success", f"Mask '{original_name}' duplicated as '{new_name}'.")
                self.update_mask_display(self.mask_frame)
                self.refresh_mask_comboboxes()
            else:
                messagebox.showerror("Error", f"Failed to duplicate mask '{original_name}'.")

    def delete_mask(self, name):
        """Delete a mask from the configuration."""
        if name == 'default':
            messagebox.showwarning("Warning", "Cannot delete the default mask.")
            return
        if messagebox.askyesno("Confirm", f"Are you sure you want to delete mask '{name}'?"):
            if self.processor.remove_mask(name):
                messagebox.showinfo("Success", f"Mask '{name}' deleted successfully.")
                self.update_mask_display(self.mask_frame)
                self.refresh_mask_comboboxes()
    def set_default_mask(self):
        """Set the default mask."""
        name = self.default_mask_var.get()
        if not name:
            messagebox.showwarning("Warning", "No mask selected.")
            return
            
        if self.processor.set_default_mask(name):
            messagebox.showinfo("Success", f"Default mask set to '{name}'.")
        else:
            messagebox.showerror("Error", f"Failed to set default mask to '{name}'.")

    def refresh_masks(self):
        """Refresh the mask display and comboboxes."""
        self.update_mask_display(self.mask_frame)
        self.refresh_mask_comboboxes()

    def cleanup(self):
        """Clean up any running processes when the application exits."""
        # Terminate all child processes
        current_process = psutil.Process()
        children = current_process.children(recursive=True)
        for child in children:
            try:
                child.terminate()
            except:
                pass
        
        # Wait for processes to terminate
        _, still_alive = psutil.wait_procs(children, timeout=3)
        
        # Kill any remaining processes
        for process in still_alive:
            try:
                process.kill()
            except:
                pass
    
    def on_closing(self):
        """Handle window close event."""
        self.cleanup()
        self.root.destroy()

if __name__ == "__main__":
    processor = IPCIDRProcessor()
    app = IPCIDRProcessorGUI(processor)
