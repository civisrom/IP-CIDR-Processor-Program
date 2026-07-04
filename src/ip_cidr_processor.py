import argparse
import os
import re
import copy
import hashlib
import yaml
import signal
import sys
import atexit
import multiprocessing
import concurrent.futures
import threading
import ipaddress
import requests
from typing import List, Dict, Set, Union, Tuple, Optional
from urllib.parse import urlparse


class SafeFormatDict(dict):
    """Keep unknown template placeholders visible instead of failing formatting."""
    def __missing__(self, key):
        return '{' + key + '}'


try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, simpledialog
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False

    class _TkFallback:
        END = 'end'

        def __getattr__(self, name):
            return object

    tk = _TkFallback()
    ttk = _TkFallback()
    filedialog = _TkFallback()
    messagebox = _TkFallback()
    simpledialog = _TkFallback()

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None
    PSUTIL_AVAILABLE = False

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


SUPPORTED_DROP_EXTENSIONS = ('.txt', '.log', '.dat', '.csv', '.json', '.yaml', '.yml')
EXTRACTION_MODES = ('smart', 'strict')
FILTER_DEFAULTS = {
    'public_only': False,
    'exclude_private': False,
    'exclude_loopback': False,
    'exclude_link_local': False,
    'exclude_multicast': False,
    'exclude_reserved': False,
    'exclude_unspecified': False,
}


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
                {
                    'name': 'keenetic-webadmin-udp-41495',
                    'category': 'Router',
                    'prefix': '',
                    'suffix': '',
                    'separator': '\n',
                    'header': 'access-list _WEBADMIN_GigabitEthernet1',
                    'line_template': '    permit udp {network} {netmask} 0.0.0.0 0.0.0.0 port eq 41495\n    permit description winmobile',
                    'footer': '    deny udp 0.0.0.0 0.0.0.0 0.0.0.0 0.0.0.0 port eq 443',
                    'ip_version': 4,
                    'description': 'Keenetic ACL for _WEBADMIN_GigabitEthernet1 UDP 41495 with winmobile description and UDP 443 deny'
                },

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
                normalized_mask = {
                    'name': name,
                    'prefix': str(mask.get('prefix', '')),
                    'suffix': str(mask.get('suffix', '')),
                    'separator': str(mask.get('separator', '\n')),
                    'category': str(mask.get('category', 'Custom')),
                    'description': str(mask.get('description', ''))
                }
                for optional_key in ('line_template', 'header', 'footer'):
                    if optional_key in mask and mask.get(optional_key) is not None:
                        normalized_mask[optional_key] = str(mask.get(optional_key, ''))
                variables = self._normalize_mask_variables(mask.get('variables'))
                if variables:
                    normalized_mask['variables'] = variables
                if mask.get('ip_version') in (4, 6, '4', '6'):
                    normalized_mask['ip_version'] = int(mask['ip_version'])
                self._upgrade_builtin_mask(normalized_mask)
                valid_masks.append(normalized_mask)

        if valid_masks:
            self._append_default_mask_if_missing(valid_masks, seen_names, 'keenetic-webadmin-udp-41495')
            normalized['masks'] = valid_masks

        mask_names = {mask['name'] for mask in normalized['masks']}
        default_mask = config.get('default_mask')
        if isinstance(default_mask, str) and default_mask in mask_names:
            normalized['default_mask'] = default_mask

        custom_range_pattern = config.get('custom_range_pattern')
        if isinstance(custom_range_pattern, str):
            normalized['custom_range_pattern'] = custom_range_pattern

        return normalized

    def _append_default_mask_if_missing(self, masks: List[Dict], seen_names: Set[str], name: str) -> None:
        """Append a new built-in mask to existing configs without replacing user masks."""
        if name in seen_names:
            return
        default_mask = next((mask for mask in self.default_config['masks'] if mask['name'] == name), None)
        if default_mask:
            masks.append(copy.deepcopy(default_mask))
            seen_names.add(name)

    def _normalize_mask_variables(self, variables: Optional[Dict]) -> Dict[str, str]:
        """Return safe string template variables for mask formatting."""
        if not isinstance(variables, dict):
            return {}
        normalized = {}
        for key, value in variables.items():
            key = str(key).strip()
            if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key):
                continue
            normalized[key] = str(value)
        return normalized

    def parse_mask_variables_text(self, text: str) -> Dict[str, str]:
        """Parse key=value mask variables from GUI text."""
        variables = {}
        for chunk in re.split(r'[\n,;]+', text or ''):
            if '=' not in chunk:
                continue
            key, value = chunk.split('=', 1)
            key = key.strip()
            value = value.strip().replace('\\n', '\n').replace('\\t', '\t')
            if key:
                variables[key] = value
        return self._normalize_mask_variables(variables)

    def format_mask_variables_text(self, variables: Optional[Dict]) -> str:
        """Format mask variables for GUI editing."""
        normalized = self._normalize_mask_variables(variables)
        parts = []
        for key, value in normalized.items():
            display_value = value.replace('\n', '\\n').replace('\t', '\\t')
            parts.append(f"{key}={display_value}")
        return ', '.join(parts)

    def _upgrade_builtin_mask(self, mask: Dict) -> None:
        """Bring older built-in mask definitions forward without touching unrelated custom masks."""
        if mask.get('name') != 'keenetic-webadmin-udp-41495':
            return

        default_mask = next((item for item in self.default_config['masks'] if item['name'] == mask['name']), None)
        if not default_mask:
            return

        old_line_templates = {
            '    permit {protocol} {network} {netmask} 0.0.0.0 0.0.0.0 port eq {permit_port}\n    permit description {rule_description}',
            '    permit udp {network} {netmask} 0.0.0.0 0.0.0.0 port eq 41495',
            '    permit udp {network} {netmask} 0.0.0.0 0.0.0.0 port eq 41495\n    permit description example',
            '    permit udp {network} {netmask} 0.0.0.0 0.0.0.0 port eq 41495\n    permit description winmobile',
        }
        if not mask.get('line_template') or mask.get('line_template') in old_line_templates:
            mask['line_template'] = default_mask['line_template']
        old_footers = {
            '    deny {protocol} 0.0.0.0 0.0.0.0 0.0.0.0 0.0.0.0 port eq {deny_port}',
            '    deny udp 0.0.0.0 0.0.0.0 0.0.0.0 0.0.0.0 port eq 443',
        }
        if not mask.get('footer') or mask.get('footer') in old_footers:
            mask['footer'] = default_mask['footer']
        if not mask.get('header'):
            mask['header'] = default_mask['header']
        if mask.get('ip_version') not in (4, 6):
            mask['ip_version'] = default_mask['ip_version']

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
                 category: str = 'Custom', description: str = '',
                 line_template: str = '', header: str = '', footer: str = '',
                 ip_version: Optional[int] = None,
                 variables: Optional[Dict[str, str]] = None) -> bool:
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
        if line_template:
            new_mask['line_template'] = line_template
        if header:
            new_mask['header'] = header
        if footer:
            new_mask['footer'] = footer
        normalized_variables = self._normalize_mask_variables(variables)
        if normalized_variables:
            new_mask['variables'] = normalized_variables
        if ip_version in (4, 6):
            new_mask['ip_version'] = ip_version
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
        for optional_key in ('line_template', 'header', 'footer', 'ip_version', 'variables'):
            if optional_key in original:
                new_mask[optional_key] = copy.deepcopy(original[optional_key])
        self.config['masks'].append(new_mask)
        return self.save_config()

    def extract_ips(self, text: str, include_ipv4: bool = True, include_ipv6: bool = True,
                    extraction_mode: str = 'smart') -> List[str]:
        """Extract IPv4 and/or IPv6 addresses and CIDR notations from text based on settings."""
        named_prefixes = self._extract_named_prefix_tokens(text, include_ipv4, include_ipv6)
        if named_prefixes:
            return named_prefixes

        text_without_ranges = self._remove_range_spans(text, include_ipv4, include_ipv6)
        if extraction_mode == 'strict':
            return self._extract_strict_valid_ip_tokens(text_without_ranges, include_ipv4, include_ipv6)
        return self._extract_valid_ip_tokens(text_without_ranges, include_ipv4, include_ipv6)

    def _extract_named_prefix_tokens(self, text: str, include_ipv4: bool = True,
                                     include_ipv6: bool = True) -> List[str]:
        """Prefer explicit JSON prefix fields over unrelated IP values in the same document."""
        if not text or (not include_ipv4 and not include_ipv6):
            return []

        key_names = []
        if include_ipv4:
            key_names.append('ipv4Prefix')
        if include_ipv6:
            key_names.append('ipv6Prefix')
        if not key_names:
            return []

        key_pattern = '|'.join(re.escape(key) for key in key_names)
        prefix_pattern = re.compile(
            rf'["\'](?:{key_pattern})["\']\s*:\s*["\']([^"\']+)["\']',
            re.IGNORECASE,
        )
        prefixes = []
        seen = set()
        for match in prefix_pattern.finditer(text):
            token = match.group(1).strip()
            normalized = self._normalize_ip_token(token, include_ipv4, include_ipv6)
            if normalized and normalized not in seen:
                seen.add(normalized)
                prefixes.append(normalized)
        return prefixes
    
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

    def _extract_strict_valid_ip_tokens(self, text: str, include_ipv4: bool = True,
                                        include_ipv6: bool = True) -> List[str]:
        """Extract only standalone IP/CIDR tokens after trimming common list syntax."""
        if not include_ipv4 and not include_ipv6:
            return []

        results = []
        seen = set()
        separators = re.compile(r'[\s,;]+')
        wrappers = '"\'[](){}<>'
        for raw_token in separators.split(text):
            token = raw_token.strip(wrappers)
            if not token:
                continue
            normalized = self._normalize_ip_token(token, include_ipv4, include_ipv6)
            if normalized and normalized not in seen:
                seen.add(normalized)
                results.append(normalized)
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

    def get_suspicious_tokens(self, text: str, include_ipv4: bool = True,
                              include_ipv6: bool = True) -> List[Dict[str, str]]:
        """Find values that look like IP/CIDR/range data but fail validation."""
        suspicious = []
        seen = set()

        def add(value: str, reason: str) -> None:
            key = (value, reason)
            if value and key not in seen:
                seen.add(key)
                suspicious.append({'value': value, 'reason': reason})

        if include_ipv4:
            ipv4_like = re.compile(r'(?<![A-Za-z0-9_.-])(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,3})?)(?![A-Za-z0-9_.-])')
            for match in ipv4_like.finditer(text):
                token = match.group(1)
                if self._normalize_ip_token(token, include_ipv4=True, include_ipv6=False) is None:
                    add(token, 'Invalid IPv4 or IPv4 CIDR')

        if include_ipv6:
            ipv6_like = re.compile(r'(?<![A-Za-z0-9:.])([0-9A-Fa-f:.]*:[0-9A-Fa-f:.]+/\d{1,3})(?![A-Za-z0-9:.])')
            for match in ipv6_like.finditer(text):
                token = match.group(1)
                if self._normalize_ip_token(token, include_ipv4=False, include_ipv6=True) is None:
                    add(token, 'Invalid IPv6 CIDR')

        range_like = re.compile(
            r'(?<![0-9A-Fa-f:.])'
            r'((?:\d{1,3}(?:\.\d{1,3}){3})|(?:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]+))'
            r'\s*-\s*'
            r'((?:\d{1,3}(?:\.\d{1,3}){3})|(?:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]+))'
            r'(?![0-9A-Fa-f:.])'
        )
        for match in range_like.finditer(text):
            start_token, end_token = match.group(1), match.group(2)
            try:
                start = ipaddress.ip_address(start_token)
                end = ipaddress.ip_address(end_token)
            except ValueError:
                add(match.group(0), 'Invalid IP range endpoint')
                continue
            if start.version != end.version:
                add(match.group(0), 'Mixed IPv4/IPv6 range')

        return suspicious

    def _parse_networks(self, cidr_list: List[str]) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
        """Parse valid IPv4/IPv6 networks from strings."""
        networks = []
        for cidr in cidr_list:
            try:
                networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                continue
        return networks

    def _normalize_filter_options(self, filters: Optional[Dict[str, bool]]) -> Dict[str, bool]:
        """Merge filter options with defaults."""
        normalized = dict(FILTER_DEFAULTS)
        if isinstance(filters, dict):
            for key in normalized:
                normalized[key] = bool(filters.get(key, normalized[key]))
        return normalized

    def _network_matches_filters(self, network, filters: Dict[str, bool]) -> bool:
        """Return True when a network should be removed by active filters."""
        if filters['public_only']:
            return (
                not network.is_global or network.is_private or network.is_loopback or
                network.is_link_local or network.is_multicast or network.is_reserved or
                network.is_unspecified
            )
        if filters['exclude_private'] and network.is_private:
            return True
        if filters['exclude_loopback'] and network.is_loopback:
            return True
        if filters['exclude_link_local'] and network.is_link_local:
            return True
        if filters['exclude_multicast'] and network.is_multicast:
            return True
        if filters['exclude_reserved'] and network.is_reserved:
            return True
        if filters['exclude_unspecified'] and network.is_unspecified:
            return True
        return False

    def filter_cidr_list(self, cidr_list: List[str], filters: Optional[Dict[str, bool]] = None) -> List[str]:
        """Filter CIDR entries by address class without changing network coverage."""
        normalized_filters = self._normalize_filter_options(filters)
        filtered = []
        for network in self._parse_networks(cidr_list):
            if not self._network_matches_filters(network, normalized_filters):
                filtered.append(str(network))
        return self.sort_ip_addresses(filtered)

    def cidr_total_addresses(self, cidr_list: List[str]) -> int:
        """Count addresses covered by a CIDR list after exact collapse."""
        networks = self._parse_networks(cidr_list)
        if not networks:
            return 0
        ipv4 = [network for network in networks if network.version == 4]
        ipv6 = [network for network in networks if network.version == 6]
        collapsed = list(ipaddress.collapse_addresses(ipv4)) + list(ipaddress.collapse_addresses(ipv6))
        return sum(network.num_addresses for network in collapsed)

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
                        ipv4_entries.append((str(network), int(network.network_address), -network.prefixlen))
                    except ValueError:
                        network = ipaddress.IPv6Network(ip, strict=False)
                        ipv6_entries.append((str(network), int(network.network_address), -network.prefixlen))
                else:
                    try:
                        address = ipaddress.IPv4Address(ip)
                        ipv4_entries.append((f"{ip}/32", int(address), -32))
                    except ValueError:
                        address = ipaddress.IPv6Address(ip)
                        ipv6_entries.append((f"{ip}/128", int(address), -128))
            except ValueError:
                continue
        ipv4_entries.sort(key=lambda x: (x[1], x[2]))
        ipv6_entries.sort(key=lambda x: (x[1], x[2]))
        return [ip for ip, _, _ in ipv4_entries] + [ip for ip, _, _ in ipv6_entries]

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

    def optimize_cidr_list(self, cidr_list: List[str], aggressive: bool = False,
                           allow_expansion: bool = False, max_extra_addresses: int = 0) -> List[str]:
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
                if aggressive and allow_expansion and max_extra_addresses > 0:
                    optimized_ipv4 = self._lossy_expand_networks(optimized_ipv4, max_extra_addresses)
            
            # Process IPv6 networks
            optimized_ipv6 = []
            if ipv6_networks:
                # Sort networks by address and prefix length
                ipv6_networks.sort(key=lambda n: (n.network_address, -n.prefixlen))
                
                optimized_ipv6 = list(ipaddress.collapse_addresses(ipv6_networks))
                if aggressive and allow_expansion and max_extra_addresses > 0:
                    optimized_ipv6 = self._lossy_expand_networks(optimized_ipv6, max_extra_addresses)
            
            # Combine and return results
            return [str(net) for net in optimized_ipv4 + optimized_ipv6]
                    
        except Exception as e:
            print(f"Error optimizing CIDR list: {e}")
            return cidr_list
    
    def _optimize_network_list(self, networks, aggressive: bool = False):
        """Helper method for optimize_cidr_list to handle the actual optimization logic."""
        return list(ipaddress.collapse_addresses(networks)) if networks else []

    def _smallest_common_supernet(self, first, second):
        """Return the smallest supernet covering two same-version networks."""
        if first.version != second.version:
            return None
        max_prefix = first.max_prefixlen
        first_address = int(first.network_address)
        last_address = int(max(first.broadcast_address, second.broadcast_address))
        min_address = int(min(first.network_address, second.network_address))
        differing_bits = min_address ^ last_address
        prefixlen = max_prefix - differing_bits.bit_length()
        network_int = min_address & (((1 << max_prefix) - 1) ^ ((1 << (max_prefix - prefixlen)) - 1))
        return ipaddress.ip_network((network_int, prefixlen))

    def _lossy_expand_networks(self, networks, max_extra_addresses: int):
        """Merge nearby networks when the added address count stays within a limit."""
        current = list(ipaddress.collapse_addresses(networks))
        changed = True
        while changed:
            changed = False
            current.sort(key=lambda n: (int(n.network_address), n.prefixlen))
            for i, first in enumerate(current):
                best = None
                for second in current[i + 1:]:
                    if first.version != second.version:
                        continue
                    common = self._smallest_common_supernet(first, second)
                    if common is None:
                        continue
                    group = [network for network in current if network.subnet_of(common)]
                    if len(group) < 2:
                        continue
                    covered = self.cidr_total_addresses([str(network) for network in group])
                    extra = common.num_addresses - covered
                    if 0 <= extra <= max_extra_addresses:
                        best = (common, group)
                        break
                if best:
                    common, group = best
                    current = [network for network in current if network not in group]
                    current.append(common)
                    current = list(ipaddress.collapse_addresses(current))
                    changed = True
                    break
        return current

    def apply_mask(self, ips: List[str], mask_name: str) -> str:
        """Apply a mask to format a list of IP addresses."""
        mask = self.get_mask_by_name(mask_name)
        return self.apply_mask_definition(ips, mask, mask_name)

    def apply_mask_definition(self, ips: List[str], mask: Dict, mask_name: str = '') -> str:
        """Apply a mask dictionary to format a list of IP addresses."""
        formatted_ips = []
        template_variables = self._normalize_mask_variables(mask.get('variables'))
        for ip in ips:
            fields = SafeFormatDict(template_variables)
            fields.update(self._mask_template_fields(ip))
            ip_version = mask.get('ip_version')
            if ip_version in (4, 6) and fields.get('version') != ip_version:
                continue
            formatted_ips.append(self._format_mask_entry(mask, fields))

        separator = mask.get('separator', '\n')
        result_parts = []
        common_fields = SafeFormatDict(template_variables)
        common_fields.update({
            'count': len(formatted_ips),
            'separator': separator,
            'mask_name': mask.get('name', mask_name),
        })
        if not formatted_ips:
            return ''

        header = mask.get('header', '')
        if header:
            result_parts.append(self._render_template(header, common_fields))
        if formatted_ips:
            result_parts.append(separator.join(formatted_ips))
        footer = mask.get('footer', '')
        if footer:
            result_parts.append(self._render_template(footer, common_fields))
        return separator.join(result_parts)

    def _format_mask_entry(self, mask: Dict, fields: SafeFormatDict) -> str:
        """Format one network using either a template mask or prefix/suffix mask."""
        line_template = mask.get('line_template')
        if line_template:
            return self._render_template(line_template, fields)
        return f"{mask.get('prefix', '')}{fields['original']}{mask.get('suffix', '')}"

    def _render_template(self, template: str, fields: SafeFormatDict) -> str:
        """Render a mask template while preserving unknown placeholders."""
        try:
            return template.format_map(fields)
        except (ValueError, KeyError, IndexError):
            return template

    def _mask_template_fields(self, ip: str) -> SafeFormatDict:
        """Build placeholder values for template-based masks."""
        fields = SafeFormatDict({
            'original': ip,
            'cidr': ip,
            'network': ip,
            'ip': ip,
            'address': ip,
            'netmask': '',
            'hostmask': '',
            'wildcard': '',
            'prefixlen': '',
            'version': None,
            'broadcast': '',
            'num_addresses': '',
        })
        try:
            network = ipaddress.ip_network(ip, strict=False)
        except ValueError:
            return fields

        fields.update({
            'cidr': str(network),
            'network': str(network.network_address),
            'ip': str(network.network_address),
            'address': str(network.network_address),
            'netmask': str(network.netmask),
            'hostmask': str(network.hostmask),
            'wildcard': str(network.hostmask),
            'prefixlen': network.prefixlen,
            'version': network.version,
            'num_addresses': network.num_addresses,
        })
        if network.version == 4:
            fields['broadcast'] = str(network.broadcast_address)
        return fields

    def process_input_to_ips(self, input_text: str, include_ipv4: bool = True, include_ipv6: bool = True,
                             extraction_mode: str = 'smart',
                             filters: Optional[Dict[str, bool]] = None) -> List[str]:
        """Process input text to extract IPs, CIDR notations, and ranges."""
        cidrs = self.extract_ips(input_text, include_ipv4, include_ipv6, extraction_mode)
        has_named_prefixes = bool(self._extract_named_prefix_tokens(input_text, include_ipv4, include_ipv6))
        ranges = [] if has_named_prefixes else self.extract_ip_ranges(input_text, include_ipv4, include_ipv6)
        
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
        
        result = list(set(all_ips))
        if filters:
            return self.filter_cidr_list(result, filters)
        return result

    def build_processing_report(self, input_text: str, include_ipv4: bool = True, include_ipv6: bool = True,
                                extraction_mode: str = 'smart', filters: Optional[Dict[str, bool]] = None,
                                optimize: bool = False, aggressive: bool = False,
                                allow_expansion: bool = False, max_extra_addresses: int = 0) -> Dict:
        """Extract, filter, optionally optimize, and return output plus stats."""
        extraction_mode = extraction_mode if extraction_mode in EXTRACTION_MODES else 'smart'
        cidrs = self.extract_ips(input_text, include_ipv4, include_ipv6, extraction_mode)
        has_named_prefixes = bool(self._extract_named_prefix_tokens(input_text, include_ipv4, include_ipv6))
        ranges = [] if has_named_prefixes else self.extract_ip_ranges(input_text, include_ipv4, include_ipv6)
        extracted = []

        for cidr in cidrs:
            network = self._token_to_network(cidr, include_ipv4, include_ipv6)
            if network is not None:
                extracted.append(str(network))

        for ip_range in ranges:
            try:
                start_ip, end_ip = ip_range.split('-')
                extracted.extend(self.range_to_cidrs(start_ip, end_ip))
            except ValueError:
                continue

        unique_cidrs = self.sort_ip_addresses(list(set(extracted)))
        filtered_cidrs = self.filter_cidr_list(unique_cidrs, filters)
        if optimize:
            final_cidrs = self.optimize_cidr_list(
                filtered_cidrs,
                aggressive=aggressive,
                allow_expansion=allow_expansion,
                max_extra_addresses=max_extra_addresses,
            )
            final_cidrs = self.sort_ip_addresses(final_cidrs)
        else:
            final_cidrs = filtered_cidrs

        safe_total = self.cidr_total_addresses(self.optimize_cidr_list(filtered_cidrs))
        final_total = self.cidr_total_addresses(final_cidrs)
        suspicious = self.get_suspicious_tokens(input_text, include_ipv4, include_ipv6)
        return {
            'raw_entries': extracted,
            'unique_cidrs': unique_cidrs,
            'filtered_cidrs': filtered_cidrs,
            'final_cidrs': final_cidrs,
            'suspicious': suspicious,
            'stats': {
                'lines': len(input_text.splitlines()) if input_text else 0,
                'found_entries': len(extracted),
                'ranges_found': len(ranges),
                'unique_networks': len(unique_cidrs),
                'filtered_out': len(unique_cidrs) - len(filtered_cidrs),
                'after_filter': len(filtered_cidrs),
                'final_networks': len(final_cidrs),
                'addresses_covered': final_total,
                'extra_addresses': max(0, final_total - safe_total),
                'suspicious_count': len(suspicious),
            }
        }

    def format_processing_report(self, report: Dict) -> str:
        """Format processing stats and suspicious tokens for preview/report dialogs."""
        stats = report.get('stats', {})
        lines = [
            f"Lines: {stats.get('lines', 0)}",
            f"Found entries: {stats.get('found_entries', 0)}",
            f"Unique networks: {stats.get('unique_networks', 0)}",
            f"Filtered out: {stats.get('filtered_out', 0)}",
            f"Final networks: {stats.get('final_networks', 0)}",
            f"Addresses covered: {stats.get('addresses_covered', 0)}",
        ]
        extra = stats.get('extra_addresses', 0)
        if extra:
            lines.append(f"Extra addresses from aggressive merge: {extra}")
        suspicious = report.get('suspicious', [])
        if suspicious:
            lines.append("")
            lines.append("Suspicious skipped values:")
            for item in suspicious[:100]:
                lines.append(f"- {item['value']}: {item['reason']}")
            if len(suspicious) > 100:
                lines.append(f"...and {len(suspicious) - 100} more")
        return '\n'.join(lines)

    def subtract_cidr_lists(self, denylist: List[str], allowlist: List[str]) -> List[str]:
        """Subtract allowlist networks from a denylist while preserving exact coverage."""
        deny_networks = self._parse_networks(denylist)
        allow_networks = self._parse_networks(allowlist)
        remaining = []

        for base in deny_networks:
            pieces = [base]
            for allowed in allow_networks:
                if allowed.version != base.version:
                    continue
                next_pieces = []
                for piece in pieces:
                    if not piece.overlaps(allowed):
                        next_pieces.append(piece)
                    elif piece.subnet_of(allowed):
                        continue
                    elif allowed.subnet_of(piece):
                        next_pieces.extend(piece.address_exclude(allowed))
                    else:
                        next_pieces.append(piece)
                pieces = next_pieces
                if not pieces:
                    break
            remaining.extend(pieces)

        ipv4 = [network for network in remaining if network.version == 4]
        ipv6 = [network for network in remaining if network.version == 6]
        collapsed = list(ipaddress.collapse_addresses(ipv4)) + list(ipaddress.collapse_addresses(ipv6))
        return self.sort_ip_addresses([str(network) for network in collapsed])

    def run_self_test(self) -> Tuple[bool, List[str]]:
        """Run a compact built-in validation suite used by the GUI self-test."""
        checks = []

        def check(name: str, actual, expected) -> None:
            checks.append((name, actual == expected, actual, expected))

        check('IPv4 URL with port', self.extract_ips('http://192.168.1.1:8080'), ['192.168.1.1'])
        check('IPv6 compressed', self.extract_ips('2001:db8::1 ::1'), ['2001:db8::1', '::1'])
        check('Invalid prefix rejection', self.extract_ips('192.168.1.1/99 2001:db8::/129'), [])
        check('Range to CIDR', sorted(self.process_input_to_ips('192.168.1.1-192.168.1.3')),
              ['192.168.1.1/32', '192.168.1.2/31'])
        check('Safe optimization', self.optimize_cidr_list(['10.0.0.0/25', '10.0.0.128/25']), ['10.0.0.0/24'])
        check('Deny/allow subtract', self.subtract_cidr_lists(['10.0.0.0/24'], ['10.0.0.0/25']), ['10.0.0.128/25'])
        json_prefix_text = (
            '{"probe": "10.8.3.1", "prefixes": ['
            '{"ipv4Prefix": "91.205.157.0/24"},'
            '{"ipv4Prefix": "91.205.216.0/22"},'
            '{"ipv4Prefix": "193.107.112.0/22"},'
            '{"ipv4Prefix": "195.18.16.0/22"}'
            '], "nextHop": "193.233.231.208"}'
        )
        check('JSON ipv4Prefix priority',
              self.extract_ips(json_prefix_text, include_ipv4=True, include_ipv6=False),
              ['91.205.157.0/24', '91.205.216.0/22', '193.107.112.0/22', '195.18.16.0/22'])
        json_prefix_report = self.build_processing_report(
            json_prefix_text,
            include_ipv4=True,
            include_ipv6=False,
            optimize=False,
        )
        check('Keenetic mask from JSON prefixes',
              self.apply_mask(json_prefix_report['final_cidrs'], 'keenetic-webadmin-udp-41495'),
              'access-list _WEBADMIN_GigabitEthernet1\n'
              '    permit udp 91.205.157.0 255.255.255.0 0.0.0.0 0.0.0.0 port eq 41495\n'
              '    permit description winmobile\n'
              '    permit udp 91.205.216.0 255.255.252.0 0.0.0.0 0.0.0.0 port eq 41495\n'
              '    permit description winmobile\n'
              '    permit udp 193.107.112.0 255.255.252.0 0.0.0.0 0.0.0.0 port eq 41495\n'
              '    permit description winmobile\n'
              '    permit udp 195.18.16.0 255.255.252.0 0.0.0.0 0.0.0.0 port eq 41495\n'
              '    permit description winmobile\n'
              '    deny udp 0.0.0.0 0.0.0.0 0.0.0.0 0.0.0.0 port eq 443')

        lines = []
        ok = True
        for name, passed, actual, expected in checks:
            if passed:
                lines.append(f"OK: {name}")
            else:
                ok = False
                lines.append(f"FAIL: {name}\n  actual: {actual}\n  expected: {expected}")
        return ok, lines

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
                            extraction_mode: str = 'smart', filters: Optional[Dict[str, bool]] = None,
                            allow_expansion: bool = False, max_extra_addresses: int = 0,
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
            extraction_mode: smart or strict token extraction
            filters: Address class filters
            allow_expansion: Whether aggressive optimization may add extra addresses
            max_extra_addresses: Maximum extra addresses allowed when expansion is enabled
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
                                optimize, aggressive, include_ipv4, include_ipv6,
                                extraction_mode, filters, allow_expansion, max_extra_addresses): file
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
                           optimize: bool, aggressive: bool, include_ipv4: bool, include_ipv6: bool,
                           extraction_mode: str = 'smart', filters: Optional[Dict[str, bool]] = None,
                           allow_expansion: bool = False, max_extra_addresses: int = 0) -> Dict[str, int]:
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
            
            report = self.build_processing_report(
                content,
                include_ipv4=include_ipv4,
                include_ipv6=include_ipv6,
                extraction_mode=extraction_mode,
                filters=filters,
                optimize=optimize,
                aggressive=aggressive,
                allow_expansion=allow_expansion,
                max_extra_addresses=max_extra_addresses,
            )
            sorted_cidrs = report['final_cidrs']
            stats['total_ips_found'] = report['stats']['found_entries']
            stats['unique_ips'] = report['stats']['after_filter']
            stats['optimized_networks'] = len(sorted_cidrs)
            
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
        if not TKINTER_AVAILABLE:
            raise RuntimeError("tkinter is not installed. Install python3-tk to use the GUI.")
        self.processor = processor

        # Use TkinterDnD if available for drag and drop support
        if TKDND_AVAILABLE:
            self.root = TkinterDnD.Tk()
        else:
            self.root = tk.Tk()

        self.root.title("IP CIDR Processor" + (" (Drag & Drop Enabled)" if TKDND_AVAILABLE else ""))
        self.root.geometry("1040x780")
    
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
        self.tab_compare = ttk.Frame(self.notebook)
        self.tab_masks = ttk.Frame(self.notebook)
        self.tab_config = ttk.Frame(self.notebook)  # New config tab
        
        # Add tabs to notebook
        self.notebook.add(self.tab_process, text="Process Files")
        self.notebook.add(self.tab_ranges, text="IP Ranges")
        self.notebook.add(self.tab_optimize, text="Optimize CIDR")
        self.notebook.add(self.tab_url, text="URL Processing")
        self.notebook.add(self.tab_batch, text="Batch Processing")  # New batch tab
        self.notebook.add(self.tab_compare, text="Compare Lists")
        self.notebook.add(self.tab_masks, text="Mask Settings")
        self.notebook.add(self.tab_config, text="Configuration")  # New config tab
        
        # Set up tabs
        self.setup_process_tab()
        self.setup_ranges_tab()
        self.setup_optimize_tab()
        self.setup_url_tab()
        self.setup_batch_tab()  # Setup batch tab
        self.setup_compare_tab()
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
            'batch': self.tab_batch,
            'compare': self.tab_compare
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

    def current_tab_label(self) -> str:
        """Return the visible label of the selected notebook tab."""
        return self.notebook.tab(self.notebook.select(), "text")

    def add_files_shortcut(self):
        """Add files via keyboard shortcut based on current tab."""
        current_tab = self.current_tab_label()
        if current_tab == "Process Files":
            self.add_local_files()
        elif current_tab == "Optimize CIDR":
            self.add_local_files(optimize=True)
        elif current_tab == "URL Processing":
            self.add_url()
        elif current_tab == "Batch Processing":
            self.add_local_files(batch=True)
        elif current_tab == "Compare Lists":
            self.add_compare_files('deny')

    def save_shortcut(self):
        """Save results via keyboard shortcut based on current tab."""
        current_tab = self.current_tab_label()
        if current_tab == "IP Ranges":
            self.save_results()

    def delete_selected_items(self):
        """Delete selected items from the current listbox."""
        current_tab = self.current_tab_label()
        listbox = None

        if current_tab == "Process Files":
            listbox = self.listbox_files
        elif current_tab == "Optimize CIDR":
            listbox = self.listbox_files_optimize
        elif current_tab == "URL Processing":
            listbox = self.listbox_urls
        elif current_tab == "Batch Processing":
            listbox = self.listbox_batch_files
        elif current_tab == "Compare Lists":
            listbox = self.listbox_compare_deny

        if listbox:
            selection = listbox.curselection()
            if selection:
                for index in reversed(selection):
                    listbox.delete(index)

    def select_all_items(self):
        """Select all items in the current listbox."""
        current_tab = self.current_tab_label()
        listbox = None

        if current_tab == "Process Files":
            listbox = self.listbox_files
        elif current_tab == "Optimize CIDR":
            listbox = self.listbox_files_optimize
        elif current_tab == "URL Processing":
            listbox = self.listbox_urls
        elif current_tab == "Batch Processing":
            listbox = self.listbox_batch_files
        elif current_tab == "Compare Lists":
            listbox = self.listbox_compare_deny

        if listbox:
            listbox.select_set(0, tk.END)

    def process_shortcut(self):
        """Process files via F5 shortcut based on current tab."""
        current_tab = self.current_tab_label()
        if current_tab == "Process Files":
            self.process_local_files()
        elif current_tab == "Optimize CIDR":
            self.optimize_files()
        elif current_tab == "URL Processing":
            self.process_urls()
        elif current_tab == "Batch Processing":
            self.process_batch_files()
        elif current_tab == "Compare Lists":
            self.compare_lists()

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
        current_tab = self.current_tab_label()
        count = 0

        if current_tab == "Process Files":
            count = self.listbox_files.size()
        elif current_tab == "Optimize CIDR":
            count = self.listbox_files_optimize.size()
        elif current_tab == "URL Processing":
            count = self.listbox_urls.size()
        elif current_tab == "Batch Processing":
            count = self.listbox_batch_files.size()
        elif current_tab == "Compare Lists":
            deny = self.listbox_compare_deny.size()
            allow = self.listbox_compare_allow.size()
            self.file_count_var.set(f"Deny: {deny} Allow: {allow}")
            count = None

        if current_tab in ["Process Files", "Optimize CIDR", "Batch Processing"]:
            self.file_count_var.set(f"Files: {count}")
        elif current_tab == "URL Processing":
            self.file_count_var.set(f"URLs: {count}")
        elif count is not None:
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

    def add_processing_options(self, parent, prefix: str, include_optimize: bool = True):
        """Add shared extraction, filtering, and optimization controls."""
        options_frame = ttk.LabelFrame(parent, text="Processing Options")
        options_frame.pack(fill='x', padx=10, pady=5)

        row_one = ttk.Frame(options_frame)
        row_one.pack(fill='x', padx=5, pady=3)
        ttk.Label(row_one, text="Extraction:").pack(side='left', padx=5)
        mode_var = tk.StringVar(value='smart')
        setattr(self, f"{prefix}_mode_var", mode_var)
        mode_combo = ttk.Combobox(row_one, textvariable=mode_var, values=EXTRACTION_MODES, state='readonly', width=10)
        mode_combo.pack(side='left', padx=5)

        if include_optimize:
            optimize_var = tk.BooleanVar(value=False)
            setattr(self, f"{prefix}_optimize_results_var", optimize_var)
            ttk.Checkbutton(row_one, text="Optimize", variable=optimize_var).pack(side='left', padx=8)

        allow_expansion_var = tk.BooleanVar(value=False)
        setattr(self, f"{prefix}_allow_expansion_var", allow_expansion_var)
        ttk.Checkbutton(row_one, text="Allow coverage expansion", variable=allow_expansion_var).pack(side='left', padx=8)

        ttk.Label(row_one, text="Max extra:").pack(side='left', padx=5)
        max_extra_var = tk.StringVar(value="0")
        setattr(self, f"{prefix}_max_extra_var", max_extra_var)
        ttk.Entry(row_one, textvariable=max_extra_var, width=8).pack(side='left', padx=3)

        row_two = ttk.Frame(options_frame)
        row_two.pack(fill='x', padx=5, pady=3)
        filter_defs = [
            ('public_only', 'Public only'),
            ('exclude_private', 'No private'),
            ('exclude_loopback', 'No loopback'),
            ('exclude_link_local', 'No link-local'),
            ('exclude_multicast', 'No multicast'),
            ('exclude_reserved', 'No reserved'),
            ('exclude_unspecified', 'No unspecified'),
        ]
        for key, label in filter_defs:
            var = tk.BooleanVar(value=False)
            setattr(self, f"{prefix}_{key}_var", var)
            ttk.Checkbutton(row_two, text=label, variable=var).pack(side='left', padx=4)

    def get_filter_options(self, prefix: str) -> Dict[str, bool]:
        """Read address-class filter options from a tab."""
        return {
            key: getattr(self, f"{prefix}_{key}_var").get()
            for key in FILTER_DEFAULTS
            if hasattr(self, f"{prefix}_{key}_var")
        }

    def get_processing_options(self, prefix: str, optimize_default: bool = False) -> Dict:
        """Read shared processing options from a tab."""
        max_extra = 0
        if hasattr(self, f"{prefix}_max_extra_var"):
            try:
                max_extra = max(0, int(getattr(self, f"{prefix}_max_extra_var").get()))
            except ValueError:
                max_extra = 0
        optimize = optimize_default
        if hasattr(self, f"{prefix}_optimize_results_var"):
            optimize = getattr(self, f"{prefix}_optimize_results_var").get()
        mode_var = getattr(self, f"{prefix}_mode_var", None)
        allow_expansion_var = getattr(self, f"{prefix}_allow_expansion_var", None)
        return {
            'extraction_mode': mode_var.get() if mode_var else 'smart',
            'filters': self.get_filter_options(prefix),
            'optimize': optimize,
            'allow_expansion': allow_expansion_var.get() if allow_expansion_var else False,
            'max_extra_addresses': max_extra,
        }

    def read_files_content(self, files: Tuple[str, ...]) -> Tuple[Optional[str], Optional[str]]:
        """Read selected files and return combined content or an error message."""
        content_parts = []
        for file in files:
            try:
                with open(file, 'r', encoding='utf-8', errors='ignore') as handle:
                    content_parts.append(handle.read())
            except Exception as e:
                return None, f"Error processing file {file}: {e}"
        return '\n'.join(content_parts), None

    def show_processing_preview(self, title: str, formatted_content: str, report: Dict,
                                default_extension: str = ".txt"):
        """Show a preview dialog with stats, result, report, copy, and save actions."""
        preview_dialog = tk.Toplevel(self.root)
        preview_dialog.title(title)
        preview_dialog.geometry("820x620")

        stats_text = self.processor.format_processing_report(report)
        stats_frame = ttk.LabelFrame(preview_dialog, text="Stats")
        stats_frame.pack(fill='x', padx=10, pady=5)
        stats_label = ttk.Label(stats_frame, text=stats_text.split('\n\n')[0], justify='left')
        stats_label.pack(anchor='w', padx=8, pady=5)

        result_frame = ttk.LabelFrame(preview_dialog, text="Preview")
        result_frame.pack(fill='both', expand=True, padx=10, pady=5)
        text_widget = tk.Text(result_frame, wrap='none', height=18)
        text_widget.pack(side='left', fill='both', expand=True)
        scrollbar_y = ttk.Scrollbar(result_frame, orient='vertical', command=text_widget.yview)
        scrollbar_y.pack(side='right', fill='y')
        text_widget.configure(yscrollcommand=scrollbar_y.set)
        text_widget.insert('1.0', formatted_content)
        text_widget.config(state='disabled')

        btn_frame = ttk.Frame(preview_dialog)
        btn_frame.pack(fill='x', padx=10, pady=10)

        def copy_result():
            self.root.clipboard_clear()
            self.root.clipboard_append(formatted_content)
            messagebox.showinfo("Copied", "Preview copied to clipboard", parent=preview_dialog)

        def save_result():
            output_path = filedialog.asksaveasfilename(
                defaultextension=default_extension,
                filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
                parent=preview_dialog
            )
            if output_path:
                try:
                    with open(output_path, 'w', encoding='utf-8') as handle:
                        handle.write(formatted_content)
                    messagebox.showinfo("Success", f"Results saved to: {output_path}", parent=preview_dialog)
                except Exception as e:
                    messagebox.showerror("Error", f"Error saving results: {e}", parent=preview_dialog)

        def show_report():
            report_dialog = tk.Toplevel(preview_dialog)
            report_dialog.title("Processing Report")
            report_dialog.geometry("700x500")
            report_text = tk.Text(report_dialog, wrap='word')
            report_text.pack(fill='both', expand=True, padx=10, pady=10)
            report_text.insert('1.0', stats_text)
            report_text.config(state='disabled')
            ttk.Button(report_dialog, text="Close", command=report_dialog.destroy).pack(pady=8)
            report_dialog.transient(preview_dialog)

        ttk.Button(btn_frame, text="Copy", command=copy_result).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Save", command=save_result).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Report", command=show_report).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Close", command=preview_dialog.destroy).pack(side='right', padx=5)

        preview_dialog.transient(self.root)

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

        self.add_processing_options(self.tab_process, 'process', include_optimize=True)
        
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

        self.add_processing_options(self.tab_optimize, 'optimize', include_optimize=False)
        
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

        self.add_processing_options(self.tab_url, 'url', include_optimize=False)
        
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

        # Row 6: Header
        ttk.Label(new_mask_frame, text="Header:").grid(row=6, column=0, padx=5, pady=5, sticky='w')
        self.new_mask_header = tk.StringVar()
        ttk.Entry(new_mask_frame, textvariable=self.new_mask_header, width=70).grid(row=6, column=1, padx=5, pady=5, sticky='ew')

        # Row 7: Line Template
        ttk.Label(new_mask_frame, text="Line Template:").grid(row=7, column=0, padx=5, pady=5, sticky='w')
        self.new_mask_line_template = tk.StringVar()
        ttk.Entry(new_mask_frame, textvariable=self.new_mask_line_template, width=70).grid(row=7, column=1, padx=5, pady=5, sticky='ew')

        # Row 8: Footer
        ttk.Label(new_mask_frame, text="Footer:").grid(row=8, column=0, padx=5, pady=5, sticky='w')
        self.new_mask_footer = tk.StringVar()
        ttk.Entry(new_mask_frame, textvariable=self.new_mask_footer, width=70).grid(row=8, column=1, padx=5, pady=5, sticky='ew')

        # Row 9: IP Version
        ttk.Label(new_mask_frame, text="IP Version:").grid(row=9, column=0, padx=5, pady=5, sticky='w')
        self.new_mask_ip_version = tk.StringVar()
        ip_version_combo = ttk.Combobox(new_mask_frame, textvariable=self.new_mask_ip_version, values=['', '4', '6'], width=10, state='readonly')
        ip_version_combo.grid(row=9, column=1, padx=5, pady=5, sticky='w')

        # Row 10: Template Variables
        ttk.Label(new_mask_frame, text="Template Variables:").grid(row=10, column=0, padx=5, pady=5, sticky='w')
        self.new_mask_variables = tk.StringVar()
        ttk.Entry(new_mask_frame, textvariable=self.new_mask_variables, width=70).grid(row=10, column=1, padx=5, pady=5, sticky='ew')

        # Row 11: Preview
        preview_frame = ttk.Frame(new_mask_frame)
        preview_frame.grid(row=11, column=0, columnspan=2, padx=5, pady=5, sticky='ew')

        ttk.Button(preview_frame, text="Preview", command=self.preview_mask).pack(side='left', padx=2)
        ttk.Button(preview_frame, text="Add Mask", command=self.add_new_mask).pack(side='left', padx=2)

        # Row 12: Help text
        help_text = "Note: Use \\n for newline, \\t for tab. Variables: key=value, e.g. protocol=udp, permit_port=41495, deny_port=443, rule_description=client."
        ttk.Label(new_mask_frame, text=help_text, font=('Arial', 8), foreground='gray').grid(row=12, column=0, columnspan=2, padx=5, pady=2, sticky='w')
        new_mask_frame.columnconfigure(1, weight=1)

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
        self.compare_mask_combo['values'] = mask_names
        
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
        if self.compare_mask_var.get() not in mask_names:
            self.compare_mask_combo.current(0)
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

        self.add_processing_options(self.tab_batch, 'batch', include_optimize=False)
        
        # Process and Stop buttons
        process_frame = ttk.Frame(self.tab_batch)
        process_frame.pack(pady=10)
        ttk.Button(process_frame, text="Preview Combined", command=self.preview_batch_combined).pack(side='left', padx=5)
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

    def setup_compare_tab(self):
        """Set up denylist/allowlist comparison tab."""
        lists_frame = ttk.Frame(self.tab_compare)
        lists_frame.pack(fill='both', expand=True, padx=10, pady=5)

        deny_frame = ttk.LabelFrame(lists_frame, text="Denylist Files")
        deny_frame.pack(side='left', fill='both', expand=True, padx=(0, 5))
        self.listbox_compare_deny = tk.Listbox(deny_frame)
        self.listbox_compare_deny.pack(side='left', fill='both', expand=True)
        deny_scrollbar = ttk.Scrollbar(deny_frame, orient="vertical", command=self.listbox_compare_deny.yview)
        deny_scrollbar.pack(side='right', fill='y')
        self.listbox_compare_deny.config(yscrollcommand=deny_scrollbar.set)
        self.enable_drag_and_drop(self.listbox_compare_deny, "files")
        self.add_context_menu(self.listbox_compare_deny, "files")

        allow_frame = ttk.LabelFrame(lists_frame, text="Allowlist Files")
        allow_frame.pack(side='left', fill='both', expand=True, padx=(5, 0))
        self.listbox_compare_allow = tk.Listbox(allow_frame)
        self.listbox_compare_allow.pack(side='left', fill='both', expand=True)
        allow_scrollbar = ttk.Scrollbar(allow_frame, orient="vertical", command=self.listbox_compare_allow.yview)
        allow_scrollbar.pack(side='right', fill='y')
        self.listbox_compare_allow.config(yscrollcommand=allow_scrollbar.set)
        self.enable_drag_and_drop(self.listbox_compare_allow, "files")
        self.add_context_menu(self.listbox_compare_allow, "files")

        btn_frame = ttk.Frame(self.tab_compare)
        btn_frame.pack(fill='x', padx=10, pady=5)
        ttk.Button(btn_frame, text="Add Deny Files", command=lambda: self.add_compare_files('deny')).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Add Allow Files", command=lambda: self.add_compare_files('allow')).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Clear Deny", command=lambda: self.listbox_compare_deny.delete(0, tk.END)).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Clear Allow", command=lambda: self.listbox_compare_allow.delete(0, tk.END)).pack(side='left', padx=5)

        output_frame = ttk.LabelFrame(self.tab_compare, text="Output")
        output_frame.pack(fill='x', padx=10, pady=5)
        ttk.Label(output_frame, text="Apply Mask:").pack(side='left', padx=5)
        self.compare_mask_var = tk.StringVar(value=self.processor.config['default_mask'])
        self.compare_mask_combo = ttk.Combobox(output_frame, textvariable=self.compare_mask_var)
        self.compare_mask_combo['values'] = self.processor.get_mask_names()
        self.compare_mask_combo.pack(side='left', padx=5)

        self.compare_optimize_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(output_frame, text="Optimize result", variable=self.compare_optimize_var).pack(side='left', padx=8)
        self.add_processing_options(self.tab_compare, 'compare', include_optimize=False)
        ttk.Button(self.tab_compare, text="Subtract Allowlist and Preview", command=self.compare_lists).pack(pady=10)
    
    def browse_batch_output_folder(self):
        """Browse for output folder for batch processing."""
        folder = filedialog.askdirectory(title="Select Output Folder")
        if folder:
            self.batch_output_folder_var.set(folder)

    def preview_batch_combined(self):
        """Preview all batch files as one combined output before writing per-file results."""
        files = self.listbox_batch_files.get(0, tk.END)
        if not files:
            messagebox.showwarning("Warning", "No files selected for batch processing.")
            return

        include_ipv4 = self.batch_ipv4_var.get()
        include_ipv6 = self.batch_ipv6_var.get()
        if not include_ipv4 and not include_ipv6:
            messagebox.showwarning("Warning", "At least one IP version (IPv4 or IPv6) must be selected.")
            return

        content, error = self.read_files_content(files)
        if error:
            messagebox.showerror("Error", error)
            return

        options = self.get_processing_options('batch', optimize_default=self.batch_optimize_var.get())
        report = self.processor.build_processing_report(
            content or '',
            include_ipv4=include_ipv4,
            include_ipv6=include_ipv6,
            extraction_mode=options['extraction_mode'],
            filters=options['filters'],
            optimize=self.batch_optimize_var.get(),
            aggressive=self.batch_aggressive_var.get(),
            allow_expansion=options['allow_expansion'],
            max_extra_addresses=options['max_extra_addresses'],
        )
        formatted_content = self.processor.apply_mask(report['final_cidrs'], self.batch_mask_var.get())
        self.show_processing_preview("Batch Combined Preview", formatted_content, report)
    
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
        options = self.get_processing_options('batch', optimize_default=optimize)
        
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
                    extraction_mode=options['extraction_mode'],
                    filters=options['filters'],
                    allow_expansion=options['allow_expansion'],
                    max_extra_addresses=options['max_extra_addresses'],
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
            if not PSUTIL_AVAILABLE:
                self.stop_button['state'] = 'disabled'
                return
            
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

        selftest_frame = ttk.Frame(config_frame)
        selftest_frame.pack(fill='x', padx=5, pady=10)
        ttk.Label(selftest_frame, text="Self Test:").pack(side='left', padx=5)
        ttk.Button(selftest_frame, text="Run Self-Test", command=self.run_self_test_gui).pack(side='left', padx=10)
        
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

    def run_self_test_gui(self):
        """Run built-in processor checks and show the result."""
        ok, lines = self.processor.run_self_test()
        title = "Self-Test Passed" if ok else "Self-Test Failed"
        message = "\n".join(lines)
        if ok:
            messagebox.showinfo(title, message)
        else:
            messagebox.showerror(title, message)

    # File Processing Tab Methods
    def add_compare_files(self, list_type: str):
        """Add files to denylist or allowlist compare listbox."""
        files = filedialog.askopenfilenames(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        listbox = self.listbox_compare_allow if list_type == 'allow' else self.listbox_compare_deny
        for file in files:
            if file not in listbox.get(0, tk.END):
                listbox.insert(tk.END, file)

    def compare_lists(self):
        """Subtract allowlist files from denylist files and show a preview."""
        include_ipv4 = self.compare_ipv4_var.get()
        include_ipv6 = self.compare_ipv6_var.get()
        if not include_ipv4 and not include_ipv6:
            messagebox.showwarning("Warning", "At least one IP version (IPv4 or IPv6) must be selected.")
            return

        deny_files = self.listbox_compare_deny.get(0, tk.END)
        allow_files = self.listbox_compare_allow.get(0, tk.END)
        if not deny_files:
            messagebox.showwarning("Warning", "No denylist files selected.")
            return

        deny_content, error = self.read_files_content(deny_files)
        if error:
            messagebox.showerror("Error", error)
            return
        allow_content, error = self.read_files_content(allow_files)
        if error:
            messagebox.showerror("Error", error)
            return

        options = self.get_processing_options('compare')
        deny_report = self.processor.build_processing_report(
            deny_content or '',
            include_ipv4=include_ipv4,
            include_ipv6=include_ipv6,
            extraction_mode=options['extraction_mode'],
            filters=options['filters'],
            optimize=False,
        )
        allow_report = self.processor.build_processing_report(
            allow_content or '',
            include_ipv4=include_ipv4,
            include_ipv6=include_ipv6,
            extraction_mode=options['extraction_mode'],
            filters=None,
            optimize=False,
        )

        result = self.processor.subtract_cidr_lists(deny_report['filtered_cidrs'], allow_report['filtered_cidrs'])
        if self.compare_optimize_var.get():
            result = self.processor.optimize_cidr_list(
                result,
                aggressive=True,
                allow_expansion=options['allow_expansion'],
                max_extra_addresses=options['max_extra_addresses'],
            )
            result = self.processor.sort_ip_addresses(result)

        report = {
            'final_cidrs': result,
            'suspicious': deny_report['suspicious'] + allow_report['suspicious'],
            'stats': {
                'lines': deny_report['stats']['lines'] + allow_report['stats']['lines'],
                'found_entries': deny_report['stats']['found_entries'] + allow_report['stats']['found_entries'],
                'ranges_found': deny_report['stats']['ranges_found'] + allow_report['stats']['ranges_found'],
                'unique_networks': deny_report['stats']['unique_networks'],
                'filtered_out': deny_report['stats']['filtered_out'],
                'after_filter': deny_report['stats']['after_filter'],
                'final_networks': len(result),
                'addresses_covered': self.processor.cidr_total_addresses(result),
                'extra_addresses': 0,
                'suspicious_count': len(deny_report['suspicious']) + len(allow_report['suspicious']),
            }
        }
        formatted_content = self.processor.apply_mask(result, self.compare_mask_var.get())
        self.show_processing_preview("Compare Lists Preview", formatted_content, report)

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
        
        content, error = self.read_files_content(files)
        if error:
            messagebox.showerror("Error", error)
            return

        options = self.get_processing_options('process')
        report = self.processor.build_processing_report(
            content or '',
            include_ipv4=include_ipv4,
            include_ipv6=include_ipv6,
            extraction_mode=options['extraction_mode'],
            filters=options['filters'],
            optimize=options['optimize'],
            aggressive=True,
            allow_expansion=options['allow_expansion'],
            max_extra_addresses=options['max_extra_addresses'],
        )
        sorted_cidrs = report['final_cidrs']
        mask_name = self.process_mask_var.get()
        formatted_content = self.processor.apply_mask(sorted_cidrs, mask_name)
        self.show_processing_preview("Process Files Preview", formatted_content, report)

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

        content, error = self.read_files_content(files)
        if error:
            messagebox.showerror("Error", error)
            return

        aggressive = self.aggressive_var.get()
        options = self.get_processing_options('optimize', optimize_default=True)
        report = self.processor.build_processing_report(
            content or '',
            include_ipv4=include_ipv4,
            include_ipv6=include_ipv6,
            extraction_mode=options['extraction_mode'],
            filters=options['filters'],
            optimize=True,
            aggressive=aggressive,
            allow_expansion=options['allow_expansion'],
            max_extra_addresses=options['max_extra_addresses'],
        )
        sorted_cidrs = report['final_cidrs']
        mask_name = self.optimize_mask_var.get()
        formatted_content = self.processor.apply_mask(sorted_cidrs, mask_name)
        self.show_processing_preview("Optimize CIDR Preview", formatted_content, report)

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

        mask_name = self.url_mask_var.get()
        should_optimize = self.url_optimize_var.get()
        options = self.get_processing_options('url', optimize_default=should_optimize)
        self.update_status_bar("Processing URLs...")

        def process_urls_thread():
            try:
                errors = []
                content_parts = []
                for url in urls:
                    content = self.processor.download_file(url)
                    if not content:
                        errors.append(f"No content downloaded from {url}")
                        continue
                    content_parts.append(content)

                report = self.processor.build_processing_report(
                    '\n'.join(content_parts),
                    include_ipv4=include_ipv4,
                    include_ipv6=include_ipv6,
                    extraction_mode=options['extraction_mode'],
                    filters=options['filters'],
                    optimize=should_optimize,
                    aggressive=True,
                    allow_expansion=options['allow_expansion'],
                    max_extra_addresses=options['max_extra_addresses'],
                )
                if errors:
                    report['suspicious'].extend({'value': error, 'reason': 'Download warning'} for error in errors)
                    report['stats']['suspicious_count'] = len(report['suspicious'])

                formatted_content = self.processor.apply_mask(report['final_cidrs'], mask_name)

                self.root.after(0, lambda: self.update_status_bar("Ready"))
                self.root.after(0, lambda content=formatted_content, rep=report: self.show_processing_preview(
                    "URL Processing Preview", content, rep
                ))
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
        header = self.new_mask_header.get().replace('\\n', '\n').replace('\\t', '\t')
        line_template = self.new_mask_line_template.get().replace('\\n', '\n').replace('\\t', '\t')
        footer = self.new_mask_footer.get().replace('\\n', '\n').replace('\\t', '\t')
        ip_version = int(self.new_mask_ip_version.get()) if self.new_mask_ip_version.get() in ('4', '6') else None
        variables = self.processor.parse_mask_variables_text(self.new_mask_variables.get())

        if not name:
            messagebox.showwarning("Warning", "Mask name is required.")
            return

        if self.processor.add_mask(
            name, prefix, suffix, separator, category, description,
            line_template=line_template, header=header, footer=footer, ip_version=ip_version,
            variables=variables,
        ):
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
            self.new_mask_header.set("")
            self.new_mask_line_template.set("")
            self.new_mask_footer.set("")
            self.new_mask_ip_version.set("")
            self.new_mask_variables.set("")

    def edit_mask(self, name):
        """Edit an existing mask."""
        mask = self.processor.get_mask_by_name(name)
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Edit Mask: {name}")
        dialog.geometry("800x620")

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
        ttk.Entry(dialog, textvariable=description_var, width=70).grid(row=5, column=1, padx=10, pady=10, sticky='ew')

        ttk.Label(dialog, text="Header:").grid(row=6, column=0, padx=10, pady=10, sticky='w')
        header_var = tk.StringVar(value=mask.get('header', '').replace('\n', '\\n').replace('\t', '\\t'))
        ttk.Entry(dialog, textvariable=header_var, width=70).grid(row=6, column=1, padx=10, pady=10, sticky='ew')

        ttk.Label(dialog, text="Line Template:").grid(row=7, column=0, padx=10, pady=10, sticky='w')
        line_template_var = tk.StringVar(value=mask.get('line_template', '').replace('\n', '\\n').replace('\t', '\\t'))
        ttk.Entry(dialog, textvariable=line_template_var, width=70).grid(row=7, column=1, padx=10, pady=10, sticky='ew')

        ttk.Label(dialog, text="Footer:").grid(row=8, column=0, padx=10, pady=10, sticky='w')
        footer_var = tk.StringVar(value=mask.get('footer', '').replace('\n', '\\n').replace('\t', '\\t'))
        ttk.Entry(dialog, textvariable=footer_var, width=70).grid(row=8, column=1, padx=10, pady=10, sticky='ew')

        ttk.Label(dialog, text="IP Version:").grid(row=9, column=0, padx=10, pady=10, sticky='w')
        ip_version_var = tk.StringVar(value=str(mask.get('ip_version', '')) if mask.get('ip_version') in (4, 6) else '')
        ip_version_combo = ttk.Combobox(dialog, textvariable=ip_version_var, values=['', '4', '6'], width=10, state='readonly')
        ip_version_combo.grid(row=9, column=1, padx=10, pady=10, sticky='w')

        ttk.Label(dialog, text="Template Variables:").grid(row=10, column=0, padx=10, pady=10, sticky='w')
        variables_var = tk.StringVar(value=self.processor.format_mask_variables_text(mask.get('variables')))
        ttk.Entry(dialog, textvariable=variables_var, width=70).grid(row=10, column=1, padx=10, pady=10, sticky='ew')

        ttk.Label(dialog, text="Note: Variables use key=value, e.g. protocol=udp, permit_port=41495, deny_port=443, rule_description=client.").grid(row=11, column=0, columnspan=2, padx=10, pady=5, sticky='w')
        dialog.columnconfigure(1, weight=1)

        def save_changes():
            new_name = name_var.get().strip()
            new_prefix = prefix_var.get()
            new_suffix = suffix_var.get()
            new_separator = separator_var.get().replace('\\n', '\n').replace('\\t', '\t')
            new_category = category_var.get()
            new_description = description_var.get()
            new_header = header_var.get().replace('\\n', '\n').replace('\\t', '\t')
            new_line_template = line_template_var.get().replace('\\n', '\n').replace('\\t', '\t')
            new_footer = footer_var.get().replace('\\n', '\n').replace('\\t', '\t')
            new_ip_version = int(ip_version_var.get()) if ip_version_var.get() in ('4', '6') else None
            new_variables = self.processor.parse_mask_variables_text(variables_var.get())
            if not new_name:
                messagebox.showwarning("Warning", "Mask name is required.")
                return
            if new_name != name and any(m['name'] == new_name for m in self.processor.get_masks()):
                messagebox.showwarning("Warning", f"Mask '{new_name}' already exists.")
                return
            if new_name != name:
                self.processor.remove_mask(name)
            if self.processor.add_mask(
                new_name, new_prefix, new_suffix, new_separator, new_category, new_description,
                line_template=new_line_template,
                header=new_header,
                footer=new_footer,
                ip_version=new_ip_version,
                variables=new_variables,
            ):
                dialog.destroy()
                self.update_mask_display(self.mask_frame)
                self.refresh_mask_comboboxes()
                # Refresh category filter
                if hasattr(self, 'mask_category_combo'):
                    self.mask_category_combo['values'] = ['All'] + self.processor.get_mask_categories()

        ttk.Button(dialog, text="Save Changes", command=save_changes).grid(row=12, column=0, columnspan=2, pady=15)
        dialog.transient(self.root)
        dialog.grab_set()
        self.root.wait_window(dialog)

    def preview_mask(self):
        """Preview the mask being created with sample IPs."""
        prefix = self.new_mask_prefix.get()
        suffix = self.new_mask_suffix.get()
        separator = self.new_mask_separator.get().replace('\\n', '\n').replace('\\t', '\t')
        header = self.new_mask_header.get().replace('\\n', '\n').replace('\\t', '\t')
        line_template = self.new_mask_line_template.get().replace('\\n', '\n').replace('\\t', '\t')
        footer = self.new_mask_footer.get().replace('\\n', '\n').replace('\\t', '\t')
        ip_version = int(self.new_mask_ip_version.get()) if self.new_mask_ip_version.get() in ('4', '6') else None
        variables = self.processor.parse_mask_variables_text(self.new_mask_variables.get())

        # Sample IPs for preview
        sample_ips = ['192.168.1.0/24', '10.0.0.0/8', '172.16.0.0/12']

        # Apply mask
        temp_mask = {
            'name': '__preview__',
            'prefix': prefix,
            'suffix': suffix,
            'separator': separator,
        }
        if header:
            temp_mask['header'] = header
        if line_template:
            temp_mask['line_template'] = line_template
        if footer:
            temp_mask['footer'] = footer
        if ip_version in (4, 6):
            temp_mask['ip_version'] = ip_version
        if variables:
            temp_mask['variables'] = variables
        result = self.processor.apply_mask_definition(sample_ips, temp_mask, '__preview__')

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
        name = mask.get('name', 'Unknown')
        description = mask.get('description', '')

        # Sample IPs for preview
        sample_ips = ['192.168.1.0/24', '10.0.0.0/8', '172.16.0.0/12']

        # Apply mask
        result = self.processor.apply_mask(sample_ips, name)

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
        variables_text = self.processor.format_mask_variables_text(mask.get('variables'))
        if variables_text:
            ttk.Label(info_frame, text=f"Variables: {variables_text}", font=('Arial', 8), foreground='gray').pack(padx=5, pady=2, anchor='w')

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
        if not PSUTIL_AVAILABLE:
            return
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


def build_cli_parser() -> argparse.ArgumentParser:
    """Build the command-line parser used when arguments are provided."""
    parser = argparse.ArgumentParser(description="Extract, filter, optimize, and format IP/CIDR lists.")
    parser.add_argument('inputs', nargs='*', help='Input text files. If omitted, the GUI starts.')
    parser.add_argument('-o', '--output', help='Output file. Defaults to stdout.')
    parser.add_argument('--mask', default='default', help='Output mask name.')
    parser.add_argument('--mode', choices=EXTRACTION_MODES, default='smart', help='Extraction mode.')
    parser.add_argument('--ipv4-only', action='store_true', help='Process only IPv4.')
    parser.add_argument('--ipv6-only', action='store_true', help='Process only IPv6.')
    parser.add_argument('--optimize', action='store_true', help='Collapse duplicate and adjacent CIDR networks.')
    parser.add_argument('--aggressive', action='store_true', help='Enable aggressive optimization mode.')
    parser.add_argument('--allow-expansion', action='store_true', help='Allow aggressive merge to add extra covered addresses.')
    parser.add_argument('--max-extra-addresses', type=int, default=0, help='Maximum extra addresses allowed with --allow-expansion.')
    parser.add_argument('--public-only', action='store_true', help='Keep only globally routable networks.')
    parser.add_argument('--exclude-private', action='store_true', help='Drop private networks.')
    parser.add_argument('--exclude-loopback', action='store_true', help='Drop loopback networks.')
    parser.add_argument('--exclude-link-local', action='store_true', help='Drop link-local networks.')
    parser.add_argument('--exclude-multicast', action='store_true', help='Drop multicast networks.')
    parser.add_argument('--exclude-reserved', action='store_true', help='Drop reserved networks.')
    parser.add_argument('--exclude-unspecified', action='store_true', help='Drop unspecified networks.')
    parser.add_argument('--report', action='store_true', help='Print processing report to stderr.')
    return parser


def run_cli(argv: Optional[List[str]] = None) -> int:
    """Run the non-GUI CLI mode."""
    parser = build_cli_parser()
    args = parser.parse_args(argv)
    if not args.inputs:
        return 2

    include_ipv4 = not args.ipv6_only
    include_ipv6 = not args.ipv4_only
    if not include_ipv4 and not include_ipv6:
        parser.error('--ipv4-only and --ipv6-only cannot be used together')

    filters = {
        'public_only': args.public_only,
        'exclude_private': args.exclude_private,
        'exclude_loopback': args.exclude_loopback,
        'exclude_link_local': args.exclude_link_local,
        'exclude_multicast': args.exclude_multicast,
        'exclude_reserved': args.exclude_reserved,
        'exclude_unspecified': args.exclude_unspecified,
    }

    processor = IPCIDRProcessor()
    content_parts = []
    for file_path in args.inputs:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as handle:
            content_parts.append(handle.read())
    report = processor.build_processing_report(
        '\n'.join(content_parts),
        include_ipv4=include_ipv4,
        include_ipv6=include_ipv6,
        extraction_mode=args.mode,
        filters=filters,
        optimize=args.optimize,
        aggressive=args.aggressive,
        allow_expansion=args.allow_expansion,
        max_extra_addresses=max(0, args.max_extra_addresses),
    )
    output = processor.apply_mask(report['final_cidrs'], args.mask)
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as handle:
            handle.write(output)
    else:
        print(output)
    if args.report:
        print(processor.format_processing_report(report), file=sys.stderr)
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1:
        sys.exit(run_cli(sys.argv[1:]))
    if not TKINTER_AVAILABLE:
        print("tkinter is not installed. Install python3-tk to use the GUI, or pass input files for CLI mode.", file=sys.stderr)
        sys.exit(1)
    processor = IPCIDRProcessor()
    app = IPCIDRProcessorGUI(processor)
