import os
import re
import ipaddress
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import yaml
import requests
from typing import List, Dict, Set, Union, Tuple, Optional

class IPCIDRProcessor:
    def __init__(self):
        """Initialize the IP CIDR processor with configuration settings."""
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
        
        # Create output folder if it doesn't exist
        if not os.path.exists(self.output_folder):
            os.makedirs(self.output_folder)
        
        # Load or create configuration
        self.load_config()

    def load_config(self) -> None:
        """Load configuration from file or create with defaults."""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self.config = yaml.safe_load(f)
            else:
                self.config = self.default_config
                self.save_config()
        except Exception as e:
            print(f"Error loading configuration: {e}")
            self.config = self.default_config

    def save_config(self) -> bool:
        """Save current configuration to file."""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                yaml.dump(self.config, f, default_flow_style=False, allow_unicode=True)
            return True
        except Exception as e:
            print(f"Error saving configuration: {e}")
            return False

    def add_mask(self, name: str, prefix: str, suffix: str, separator: str) -> bool:
        """Add or update a mask in the configuration."""
        if not name:
            return False
            
        new_mask = {'name': name, 'prefix': prefix, 'suffix': suffix, 'separator': separator}
        
        # Update existing mask or add new one
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
            return False  # Don't allow removing the default mask
            
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
        # Return default if not found
        return next((m for m in self.config['masks'] if m['name'] == self.config['default_mask']), 
                    self.config['masks'][0])

    def extract_ips(self, text: str) -> List[str]:
        """
        Extract IPv4 addresses and CIDR notations from text.
        """
        # IPv4 CIDR pattern
        ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/\d{1,2})?\b'
        return re.findall(ipv4_pattern, text)

    def extract_ip_ranges(self, text: str) -> List[str]:
        """
        Extract IPv4 ranges from text.
        Returns list of ranges in format "start_ip-end_ip"
        """
        # IPv4 range pattern
        ipv4_range_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\s*-\s*(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        range_matches = re.findall(ipv4_range_pattern, text)
        # Standardize format
        return [re.sub(r'\s+', '', ip_range) for ip_range in range_matches]

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
            network = ipaddress.IPv4Network(cidr, strict=False)
            return True
        except ValueError:
            return False

    def sort_ip_addresses(self, ip_list: List[str]) -> List[str]:
        """Sort a list of IPv4 addresses and CIDR notations."""
        # Filter for only valid IPv4 addresses and CIDR
        valid_ips = []
        for ip in ip_list:
            try:
                # Check if it's a CIDR notation
                if '/' in ip:
                    network = ipaddress.IPv4Network(ip, strict=False)
                    valid_ips.append(ip)
                # Check if it's a plain IP
                else:
                    address = ipaddress.IPv4Address(ip)
                    valid_ips.append(ip)
            except ValueError:
                continue

        # Sort the IPs
        return sorted(valid_ips, key=lambda x: int(ipaddress.IPv4Network(
            x if '/' in x else f"{x}/32", strict=False).network_address))

    def range_to_cidrs(self, start_ip: str, end_ip: str) -> List[str]:
        """Convert an IP range to a list of CIDR notations."""
        try:
            start = ipaddress.IPv4Address(start_ip)
            end = ipaddress.IPv4Address(end_ip)
            
            # Validate range (start should be before end)
            if start > end:
                start, end = end, start
                
            return [str(cidr) for cidr in ipaddress.summarize_address_range(start, end)]
        except ValueError as e:
            print(f"Error converting range to CIDR: {e}")
            return []

    def cidr_to_range(self, cidr: str) -> Tuple[str, str]:
        """Convert a CIDR notation to an IP range (start_ip, end_ip)."""
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
            return str(network.network_address), str(network.broadcast_address)
        except ValueError as e:
            print(f"Error converting CIDR to range: {e}")
            return ("", "")

    def optimize_cidr_list(self, cidr_list: List[str], aggressive: bool = False) -> List[str]:
        """
        Optimize a list of CIDR notations by combining adjacent networks.
        
        Args:
            cidr_list: List of CIDR notations to optimize
            aggressive: If True, attempts more aggressive optimization with potential network expansion
        
        Returns:
            List of optimized CIDR notations
        """
        try:
            # Filter for valid IPv4 CIDRs only
            valid_networks = []
            for cidr in cidr_list:
                try:
                    network = ipaddress.IPv4Network(cidr, strict=False)
                    valid_networks.append(network)
                except ValueError:
                    continue
                    
            if not valid_networks:
                return []
                
            # Sort networks by address and prefix length (more specific first)
            valid_networks.sort(key=lambda n: (n.network_address, -n.prefixlen))
            
            # First pass: exact supernet matching
            optimized = []
            i = 0
            while i < len(valid_networks):
                current = valid_networks[i]
                merged = False
                
                # Look for a potential supernet match
                for j in range(len(optimized)):
                    if optimized[j].supernet_of(current):
                        # Already covered by a supernet
                        merged = True
                        break
                    elif current.supernet_of(optimized[j]):
                        # Current is a supernet of existing network
                        optimized[j] = current
                        merged = True
                        break
                
                if not merged:
                    # Try to find adjacent networks that can be combined
                    if aggressive and i < len(valid_networks) - 1:
                        # Check if current and next can be combined by reducing prefix length
                        current_prefix = current.prefixlen
                        while current_prefix > 0:
                            # Try combining with a shorter prefix
                            current_prefix -= 1
                            try:
                                supernet = ipaddress.IPv4Network(
                                    f"{current.network_address}/{current_prefix}", strict=False
                                )
                                
                                # Check if this supernet contains the next network
                                if supernet.supernet_of(valid_networks[i+1]):
                                    current = supernet
                                    i += 1  # Skip the next network as it's now included
                                    break
                            except ValueError:
                                continue
                    
                    optimized.append(current)
                
                i += 1
            
            # Second pass: collapse adjacent networks
            try:
                collapsed = list(ipaddress.collapse_addresses(optimized))
                return [str(net) for net in collapsed]
            except ValueError:
                # If collapse fails, return the first-pass results
                return [str(net) for net in optimized]
                
        except Exception as e:
            print(f"Error optimizing CIDR list: {e}")
            return cidr_list

    def apply_mask(self, ips: List[str], mask_name: str) -> str:
        """Apply a mask to format a list of IP addresses."""
        mask = self.get_mask_by_name(mask_name)
        
        formatted_ips = []
        for ip in ips:
            formatted_ips.append(f"{mask['prefix']}{ip}{mask['suffix']}")
            
        return mask['separator'].join(formatted_ips)

    def process_input_to_ips(self, input_text: str) -> List[str]:
        """
        Process input text to extract IPs, CIDR notations and ranges.
        Convert ranges to individual IPs.
        """
        # Extract IP addresses and CIDR notations
        cidrs = self.extract_ips(input_text)
        
        # Extract IP ranges
        ranges = self.extract_ip_ranges(input_text)
        
        all_ips = []
        
        # Process CIDR notations
        for cidr in cidrs:
            try:
                # If it's a plain IP, add /32
                if '/' not in cidr:
                    cidr = f"{cidr}/32"
                network = ipaddress.IPv4Network(cidr, strict=False)
                all_ips.append(str(network))
            except ValueError:
                continue
                
        # Process IP ranges
        for ip_range in ranges:
            try:
                start_ip, end_ip = ip_range.split('-')
                cidrs_from_range = self.range_to_cidrs(start_ip, end_ip)
                all_ips.extend(cidrs_from_range)
            except ValueError:
                continue
                
        return list(set(all_ips))  # Remove duplicates

    def download_file(self, url: str) -> str:
        """Download a file from a URL."""
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            return response.text
        except Exception as e:
            print(f"Error downloading file from URL {url}: {e}")
            return ""


class IPCIDRProcessorGUI:
    def __init__(self, processor: IPCIDRProcessor):
        """Initialize the GUI for the IP CIDR processor."""
        self.processor = processor
        self.root = tk.Tk()
        self.root.title("IP CIDR Processor")
        self.root.geometry("850x650")
        
        # Create main notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create tabs
        self.tab_process = ttk.Frame(self.notebook)
        self.tab_ranges = ttk.Frame(self.notebook)
        self.tab_optimize = ttk.Frame(self.notebook)
        self.tab_url = ttk.Frame(self.notebook)
        self.tab_masks = ttk.Frame(self.notebook)
        
        # Add tabs to notebook
        self.notebook.add(self.tab_process, text="Process Files")
        self.notebook.add(self.tab_ranges, text="IP Ranges")
        self.notebook.add(self.tab_optimize, text="Optimize CIDR")
        self.notebook.add(self.tab_url, text="URL Processing")
        self.notebook.add(self.tab_masks, text="Mask Settings")
        self.tab_xtables = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_xtables, text="Xtables Rules")
        
        # Set up tabs
        self.setup_process_tab()
        self.setup_ranges_tab()
        self.setup_optimize_tab()
        self.setup_url_tab()
        self.setup_masks_tab()
        self.setup_xtables_tab()
        
        # Start the main loop
        self.root.mainloop()

    def setup_process_tab(self):
        """Set up the file processing tab."""
        # Files frame
        frame_files = ttk.LabelFrame(self.tab_process, text="Select Files")
        frame_files.pack(fill='both', expand=True, padx=10, pady=5)
        
        # File list with scrollbar
        self.listbox_files = tk.Listbox(frame_files)
        self.listbox_files.pack(side='left', fill='both', expand=True)
        
        scrollbar = ttk.Scrollbar(frame_files, orient="vertical", command=self.listbox_files.yview)
        scrollbar.pack(side='right', fill='y')
        self.listbox_files.config(yscrollcommand=scrollbar.set)
        
        # Button frame
        btn_frame = ttk.Frame(self.tab_process)
        btn_frame.pack(fill='x', padx=10, pady=5)
        
        # Add file button
        btn_add_files = ttk.Button(btn_frame, text="Add Files", command=self.add_local_files)
        btn_add_files.pack(side='left', padx=5)
        
        # Clear list button
        btn_clear_files = ttk.Button(btn_frame, text="Clear List", command=self.clear_local_files)
        btn_clear_files.pack(side='left', padx=5)
        
        # Output options frame
        output_frame = ttk.LabelFrame(self.tab_process, text="Output Options")
        output_frame.pack(fill='x', padx=10, pady=5)
        
        # Mask selection
        ttk.Label(output_frame, text="Apply Mask:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.process_mask_var = tk.StringVar()
        self.process_mask_combo = ttk.Combobox(output_frame, textvariable=self.process_mask_var)
        self.process_mask_combo['values'] = self.processor.get_mask_names()
        self.process_mask_combo.current(0)
        self.process_mask_combo.grid(row=0, column=1, padx=5, pady=5, sticky='w')
        
        # Process button
        btn_process = ttk.Button(self.tab_process, text="Process Files", command=self.process_local_files)
        btn_process.pack(pady=10)

    def setup_ranges_tab(self):
        """Set up the IP ranges conversion tab."""
        # Range to CIDR frame
        range_to_cidr_frame = ttk.LabelFrame(self.tab_ranges, text="Convert IP Range to CIDR")
        range_to_cidr_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(range_to_cidr_frame, text="Start IP:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.range_start_var = tk.StringVar()
        entry_start = ttk.Entry(range_to_cidr_frame, textvariable=self.range_start_var, width=20)
        entry_start.grid(row=0, column=1, padx=5, pady=5, sticky='w')
        
        ttk.Label(range_to_cidr_frame, text="End IP:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.range_end_var = tk.StringVar()
        entry_end = ttk.Entry(range_to_cidr_frame, textvariable=self.range_end_var, width=20)
        entry_end.grid(row=1, column=1, padx=5, pady=5, sticky='w')
        
        btn_convert_to_cidr = ttk.Button(range_to_cidr_frame, text="Convert to CIDR", 
                                         command=self.convert_range_to_cidr)
        btn_convert_to_cidr.grid(row=2, column=0, columnspan=2, padx=5, pady=5)
        
        # CIDR to Range frame
        cidr_to_range_frame = ttk.LabelFrame(self.tab_ranges, text="Convert CIDR to IP Range")
        cidr_to_range_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(cidr_to_range_frame, text="CIDR:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.cidr_var = tk.StringVar()
        entry_cidr = ttk.Entry(cidr_to_range_frame, textvariable=self.cidr_var, width=20)
        entry_cidr.grid(row=0, column=1, padx=5, pady=5, sticky='w')
        
        btn_convert_to_range = ttk.Button(cidr_to_range_frame, text="Convert to Range", 
                                         command=self.convert_cidr_to_range)
        btn_convert_to_range.grid(row=1, column=0, columnspan=2, padx=5, pady=5)
        
        # Results frame
        results_frame = ttk.LabelFrame(self.tab_ranges, text="Results")
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.results_text = tk.Text(results_frame, wrap='word', height=15)
        self.results_text.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        results_scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.results_text.yview)
        results_scrollbar.pack(side='right', fill='y')
        self.results_text.config(yscrollcommand=results_scrollbar.set)
        
        # Copy and clear buttons
        btn_frame = ttk.Frame(self.tab_ranges)
        btn_frame.pack(fill='x', padx=10, pady=5)
        
        btn_copy = ttk.Button(btn_frame, text="Copy Results", command=self.copy_results)
        btn_copy.pack(side='left', padx=5)
        
        btn_clear_results = ttk.Button(btn_frame, text="Clear Results", command=self.clear_results)
        btn_clear_results.pack(side='left', padx=5)
        
        btn_save_results = ttk.Button(btn_frame, text="Save Results", command=self.save_results)
        btn_save_results.pack(side='right', padx=5)

    def setup_optimize_tab(self):
        """Set up the CIDR optimization tab."""
        # Files frame
        frame_files = ttk.LabelFrame(self.tab_optimize, text="Select Files with CIDR Notations")
        frame_files.pack(fill='both', expand=True, padx=10, pady=5)
        
        # File list with scrollbar
        self.listbox_files_optimize = tk.Listbox(frame_files)
        self.listbox_files_optimize.pack(side='left', fill='both', expand=True)
        
        scrollbar = ttk.Scrollbar(frame_files, orient="vertical", command=self.listbox_files_optimize.yview)
        scrollbar.pack(side='right', fill='y')
        self.listbox_files_optimize.config(yscrollcommand=scrollbar.set)
        
        # Button frame
        btn_frame = ttk.Frame(self.tab_optimize)
        btn_frame.pack(fill='x', padx=10, pady=5)
        
        # Add file button
        btn_add_files = ttk.Button(btn_frame, text="Add Files", 
                                  command=lambda: self.add_local_files(optimize=True))
        btn_add_files.pack(side='left', padx=5)
        
        # Clear list button
        btn_clear_files = ttk.Button(btn_frame, text="Clear List", 
                                    command=lambda: self.clear_local_files(optimize=True))
        btn_clear_files.pack(side='left', padx=5)
        
        # Output options frame
        output_frame = ttk.LabelFrame(self.tab_optimize, text="Optimization Options")
        output_frame.pack(fill='x', padx=10, pady=5)
        
        # Aggressive optimization checkbox
        self.aggressive_var = tk.BooleanVar()
        self.aggressive_var.set(False)
        chk_aggressive = ttk.Checkbutton(output_frame, text="Aggressive Optimization", 
                                        variable=self.aggressive_var)
        chk_aggressive.pack(anchor='w', padx=5, pady=5)
        
        # Mask selection
        ttk.Label(output_frame, text="Apply Mask:").pack(anchor='w', padx=5, pady=5)
        self.optimize_mask_var = tk.StringVar()
        self.optimize_mask_combo = ttk.Combobox(output_frame, textvariable=self.optimize_mask_var)
        self.optimize_mask_combo['values'] = self.processor.get_mask_names()
        self.optimize_mask_combo.current(0)
        self.optimize_mask_combo.pack(anchor='w', padx=5, pady=5)
        
        # Optimize button
        btn_optimize = ttk.Button(self.tab_optimize, text="Optimize CIDR", command=self.optimize_files)
        btn_optimize.pack(pady=10)

    def setup_url_tab(self):
        """Set up the URL processing tab."""
        # URLs frame
        frame_urls = ttk.LabelFrame(self.tab_url, text="URL Processing")
        frame_urls.pack(fill='both', expand=True, padx=10, pady=5)
        
        # URL list with scrollbar
        self.listbox_urls = tk.Listbox(frame_urls)
        self.listbox_urls.pack(side='left', fill='both', expand=True)
        
        scrollbar = ttk.Scrollbar(frame_urls, orient="vertical", command=self.listbox_urls.yview)
        scrollbar.pack(side='right', fill='y')
        self.listbox_urls.config(yscrollcommand=scrollbar.set)
        
        # Button frame
        btn_frame = ttk.Frame(self.tab_url)
        btn_frame.pack(fill='x', padx=10, pady=5)
        
        # Add URL button
        btn_add_url = ttk.Button(btn_frame, text="Add URL", command=self.add_url)
        btn_add_url.pack(side='left', padx=5)
        
        # Clear URLs button
        btn_clear_urls = ttk.Button(btn_frame, text="Clear URLs", command=self.clear_urls)
        btn_clear_urls.pack(side='left', padx=5)
        
        # Output options frame
        output_frame = ttk.LabelFrame(self.tab_url, text="Output Options")
        output_frame.pack(fill='x', padx=10, pady=5)
        
        # Optimize checkbox
        self.url_optimize_var = tk.BooleanVar()
        self.url_optimize_var.set(True)
        chk_optimize = ttk.Checkbutton(output_frame, text="Optimize CIDR Results", 
                                      variable=self.url_optimize_var)
        chk_optimize.pack(anchor='w', padx=5, pady=5)
        
        # Mask selection
        ttk.Label(output_frame, text="Apply Mask:").pack(anchor='w', padx=5, pady=5)
        self.url_mask_var = tk.StringVar()
        self.url_mask_combo = ttk.Combobox(output_frame, textvariable=self.url_mask_var)
        self.url_mask_combo['values'] = self.processor.get_mask_names()
        self.url_mask_combo.current(0)
        self.url_mask_combo.pack(anchor='w', padx=5, pady=5)
        
        # Process button
        btn_process_urls = ttk.Button(self.tab_url, text="Process URLs", command=self.process_urls)
        btn_process_urls.pack(pady=10)

    def setup_masks_tab(self):
        """Set up the mask settings tab."""
        # Current masks frame
        masks_frame = ttk.LabelFrame(self.tab_masks, text="Current Masks")
        masks_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Create a canvas with scrollbar for the masks
        canvas = tk.Canvas(masks_frame)
        scrollbar = ttk.Scrollbar(masks_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Default mask frame (moved up to initialize self.default_mask_combo earlier)
        default_mask_frame = ttk.LabelFrame(self.tab_masks, text="Default Mask")
        default_mask_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(default_mask_frame, text="Select Default Mask:").pack(side='left', padx=5, pady=5)
        self.default_mask_var = tk.StringVar()
        self.default_mask_combo = ttk.Combobox(default_mask_frame, textvariable=self.default_mask_var)
        self.default_mask_combo['values'] = self.processor.get_mask_names()
        # Set current default
        current_default = next((i for i, name in enumerate(self.processor.get_mask_names()) 
                                if name == self.processor.config['default_mask']), 0)
        self.default_mask_combo.current(current_default)
        self.default_mask_combo.pack(side='left', padx=5, pady=5)
        
        # Set default button
        btn_set_default = ttk.Button(default_mask_frame, text="Set as Default", 
                                    command=self.set_default_mask)
        btn_set_default.pack(side='left', padx=5, pady=5)
        
        # Add the existing masks to the frame (after default_mask_combo is initialized)
        self.mask_entries = {}
        self.update_mask_display(scrollable_frame)
        
        # New mask frame
        new_mask_frame = ttk.LabelFrame(self.tab_masks, text="Add New Mask")
        new_mask_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(new_mask_frame, text="Name:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.new_mask_name = tk.StringVar()
        entry_name = ttk.Entry(new_mask_frame, textvariable=self.new_mask_name, width=20)
        entry_name.grid(row=0, column=1, padx=5, pady=5, sticky='w')
        
        ttk.Label(new_mask_frame, text="Prefix:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.new_mask_prefix = tk.StringVar()
        entry_prefix = ttk.Entry(new_mask_frame, textvariable=self.new_mask_prefix, width=20)
        entry_prefix.grid(row=1, column=1, padx=5, pady=5, sticky='w')
        
        ttk.Label(new_mask_frame, text="Suffix:").grid(row=2, column=0, padx=5, pady=5, sticky='w')
        self.new_mask_suffix = tk.StringVar()
        entry_suffix = ttk.Entry(new_mask_frame, textvariable=self.new_mask_suffix, width=20)
        entry_suffix.grid(row=2, column=1, padx=5, pady=5, sticky='w')
        
        ttk.Label(new_mask_frame, text="Separator:").grid(row=3, column=0, padx=5, pady=5, sticky='w')
        self.new_mask_separator = tk.StringVar()
        self.new_mask_separator.set("\\n")  # Default to newline
        entry_separator = ttk.Entry(new_mask_frame, textvariable=self.new_mask_separator, width=20)
        entry_separator.grid(row=3, column=1, padx=5, pady=5, sticky='w')
        
        ttk.Label(new_mask_frame, text="Note: Use \\n for newline").grid(row=4, column=0, columnspan=2, padx=5, pady=5, sticky='w')
        
        # Add mask button
        btn_add_mask = ttk.Button(new_mask_frame, text="Add Mask", command=self.add_new_mask)
        btn_add_mask.grid(row=5, column=0, columnspan=2, padx=5, pady=5)
        
        # Refresh button
        btn_refresh = ttk.Button(self.tab_masks, text="Refresh Masks", command=self.refresh_masks)
        btn_refresh.pack(pady=10)

    def update_mask_display(self, parent_frame):
        """Update the display of masks in the settings tab."""
        # Clear existing widgets
        for widget in parent_frame.winfo_children():
            widget.destroy()
            
        # Add header
        ttk.Label(parent_frame, text="Name", width=15).grid(row=0, column=0, padx=5, pady=5)
        ttk.Label(parent_frame, text="Prefix", width=15).grid(row=0, column=1, padx=5, pady=5)
        ttk.Label(parent_frame, text="Suffix", width=15).grid(row=0, column=2, padx=5, pady=5)
        ttk.Label(parent_frame, text="Separator", width=15).grid(row=0, column=3, padx=5, pady=5)
        ttk.Label(parent_frame, text="Actions", width=15).grid(row=0, column=4, padx=5, pady=5)
        
        # Add each mask
        for i, mask in enumerate(self.processor.get_masks()):
            ttk.Label(parent_frame, text=mask['name']).grid(row=i+1, column=0, padx=5, pady=5)
            ttk.Label(parent_frame, text=mask['prefix']).grid(row=i+1, column=1, padx=5, pady=5)
            ttk.Label(parent_frame, text=mask['suffix']).grid(row=i+1, column=2, padx=5, pady=5)
            
            # Display separator with special handling for newlines
            separator_display = mask['separator'].replace('\n', '\\n')
            ttk.Label(parent_frame, text=separator_display).grid(row=i+1, column=3, padx=5, pady=5)
            
            # Add edit and delete buttons
            btn_frame = ttk.Frame(parent_frame)
            btn_frame.grid(row=i+1, column=4, padx=5, pady=5)
            
            # Edit button
            btn_edit = ttk.Button(btn_frame, text="Edit", 
                                command=lambda name=mask['name']: self.edit_mask(name))
            btn_edit.pack(side='left', padx=2)
            
            # Delete button (disabled for default mask)
            btn_delete = ttk.Button(btn_frame, text="Delete", 
                                  command=lambda name=mask['name']: self.delete_mask(name))
            btn_delete.pack(side='left', padx=2)
            if mask['name'] == 'default':
                btn_delete['state'] = 'disabled'
        
        # Update comboboxes in other tabs
        self.refresh_mask_comboboxes()

    def refresh_mask_comboboxes(self):
        """Update all mask comboboxes with current mask names."""
        mask_names = self.processor.get_mask_names()
        
        # Update comboboxes in all tabs
        self.process_mask_combo['values'] = mask_names
        self.optimize_mask_combo['values'] = mask_names
        self.url_mask_combo['values'] = mask_names
        
        # Only update default_mask_combo if it exists
        if hasattr(self, 'default_mask_combo'):
            self.default_mask_combo['values'] = mask_names
        
        # Make sure all comboboxes have a valid selection
        if self.process_mask_var.get() not in mask_names:
            self.process_mask_combo.current(0)
        if self.optimize_mask_var.get() not in mask_names:
            self.optimize_mask_combo.current(0)
        if self.url_mask_var.get() not in mask_names:
            self.url_mask_combo.current(0)
        if hasattr(self, 'default_mask_combo') and self.default_mask_var.get() not in mask_names:
            self.default_mask_combo.current(0)

    # File Processing Tab Methods
    def add_local_files(self, optimize=False, xtables=False):
        files = filedialog.askopenfilenames(
            title="Select Files",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if optimize:
            listbox = self.listbox_files_optimize
        elif xtables:
            listbox = self.listbox_files_xtables
        else:
            listbox = self.listbox_files
        
        for file in files:
            if file not in listbox.get(0, tk.END):
                listbox.insert(tk.END, file)
    
    def clear_local_files(self, optimize=False, xtables=False):
        if optimize:
            listbox = self.listbox_files_optimize
        elif xtables:
            listbox = self.listbox_files_xtables
        else:
            listbox = self.listbox_files
        listbox.delete(0, tk.END)

    def process_local_files(self):
        """Process files to extract and format IP addresses."""
        files = self.listbox_files.get(0, tk.END)
        if not files:
            messagebox.showwarning("Warning", "No files selected.")
            return
            
        all_cidrs = []
        
        # Process each file
        for file in files:
            try:
                with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Extract IPs and ranges
                ips = self.processor.extract_ips(content)
                ranges = self.processor.extract_ip_ranges(content)
                
                # Convert ranges to CIDRs
                for ip_range in ranges:
                    try:
                        start_ip, end_ip = ip_range.split('-')
                        cidrs_from_range = self.processor.range_to_cidrs(start_ip, end_ip)
                        all_cidrs.extend(cidrs_from_range)
                    except ValueError:
                        continue
                
                # Add single IPs and CIDRs
                for ip in ips:
                    # If it's a single IP, add /32
                    if '/' not in ip:
                        ip = f"{ip}/32"
                    all_cidrs.append(ip)
                    
            except Exception as e:
                messagebox.showerror("Error", f"Error processing file {file}: {e}")
                return
        
        # Remove duplicates
        unique_cidrs = list(set(all_cidrs))
        
        # Sort IPs
        sorted_cidrs = self.processor.sort_ip_addresses(unique_cidrs)
        
        # Format with mask
        mask_name = self.process_mask_var.get()
        formatted_content = self.processor.apply_mask(sorted_cidrs, mask_name)
        
        # Save to file
        output_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        
        if output_path:
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(formatted_content)
                messagebox.showinfo("Success", f"Processed {len(sorted_cidrs)} IPs saved to: {output_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Error saving results: {e}")

    # IP Ranges Tab Methods
    def convert_range_to_cidr(self):
        """Convert IP range to CIDR notation."""
        start_ip = self.range_start_var.get().strip()
        end_ip = self.range_end_var.get().strip()
        
        if not start_ip or not end_ip:
            messagebox.showwarning("Warning", "Please enter both start and end IP addresses.")
            return
            
        # Validate IPs
        if not self.processor.is_valid_ipv4(start_ip) or not self.processor.is_valid_ipv4(end_ip):
            messagebox.showerror("Error", "Invalid IP address format.")
            return
            
        # Convert
        cidrs = self.processor.range_to_cidrs(start_ip, end_ip)
        
        if not cidrs:
            messagebox.showwarning("Warning", "Could not convert range to CIDR.")
            return
            
        # Display result
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "IP Range to CIDR Results:\n\n")
        self.results_text.insert(tk.END, f"Range: {start_ip} - {end_ip}\n\n")
        self.results_text.insert(tk.END, "CIDR Notations:\n")
        for cidr in cidrs:
            self.results_text.insert(tk.END, f"{cidr}\n")

    def convert_cidr_to_range(self):
        """Convert CIDR notation to IP range."""
        cidr = self.cidr_var.get().strip()
        
        if not cidr:
            messagebox.showwarning("Warning", "Please enter a CIDR notation.")
            return
            
        # Validate CIDR
        if not self.processor.is_valid_ipv4_cidr(cidr):
            messagebox.showerror("Error", "Invalid CIDR notation format.")
            return
            
        # Convert
        start_ip, end_ip = self.processor.cidr_to_range(cidr)
        
        if not start_ip or not end_ip:
            messagebox.showwarning("Warning", "Could not convert CIDR to range.")
            return
            
        # Get network details
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
            prefix_length = network.prefixlen
            netmask = str(network.netmask)
            hosts_count = network.num_addresses
            
            # Display result
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, "CIDR to IP Range Results:\n\n")
            self.results_text.insert(tk.END, f"CIDR: {cidr}\n")
            self.results_text.insert(tk.END, f"Network: {network.network_address}\n")
            self.results_text.insert(tk.END, f"Broadcast: {network.broadcast_address}\n")
            self.results_text.insert(tk.END, f"Netmask: {netmask}\n")
            self.results_text.insert(tk.END, f"Prefix Length: /{prefix_length}\n")
            self.results_text.insert(tk.END, f"Number of Addresses: {hosts_count}\n\n")
            self.results_text.insert(tk.END, f"IP Range: {start_ip} - {end_ip}\n")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error analyzing CIDR: {e}")

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
        content = self.results_text.get(1.0, tk.END)
        if not content.strip():
            messagebox.showwarning("Warning", "No results to save.")
            return
            
        output_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        
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
        files = self.listbox_files_optimize.get(0, tk.END)
        if not files:
            messagebox.showwarning("Warning", "No files selected.")
            return
            
        all_cidrs = []
        
        # Process each file
        for file in files:
            try:
                with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Extract IPs and CIDR notations
                cidrs = self.processor.extract_ips(content)
                all_cidrs.extend(cidrs)
                    
            except Exception as e:
                messagebox.showerror("Error", f"Error processing file {file}: {e}")
                return
        
        # Remove duplicates
        unique_cidrs = list(set(all_cidrs))
        
        # Optimize CIDRs
        aggressive = self.aggressive_var.get()
        optimized_cidrs = self.processor.optimize_cidr_list(unique_cidrs, aggressive)
        
        # Sort optimized CIDRs
        sorted_cidrs = self.processor.sort_ip_addresses(optimized_cidrs)
        
        # Format with mask
        mask_name = self.optimize_mask_var.get()
        formatted_content = self.processor.apply_mask(sorted_cidrs, mask_name)
        
        # Save to file
        output_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        
        if output_path:
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(formatted_content)
                messagebox.showinfo(
                    "Success", 
                    f"Optimized {len(unique_cidrs)} IPs into {len(sorted_cidrs)} networks.\n"
                    f"Results saved to: {output_path}"
                )
            except Exception as e:
                messagebox.showerror("Error", f"Error saving results: {e}")

    # URL Processing Tab Methods
    def add_url(self):
        """Add a URL to the URL listbox."""
        url = simpledialog.askstring("Add URL", "Enter URL:")
        if url and url not in self.listbox_urls.get(0, tk.END):
            self.listbox_urls.insert(tk.END, url)

    def clear_urls(self):
        """Clear the URL listbox."""
        self.listbox_urls.delete(0, tk.END)

    def process_urls(self):
        """Process URLs to extract and format IP addresses."""
        urls = self.listbox_urls.get(0, tk.END)
        if not urls:
            messagebox.showwarning("Warning", "No URLs added.")
            return
            
        all_cidrs = []
        
        # Process each URL
        for url in urls:
            try:
                # Download content
                content = self.processor.download_file(url)
                if not content:
                    messagebox.showwarning("Warning", f"Could not download content from {url}")
                    continue
                
                # Extract IPs and ranges
                ips = self.processor.extract_ips(content)
                ranges = self.processor.extract_ip_ranges(content)
                
                # Convert ranges to CIDRs
                for ip_range in ranges:
                    try:
                        start_ip, end_ip = ip_range.split('-')
                        cidrs_from_range = self.processor.range_to_cidrs(start_ip, end_ip)
                        all_cidrs.extend(cidrs_from_range)
                    except ValueError:
                        continue
                
                # Add single IPs and CIDRs
                for ip in ips:
                    # If it's a single IP, add /32
                    if '/' not in ip:
                        ip = f"{ip}/32"
                    all_cidrs.append(ip)
                    
            except Exception as e:
                messagebox.showerror("Error", f"Error processing URL {url}: {e}")
                return
        
        # Remove duplicates
        unique_cidrs = list(set(all_cidrs))
        
        # Optimize if requested
        if self.url_optimize_var.get():
            optimized_cidrs = self.processor.optimize_cidr_list(unique_cidrs)
            sorted_cidrs = self.processor.sort_ip_addresses(optimized_cidrs)
        else:
            sorted_cidrs = self.processor.sort_ip_addresses(unique_cidrs)
        
        # Format with mask
        mask_name = self.url_mask_var.get()
        formatted_content = self.processor.apply_mask(sorted_cidrs, mask_name)
        
        # Save to file
        output_path = filedialog.asksaveasfilename(
            defaultextension=".txt", 
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        
        if output_path:
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(formatted_content)
                    
                if self.url_optimize_var.get():
                    messagebox.showinfo(
                        "Success", 
                        f"Processed {len(unique_cidrs)} IPs and optimized to {len(sorted_cidrs)} networks.\n"
                        f"Results saved to: {output_path}"
                    )
                else:
                    messagebox.showinfo(
                        "Success", 
                        f"Processed {len(sorted_cidrs)} IPs saved to: {output_path}"
                    )
            except Exception as e:
                messagebox.showerror("Error", f"Error saving results: {e}")

    # Mask Settings Tab Methods
    def add_new_mask(self):
        """Add a new mask to the configuration."""
        name = self.new_mask_name.get().strip()
        prefix = self.new_mask_prefix.get()
        suffix = self.new_mask_suffix.get()
        separator = self.new_mask_separator.get().replace('\\n', '\n')
        
        if not name:
            messagebox.showwarning("Warning", "Mask name is required.")
            return
            
        if self.processor.add_mask(name, prefix, suffix, separator):
            messagebox.showinfo("Success", f"Mask '{name}' added successfully.")
            # Update mask display
            self.refresh_masks()
            # Clear entries
            self.new_mask_name.set("")
            self.new_mask_prefix.set("")
            self.new_mask_suffix.set("")
            self.new_mask_separator.set("\\n")
        else:
            messagebox.showerror("Error", f"Failed to add mask '{name}'.")

    def edit_mask(self, name):
        """Edit an existing mask."""
        mask = self.processor.get_mask_by_name(name)
        if not mask:
            messagebox.showerror("Error", f"Mask '{name}' not found.")
            return
            
        # Create a dialog window
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Edit Mask: {name}")
        dialog.geometry("400x250")
        dialog.resizable(False, False)
        
        # Create form fields
        ttk.Label(dialog, text="Name:").grid(row=0, column=0, padx=10, pady=10, sticky='w')
        name_var = tk.StringVar(value=mask['name'])
        entry_name = ttk.Entry(dialog, textvariable=name_var, width=30)
        entry_name.grid(row=0, column=1, padx=10, pady=10, sticky='w')
        
        ttk.Label(dialog, text="Prefix:").grid(row=1, column=0, padx=10, pady=10, sticky='w')
        prefix_var = tk.StringVar(value=mask['prefix'])
        entry_prefix = ttk.Entry(dialog, textvariable=prefix_var, width=30)
        entry_prefix.grid(row=1, column=1, padx=10, pady=10, sticky='w')
        
        ttk.Label(dialog, text="Suffix:").grid(row=2, column=0, padx=10, pady=10, sticky='w')
        suffix_var = tk.StringVar(value=mask['suffix'])
        entry_suffix = ttk.Entry(dialog, textvariable=suffix_var, width=30)
        entry_suffix.grid(row=2, column=1, padx=10, pady=10, sticky='w')
        
        ttk.Label(dialog, text="Separator:").grid(row=3, column=0, padx=10, pady=10, sticky='w')
        separator_var = tk.StringVar(value=mask['separator'].replace('\n', '\\n'))
        entry_separator = ttk.Entry(dialog, textvariable=separator_var, width=30)
        entry_separator.grid(row=3, column=1, padx=10, pady=10, sticky='w')
        
        ttk.Label(dialog, text="Note: Use \\n for newline").grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky='w')
        
        # Save button
        def save_changes():
            new_name = name_var.get().strip()
            new_prefix = prefix_var.get()
            new_suffix = suffix_var.get()
            new_separator = separator_var.get().replace('\\n', '\n')
            
            if not new_name:
                messagebox.showwarning("Warning", "Mask name is required.")
                return
                
            # Check if name changed and exists
            if new_name != name and any(m['name'] == new_name for m in self.processor.get_masks()):
                messagebox.showwarning("Warning", f"Mask '{new_name}' already exists.")
                return
                
            # Remove old mask if name changed
            if new_name != name:
                self.processor.remove_mask(name)
                
            # Add new/updated mask
            if self.processor.add_mask(new_name, new_prefix, new_suffix, new_separator):
                messagebox.showinfo("Success", f"Mask '{new_name}' updated successfully.")
                dialog.destroy()
                self.refresh_masks()
            else:
                messagebox.showerror("Error", f"Failed to update mask.")
                
        ttk.Button(dialog, text="Save Changes", command=save_changes).grid(row=5, column=0, columnspan=2, pady=15)
        
        # Make dialog modal
        dialog.transient(self.root)
        dialog.grab_set()
        self.root.wait_window(dialog)

    def delete_mask(self, name):
        """Delete a mask from the configuration."""
        if name == 'default':
            messagebox.showwarning("Warning", "Cannot delete the default mask.")
            return
            
        if messagebox.askyesno("Confirm", f"Are you sure you want to delete mask '{name}'?"):
            if self.processor.remove_mask(name):
                messagebox.showinfo("Success", f"Mask '{name}' deleted successfully.")
                self.refresh_masks()
            else:
                messagebox.showerror("Error", f"Failed to delete mask '{name}'.")

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

    def setup_xtables_tab(self):
        # Files frame
        frame_files = ttk.LabelFrame(self.tab_xtables, text="Select Files with CIDR Notations")
        frame_files.pack(fill='both', expand=True, padx=10, pady=5)
        
        # File list with scrollbar
        self.listbox_files_xtables = tk.Listbox(frame_files)
        self.listbox_files_xtables.pack(side='left', fill='both', expand=True)
        
        scrollbar = ttk.Scrollbar(frame_files, orient="vertical", command=self.listbox_files_xtables.yview)
        scrollbar.pack(side='right', fill='y')
        self.listbox_files_xtables.config(yscrollcommand=scrollbar.set)
        
        # Button frame
        btn_frame = ttk.Frame(self.tab_xtables)
        btn_frame.pack(fill='x', padx=10, pady=5)
        
        # Add file button
        btn_add_files = ttk.Button(btn_frame, text="Add Files", 
                                  command=lambda: self.add_local_files(xtables=True))
        btn_add_files.pack(side='left', padx=5)
        
        # Clear list button
        btn_clear_files = ttk.Button(btn_frame, text="Clear List", 
                                    command=lambda: self.clear_local_files(xtables=True))
        btn_clear_files.pack(side='left', padx=5)
        
        # Options frame
        options_frame = ttk.LabelFrame(self.tab_xtables, text="Rule Options")
        options_frame.pack(fill='x', padx=10, pady=5)
        
        # Chain selection
        ttk.Label(options_frame, text="Chain:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.chain_var = tk.StringVar()
        chain_combo = ttk.Combobox(options_frame, textvariable=self.chain_var, 
                                   values=["INPUT", "OUTPUT", "FORWARD"])
        chain_combo.current(0)
        chain_combo.grid(row=0, column=1, padx=5, pady=5, sticky='w')
        
        # Action selection
        ttk.Label(options_frame, text="Action:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.action_var = tk.StringVar()
        action_combo = ttk.Combobox(options_frame, textvariable=self.action_var, 
                                    values=["ACCEPT", "DROP", "REJECT"])
        action_combo.current(1)  # Default to DROP
        action_combo.grid(row=1, column=1, padx=5, pady=5, sticky='w')
        
        # Match type
        ttk.Label(options_frame, text="Match On:").grid(row=2, column=0, padx=5, pady=5, sticky='w')
        self.match_var = tk.StringVar()
        match_combo = ttk.Combobox(options_frame, textvariable=self.match_var, 
                                   values=["Source IP", "Destination IP"])
        match_combo.current(0)  # Default to Source IP
        match_combo.grid(row=2, column=1, padx=5, pady=5, sticky='w')
        
        # Optimize checkbox
        self.xtables_optimize_var = tk.BooleanVar()
        self.xtables_optimize_var.set(True)
        chk_optimize = ttk.Checkbutton(options_frame, text="Optimize CIDR List", 
                                       variable=self.xtables_optimize_var)
        chk_optimize.grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky='w')
        
        # Generate button
        btn_generate = ttk.Button(self.tab_xtables, text="Generate Rules", command=self.generate_xtables_rules)
        btn_generate.pack(pady=10)
        
        # Results frame
        results_frame = ttk.LabelFrame(self.tab_xtables, text="Generated Rules")
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.xtables_results_text = tk.Text(results_frame, wrap='word', height=15)
        self.xtables_results_text.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        results_scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.xtables_results_text.yview)
        results_scrollbar.pack(side='right', fill='y')
        self.xtables_results_text.config(yscrollcommand=results_scrollbar.set)
        
        # Copy and save buttons
        btn_copy = ttk.Button(self.tab_xtables, text="Copy Rules", command=self.copy_xtables_rules)
        btn_copy.pack(side='left', padx=5, pady=5)
        
        btn_save = ttk.Button(self.tab_xtables, text="Save Rules", command=self.save_xtables_rules)
        btn_save.pack(side='left', padx=5, pady=5)

    def generate_xtables_rules(self):
        files = self.listbox_files_xtables.get(0, tk.END)
        if not files:
            messagebox.showwarning("Warning", "No files selected.")
            return
        
        chain = self.chain_var.get()
        action = self.action_var.get()
        match_on = self.match_var.get()
        
        if not chain or not action or not match_on:
            messagebox.showwarning("Warning", "Please select chain, action, and match type.")
            return
        
        match_flag = "-s" if match_on == "Source IP" else "-d"
        
        all_cidrs = []
        
        for file in files:
            try:
                with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                cidrs = self.processor.extract_ips(content)
                all_cidrs.extend(cidrs)
            except Exception as e:
                messagebox.showerror("Error", f"Error reading file {file}: {e}")
                return
        
        # Remove duplicates
        unique_cidrs = list(set(all_cidrs))
        
        if self.xtables_optimize_var.get():
            optimized_cidrs = self.processor.optimize_cidr_list(unique_cidrs)
            sorted_cidrs = self.processor.sort_ip_addresses(optimized_cidrs)
        else:
            sorted_cidrs = self.processor.sort_ip_addresses(unique_cidrs)
        
        # Generate rules
        rules = []
        for cidr in sorted_cidrs:
            rule = f"iptables -A {chain} {match_flag} {cidr} -j {action}"
            rules.append(rule)
        
        # Display in text area
        self.xtables_results_text.delete(1.0, tk.END)
        self.xtables_results_text.insert(tk.END, "\n".join(rules))
    
    def copy_xtables_rules(self):
        content = self.xtables_results_text.get(1.0, tk.END).strip()
        if content:
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            messagebox.showinfo("Copied", "Rules copied to clipboard.")
        else:
            messagebox.showwarning("Warning", "No rules to copy.")
    
    def save_xtables_rules(self):
        content = self.xtables_results_text.get(1.0, tk.END).strip()
        if not content:
            messagebox.showwarning("Warning", "No rules to save.")
            return
        
        output_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        
        if output_path:
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo("Success", f"Rules saved to: {output_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Error saving rules: {e}")

    def refresh_masks(self):
        """Refresh the mask display and comboboxes."""
        # First find the correct frame to update
        for widget in self.tab_masks.winfo_children():
            if isinstance(widget, ttk.LabelFrame) and widget.winfo_children():
                for child in widget.winfo_children():
                    if isinstance(child, tk.Canvas) and child.winfo_children():
                        for canvas_child in child.winfo_children():
                            if isinstance(canvas_child, ttk.Frame):
                                # Update the mask display
                                self.update_mask_display(canvas_child)
                                break
                        break
                break
        # Update comboboxes
        self.refresh_mask_comboboxes()


if __name__ == "__main__":
    processor = IPCIDRProcessor()
    app = IPCIDRProcessorGUI(processor)
