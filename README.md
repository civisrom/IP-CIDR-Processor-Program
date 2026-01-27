# IP CIDR Processor

A powerful and user-friendly GUI application for processing, analyzing, and managing IP addresses and CIDR notations.

## Features

### Core Functionality
- **Extract IP Addresses**: Parse IPv4 and IPv6 addresses from text files
- **CIDR Management**: Convert between IP ranges and CIDR notation
- **Optimization**: Combine and optimize CIDR blocks to reduce redundancy
- **Batch Processing**: Process multiple files simultaneously with multiprocessing
- **URL Processing**: Download and process IP lists from URLs
- **Custom Masks**: Apply custom formatting masks to output (e.g., Clash format)

### User Interface Features
- **Drag & Drop Support**: Simply drag files or folders into the application
- **Context Menus**: Right-click on file lists for quick actions
- **Keyboard Shortcuts**: Speed up your workflow with hotkeys
- **Status Bar**: Real-time information about files and processing status
- **Progress Tracking**: Visual progress bars for batch operations

## Installation

### Prerequisites
- Python 3.7 or higher

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Dependencies
- `requests` - HTTP library for URL processing
- `PyYAML` - Configuration file management
- `psutil` - Process and system monitoring
- `tkinterdnd2` - Drag and drop support (optional but recommended)
- `pyinstaller` - For creating standalone executables

## Usage

### Running the Application

```bash
python src/ip_cidr_processor.py
```

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+O` | Add files/URLs to current tab |
| `Ctrl+S` | Save results (on applicable tabs) |
| `Delete` | Remove selected items from list |
| `Ctrl+A` | Select all items in current list |
| `F5` | Process/Execute current tab action |
| `Ctrl+Q` | Quit application |

### Context Menu (Right-Click)

- **Add Files**: Open file browser
- **Remove Selected**: Delete selected items
- **Clear All**: Remove all items from list
- **Select All**: Select all items
- **Open File Location**: Open folder containing selected file

### Drag & Drop

Simply drag and drop:
- **Files**: `.txt`, `.log`, `.dat`, `.csv` files
- **Folders**: Automatically adds all supported files from folder
- **URLs**: Drag URLs into the URL Processing tab

## Tabs Overview

### 1. Process Files
Extract and format IP addresses from multiple files
- Supports IPv4 and IPv6
- Auto-converts single IPs to CIDR notation
- Apply custom output masks
- Sort results automatically

### 2. IP Ranges
Convert between IP ranges and CIDR notation
- **Range to CIDR**: Convert IP range (e.g., 192.168.1.1 - 192.168.1.255) to CIDR blocks
- **CIDR to Range**: Convert CIDR notation to IP range with detailed statistics
- Copy, save, or clear results

### 3. Optimize CIDR
Reduce and optimize CIDR blocks
- Combine adjacent networks
- Remove redundant entries
- Aggressive optimization mode
- Sort by network address

### 4. URL Processing
Download and process IP lists from URLs
- Automatic download from HTTP/HTTPS
- Extract IPs and ranges
- Optional optimization
- Multiple URL support

### 5. Batch Processing
Process multiple files in parallel
- Multi-threaded processing
- Real-time progress tracking
- Stop processing at any time
- Detailed statistics

### 6. Mask Settings
Create and manage custom output formats
- Define prefix, suffix, and separator
- Built-in templates (default, clash, custom)
- Import/Export mask configurations
- Set default mask

### 7. Configuration
Manage application settings
- Export configuration to file
- Import configuration from file
- Reset to default settings
- Backup your settings

## Output Masks

### Built-in Masks

**Default Mask**
```
192.168.1.0/24
10.0.0.0/8
```

**Clash Mask**
```
IP-CIDR,192.168.1.0/24,no-resolve
IP-CIDR,10.0.0.0/8,no-resolve
```

**Custom Mask**
```
[192.168.1.0/24], [10.0.0.0/8]
```

### Creating Custom Masks

1. Go to **Mask Settings** tab
2. Enter mask name
3. Define prefix (text before IP)
4. Define suffix (text after IP)
5. Set separator (use `\n` for newline)
6. Click **Add Mask**

## Examples

### Example 1: Extract IPs from Multiple Files

1. Open **Process Files** tab
2. Drag files into the list (or click **Add Files**)
3. Select IPv4/IPv6 options
4. Choose output mask
5. Click **Process Files**
6. Save results

### Example 2: Optimize CIDR List

1. Open **Optimize CIDR** tab
2. Add files containing CIDR notations
3. Enable **Aggressive Optimization** if needed
4. Click **Optimize CIDR**
5. Review optimized results

### Example 3: Batch Process Large Dataset

1. Open **Batch Processing** tab
2. Drag folder with multiple files
3. Set output folder
4. Enable optimization options
5. Click **Process All Files**
6. Monitor progress

## Configuration Files

### ip_cidr_config.yaml
Stores application settings and masks
- Automatically created on first run
- Can be exported and shared
- Edit manually if needed

## Troubleshooting

### Drag & Drop Not Working
- Install `tkinterdnd2`: `pip install tkinterdnd2`
- Restart the application
- If still not working, use **Add Files** button

### Processing Errors
- Check file encoding (UTF-8 recommended)
- Verify IP address format
- Review error messages in dialogs

### Performance Issues
- Reduce number of files in batch processing
- Disable aggressive optimization for large datasets
- Close other applications to free memory

## Building Standalone Executable

```bash
pyinstaller ip_cidr_processor.spec
```

Executable will be in `dist/` folder.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

See LICENSE file for details.

## Support

For issues and questions:
- Open an issue on GitHub
- Check existing issues for solutions

## Changelog

### Version 2.0.0
- ✨ Added drag and drop support
- ✨ Added keyboard shortcuts
- ✨ Added context menus
- ✨ Added status bar with file counts
- ✨ Added URL validation
- 🐛 Fixed duplicate method definition
- 🎨 Improved user interface
- 📝 Enhanced error messages

### Version 1.0.0
- Initial release
- Basic IP/CIDR processing
- Batch processing
- Mask management
