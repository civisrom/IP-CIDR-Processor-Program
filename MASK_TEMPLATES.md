# Mask Templates Guide

## Overview

IP CIDR Processor now includes 30+ predefined mask templates organized by category, making it easy to format IP addresses for various applications and use cases.

## How to Use Masks

1. Navigate to the **Mask Settings** tab
2. Browse masks by category using the filter dropdown
3. Click the **👁 Preview** button to see how a mask formats IPs
4. Click **⎘ Duplicate** to create a custom version
5. Click **✎ Edit** to modify a mask
6. Select a mask in any processing tab to apply it

## Mask Categories

### 📁 Basic
General-purpose formats for simple IP lists

| Name | Description | Example Output |
|------|-------------|----------------|
| **default** | Plain IP list, one per line | `192.168.1.0/24` |
| **custom** | Bracket-wrapped, comma separated | `[192.168.1.0/24], [10.0.0.0/8]` |
| **space-separated** | Space separated list | `192.168.1.0/24 10.0.0.0/8` |

### 📁 Clash
Formats for Clash proxy configuration

| Name | Description | Example Output |
|------|-------------|----------------|
| **clash** | Clash IP-CIDR format | `IP-CIDR,192.168.1.0/24,no-resolve` |
| **clash-resolve** | Clash IP-CIDR with resolve | `IP-CIDR,192.168.1.0/24` |
| **clash-ipv6** | Clash IPv6 format | `IP-CIDR6,2001:db8::/32,no-resolve` |

### 📁 Surge
Formats for Surge proxy configuration

| Name | Description | Example Output |
|------|-------------|----------------|
| **surge** | Surge IP-CIDR format | `IP-CIDR,192.168.1.0/24` |
| **surge-ipv6** | Surge IPv6 format | `IP-CIDR6,2001:db8::/32` |

### 📁 Quantumult
Formats for Quantumult X proxy configuration

| Name | Description | Example Output |
|------|-------------|----------------|
| **quantumult-x** | Quantumult X reject format | `IP-CIDR,192.168.1.0/24,REJECT` |
| **quantumult-x-direct** | Quantumult X direct format | `IP-CIDR,192.168.1.0/24,DIRECT` |

### 📁 Shadowrocket
Formats for Shadowrocket proxy configuration

| Name | Description | Example Output |
|------|-------------|----------------|
| **shadowrocket** | Shadowrocket format | `IP-CIDR,192.168.1.0/24` |

### 📁 Programming
Formats for programming languages and data structures

| Name | Description | Example Output |
|------|-------------|----------------|
| **json-array** | JSON array format | `  "192.168.1.0/24",\n  "10.0.0.0/8"` |
| **python-list** | Python list format | `    "192.168.1.0/24",\n    "10.0.0.0/8"` |
| **csv** | CSV format | `192.168.1.0/24,10.0.0.0/8` |
| **yaml-list** | YAML list format | `  - 192.168.1.0/24\n  - 10.0.0.0/8` |

**Full Example - JSON Array:**
```json
[
  "192.168.1.0/24",
  "10.0.0.0/8",
  "172.16.0.0/12"
]
```

**Full Example - Python List:**
```python
ips = [
    "192.168.1.0/24",
    "10.0.0.0/8",
    "172.16.0.0/12"
]
```

### 📁 Firewall
Formats for firewall rules (iptables, UFW)

| Name | Description | Example Output |
|------|-------------|----------------|
| **iptables-drop** | iptables DROP rule | `iptables -A INPUT -s 192.168.1.0/24 -j DROP` |
| **iptables-accept** | iptables ACCEPT rule | `iptables -A INPUT -s 192.168.1.0/24 -j ACCEPT` |
| **ufw-deny** | UFW deny rule | `ufw deny from 192.168.1.0/24` |
| **ufw-allow** | UFW allow rule | `ufw allow from 192.168.1.0/24` |

**Example - Complete iptables script:**
```bash
#!/bin/bash
# Block malicious IPs
iptables -A INPUT -s 192.168.1.0/24 -j DROP
iptables -A INPUT -s 10.0.0.0/8 -j DROP
iptables -A INPUT -s 172.16.0.0/12 -j DROP
```

### 📁 Router
Formats for router configurations

| Name | Description | Example Output |
|------|-------------|----------------|
| **mikrotik** | MikroTik address list | `/ip firewall address-list add list=blocked address=192.168.1.0/24` |
| **cisco-acl** | Cisco ACL deny | `deny ip 192.168.1.0/24 any` |

**Example - MikroTik Script:**
```routeros
# Add IPs to blocked list
/ip firewall address-list add list=blocked address=192.168.1.0/24
/ip firewall address-list add list=blocked address=10.0.0.0/8
/ip firewall address-list add list=blocked address=172.16.0.0/12
```

### 📁 DNS
Formats for DNS and ad-blocking

| Name | Description | Example Output |
|------|-------------|----------------|
| **hosts** | Hosts file format | `0.0.0.0 192.168.1.0` |
| **dnsmasq** | Dnsmasq format | `address=/192.168.1.0/0.0.0.0` |

**Note:** For hosts file format, you typically use domain names, not IP addresses. This is provided for special use cases.

### 📁 Other
Miscellaneous useful formats

| Name | Description | Example Output |
|------|-------------|----------------|
| **quoted** | Quoted with commas | `"192.168.1.0/24",\n"10.0.0.0/8"` |
| **single-quoted** | Single quoted with commas | `'192.168.1.0/24',\n'10.0.0.0/8'` |
| **html-list** | HTML list items | `<li>192.168.1.0/24</li>` |
| **markdown-list** | Markdown list format | `- 192.168.1.0/24` |

## Creating Custom Masks

### Step 1: Open Create New Mask Section
Navigate to **Mask Settings** tab and scroll to the bottom

### Step 2: Fill in Mask Details

| Field | Description | Example |
|-------|-------------|---------|
| **Name** | Unique identifier for the mask | `my-custom-mask` |
| **Category** | Group for organization | `Custom` or select existing |
| **Prefix** | Text before each IP | `ALLOW ` |
| **Suffix** | Text after each IP | ` FROM_LAN` |
| **Separator** | Text between IPs (use `\n` for newline, `\t` for tab) | `\n` |
| **Description** | Help text explaining the mask | `Custom firewall allow rule` |

### Step 3: Preview Before Saving
Click the **Preview** button to see how your mask will format sample IPs

### Step 4: Save
Click **Add Mask** to save your custom mask

## Duplicating Existing Masks

1. Find a mask similar to what you need
2. Click the **⎘ Duplicate** button
3. Enter a new name
4. Edit the duplicated mask as needed

## Advanced Features

### Filtering by Category
Use the category dropdown to show only masks in a specific category, making it easier to find what you need.

### Preview Function
Every mask can be previewed with sample IPs before use:
- Shows formatted output with 3 sample IPs
- Displays mask details (category, description)
- Copy preview to clipboard
- Quick edit access

### Batch Updating
When you edit a mask, all processing tabs automatically update to reflect the changes.

## Special Characters

| Character | Usage | Description |
|-----------|-------|-------------|
| `\n` | In separator field | Newline (each IP on new line) |
| `\t` | In separator field | Tab character |
| `\` | Escape character | Use `\\` for literal backslash |

## Tips and Best Practices

1. **Test with Preview**: Always preview your mask before using it on large datasets
2. **Use Descriptive Names**: Make mask names clear and searchable
3. **Category Organization**: Keep custom masks in the "Custom" category for easy management
4. **Duplicate Before Edit**: Duplicate built-in masks instead of editing them directly
5. **Add Descriptions**: Future you will thank present you for good descriptions

## Use Case Examples

### Example 1: Generating Firewall Rules
**Scenario**: Block a list of malicious IPs on a Linux server

1. Select **iptables-drop** mask
2. Process your IP list
3. Save output
4. Copy rules to your firewall script

### Example 2: Creating Proxy Configuration
**Scenario**: Set up Clash proxy rules for Chinese IPs

1. Select **clash** mask
2. Process Chinese IP list
3. Copy output to your Clash configuration
4. Direct traffic according to rules

### Example 3: Programming Integration
**Scenario**: Import IPs into a Python application

1. Select **python-list** mask
2. Process IP list
3. Copy formatted output directly into your Python code
4. Use the list in your application

### Example 4: Router Configuration
**Scenario**: Block IPs on MikroTik router

1. Select **mikrotik** mask
2. Process blocklist
3. Copy commands to router terminal
4. IPs are added to blocked list

## FAQ

**Q: Can I delete built-in masks?**
A: You can delete all masks except the "default" mask. However, it's recommended to keep built-in masks and create custom ones instead.

**Q: What happens if I edit a built-in mask?**
A: The changes are saved to your configuration. You can reset to defaults via the Configuration tab.

**Q: Can I share masks with others?**
A: Yes! Use the Configuration tab to export your settings, including all custom masks.

**Q: How many custom masks can I create?**
A: There's no practical limit. Create as many as you need!

**Q: Can I use multiple separators?**
A: Yes! You can combine characters: `\n\n` for double newlines, `, \n` for comma and newline, etc.

## Troubleshooting

### Mask Not Appearing in Dropdown
- Refresh the mask list
- Check if the mask was saved successfully
- Verify the mask name is unique

### Wrong Output Format
- Use Preview to check the mask
- Verify prefix/suffix spacing
- Check separator escape sequences (`\n`, `\t`)

### Special Characters Not Working
- Make sure to use backslash: `\n` not just `n`
- Test with Preview before processing large files
- Some terminals may display escape sequences differently

## Contributing New Masks

Have a useful mask template? Consider sharing it!
- Fork the repository
- Add your mask to the default_config
- Submit a pull request with description and use case

## Version History

### v2.0 - Enhanced Mask System
- Added 30+ predefined masks
- Category-based organization
- Preview functionality
- Duplicate mask feature
- Filter by category
- Enhanced UI with descriptions
- Support for custom categories

---

For more information, see the main [README.md](README.md)
