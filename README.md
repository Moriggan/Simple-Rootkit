# Python Rootkit + RAT for Windows 64-bit

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.6%20%7C%203.7%20%7C%203.8-blue.svg)](https://www.python.org/)

A Python-based rootkit and Remote Access Trojan (RAT) designed for educational purposes on Windows 64-bit systems. This project demonstrates advanced techniques in persistence, obfuscation, and remote command execution.

## Features

- **Persistence**: Writes itself to the `System32` directory and adds a registry entry for persistence.
- **Obfuscation**: Uses XOR encoding to obfuscate the script.
- **Remote Access**: Sets up a command server to execute remote commands.
- **Stealth**: Sets hidden and system attributes to avoid detection.

## Disclaimer

This project is for educational purposes only. Unauthorized use of this software on systems you do not own or have explicit permission to test is illegal and unethical. Use this code responsibly and ethically.

## Installation

To install and run the project, follow these steps:

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/rootkit-rat.git
   cd rootkit-rat
