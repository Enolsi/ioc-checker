# IOC Checker

A Python-based Indicator of Compromise (IOC) checker designed for basic SOC and Blue Team investigations.

The tool identifies IP addresses, domains, and file hashes and queries the VirusTotal API to retrieve threat intelligence analysis results.

## Features

- Detects IPv4 and IPv6 addresses
- Detects domain names
- Detects MD5, SHA-1, and SHA-256 hashes
- Queries the VirusTotal API
- Displays malicious, suspicious, harmless, and undetected results
- Provides a simple CLEAN, SUSPICIOUS, or MALICIOUS verdict
- Handles connection errors
- Handles common API errors
- Loads the VirusTotal API key from an environment variable

## Requirements

- Python 3
- VirusTotal API key
- Python packages listed in `requirements.txt`

## Installation

Clone the repository and enter the project directory:

```bash
git clone <repository-url>
cd ioc-checker
