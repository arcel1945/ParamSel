# ParamSel - Parameter Selection and Vulnerability Scanner

**ParamSel** is a powerful tool designed to extract parameterized URLs from a given domain. It supports vulnerability scanning to detect potential SQL Injection (SQLi), Cross-Site Scripting (XSS), and other vulnerabilities in URL parameters. This tool is built with Python and integrates Google Dorking and the Wayback Machine to fetch URLs. The extracted URLs are saved into text files, and the tool supports multithreading for faster processing.

## Features

- **-V Command**: Identify vulnerability-prone parameters (SQLi, XSS, etc.).
- **Multithreading**: Speed up the process with concurrent URL extraction.
- **Google Dorking**: Leverage Google search to find indexed URLs.
- **Wayback Machine Integration**: Fetch historical URLs using the Wayback Machine.
- **Auto-save Output**: Results are automatically saved in `results/{domain}.txt`.
- **Supports Placeholder for Parameters**: Use a placeholder (default `FUZZ`) for parameter values to further analyze them.

## Installation

### Step 1: Clone the repository

```bash
git clone https://github.com/arcel1945/ParamSel.git
cd ParamSel
```

### Step 2: Install dependencies
```bash
pip install -r requirements.txt
```
### Step 3: Running the tool

To run the tool and fetch parameterized URLs, use the following command:
```bash
python paramsel.py -d <domain>
```
For vulnerability scanning, add the -V flag:
```bash
python paramsel.py -d <domain> -V
```
You can also specify a custom placeholder for URL parameter values:
```bash
python paramsel.py -d <domain> -V -P FUZZ
```
