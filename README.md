# FTProxy - An FTP Transparent Proxy Firewall

## Prerequisites

### System requirements

- Linux - Kali GNU/Linux Rolling (Debian 4.12.6-1 kali6)
- `iptables`
- CPython 3.6

### Python dependencies

- `PyPCAPKit` (version 0.12.11)
- `wxPython` (version 4.0.3)

## Project structure

```
FTProxy
├── Pipfile                             # pipenv description file
├── README.md
├── bootstrap.sh                        # use this file to set up environment
├── ftcap                               # user-defined record file format
│   ├── README.rst
│   ├── __init__.py
│   ├── cst                             # constructor for ftcap files
│   │   ├── frame.py
│   │   └── header.py
│   ├── ext                             # extractor for ftcap files
│   │   ├── frame.py
│   │   └── header.py
│   ├── reader.py                       # reader API
│   └── writer.py                       # writer API
├── iptables_reset.sh                   # reset iptables settings
├── iptables_setup.sh                   # set up iptables settings
├── mainFrame                           # GUI
│   ├── __init__.py
├── mainGUI.py                          # entry point for GUI
├── policies.json                       # firewall policies
├── policyManager
│   └── __init__.py                     # policy utilities
└── tc-proxy.py                         # entry point for FTProxy
```
