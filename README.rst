===========================================
FTProxy - An FTP Transparent Proxy Firewall
===========================================

-------------
Prerequisites
-------------

System requirements
~~~~~~~~~~~~~~~~~~~

-  Linux - Kali GNU/Linux Rolling (Debian 4.12.6-1 kali6)
-  ``iptables``
-  CPython 3.6

Python dependencies
~~~~~~~~~~~~~~~~~~~

-  ``PyPCAPKit`` (version 0.12.11)
-  ``wxPython`` (version 4.0.3)

-----
Usage
-----

1. Before you start, use ``bootstrap.sh`` to set up the environment.

   1. To set up ``iptables``, use ``iptables_setup.sh``.
   2. To reset ``iptables``, use ``iptables_reset.sh``.

2. To start the FTProxy, run ``python tc-proxy.py``.
3. To enter GUI of FTProxy, run ``python mainFrame.py``.

-----------------
Project structure
-----------------

.. code:: text

   FTProxy
   ├── Pipfile                             # pipenv description file
   ├── README.rst                          # this file
   ├── bootstrap.sh                        # use this file to set up environment
   ├── ftcap                               # user-defined record file format
   │   ├── README.rst                      # specification for ftcap & API documentation
   │   ├── __init__.py                     # module init file
   │   ├── cst                             # constructor for ftcap files
   │   │   ├── frame.py                    # Frame constructor
   │   │   └── header.py                   # Global Header constructor
   │   ├── ext                             # extractor for ftcap files
   │   │   ├── frame.py                    # Frame extractor
   │   │   └── header.py                   # Global Header extractor
   │   ├── reader.py                       # reader API
   │   └── writer.py                       # writer API
   ├── iptables_reset.sh                   # reset iptables settings
   ├── iptables_setup.sh                   # set up iptables settings
   ├── mainFrame                           # GUI module
   │   ├── __init__.py                     # module init file
   ├── mainGUI.py                          # entry point for GUI
   ├── policies.json                       # firewall policies
   ├── policyManager                       # policy module
   │   └── __init__.py                     # module init file
   └── tc-proxy.py                         # entry point for FTProxy
