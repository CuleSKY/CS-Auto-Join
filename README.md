# CS A2S Auto Join Tool

A simple GUI-based tool for automatically joining CS community servers using A2S queries.  
Supports **CS2** and **CS:S**.

This project uses **only the Python standard library**.

---

## Requirements

### Python

- Python **3.10 or newer** (recommended: 3.11 / 3.12)

Check your version:

```bash
python --version ```
System
Steam client installed

Operating system must support the steam:// protocol

One of the following games must be installed:

CS2 (AppID 730)

CS:S (AppID 240)

Linux Only
Tkinter must be installed:

sudo apt install python3-tk
Run from Source
Clone the repository:

git clone https://github.com/yourname/yourrepo.git
cd yourrepo
Run the program:

python autojoin.py
No additional Python packages are required.

Build (Windows Example)
The program can be packaged into a single executable using PyInstaller.

Install PyInstaller
pip install pyinstaller
Build Executable
pyinstaller --noconsole --onefile --name CSJoinTool autojoin.py
Output
dist/CSJoinTool.exe
Notes
The program stops automatically after triggering the Steam connection.

Input fields are not cleared automatically.

The program does not attempt to detect whether the user successfully joined the server.
