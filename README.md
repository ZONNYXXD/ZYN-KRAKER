README.md

# ZYN-KRAKER

<img width="1129" height="833" alt="Screenshot From 2025-08-02 23-07-54" src="https://github.com/user-attachments/assets/52c32e30-808d-4d35-a411-1026d6e124d0" />


**ZYN-KRAKER** is a **brutal advanced password cracker** by **ZYNCRIPTA** (Developer: V4MP1R3).  
It supports multiple attack modes, colorful UI, resume checkpoints, and multi-processing for high-speed cracking.  

> ⚠️ **Disclaimer:** Use only for authorized penetration testing and ethical purposes.

---

## Features

- 🔹 **Dictionary Attack** – Crack hashes with wordlists.  
- 🔹 **Hybrid Attack** – Combines dictionary + mutations (leet speak, suffixes, numeric combos).  
- 🔹 **Brute Force Attack** – Multi-core password cracking with progress bars.  
- 🔹 **ZIP File Attack** – Crack password-protected ZIP archives.  
- 🔹 **Checkpoint Resume** – Continue long sessions after interruption.  
- 🔹 **Leet Variations** – Generates smart variants like `p@ssw0rd123`.  

---

## Installation

1. Clone or download the project.
2. Install Python **3.8+**.
3. Install required dependencies:

```bash
pip install -r requirements.txt

Usage

Run the script with CLI mode or interactive mode.
1️⃣ Dictionary Attack

python ZYN-KRAKER.py -H <HASH> -t md5 -w wordlists/rockyou.txt

2️⃣ Hybrid Attack

python ZYN-KRAKER.py -H <HASH> -t sha1 -w wordlists/common.txt --hybrid

3️⃣ Brute Force Attack

python ZYN-KRAKER.py -H <HASH> -t sha256 -m 6 -T 4

    -m → Max length (default 6)

    -T → Number of CPU processes

4️⃣ ZIP File Cracking

With Dictionary

python ZYN-KRAKER.py -z secret.zip -w wordlists/rockyou.txt

With Brute Force

python ZYN-KRAKER.py -z secret.zip -m 4

5️⃣ Resume Previous Session

python ZYN-KRAKER.py -H <HASH> -t md5 -w wordlists/rockyou.txt --resume

Optional Flags

    --output FILE → Save cracked results to a file.

    -c "abc123" → Custom charset for brute force.

    -v / -vv → Increase verbosity.

Example Output

[+] Password found!
[+] Password: password123
[+] Hash: cbfdac6008f9cab4083784cbd1874f76618d2a97
[+] Attempts: 3,450
[+] Time elapsed: 2.57 seconds
[+] Speed: 1,342 hashes/s

Project Structure

ZYN-KRAKER/
│
├─ ZYN-KRAKER.py         # Main script
├─ README.md             # Documentation
├─ requirements.txt      # Python dependencies
├─ wordlists/            # Store your wordlists here
│    └─ rockyou.txt
└─ cracked_results.txt   # Optional output file

Legal Disclaimer

This tool is intended for educational and ethical penetration testing purposes only.
The developer and contributors are not responsible for any misuse.

Happy Cracking! 🔐
Author: ZYNCRIPTA (V4MP1R3)


---

### **`requirements.txt`**
```txt
colorama
bcrypt
tqdm
