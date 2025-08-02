import itertools
import time
import hashlib
import bcrypt
import os
import sys
import multiprocessing
import zipfile
import json
from datetime import datetime
from colorama import Fore, Style, init
from tqdm import tqdm

# Initialize colorama
init(autoreset=True)

CHECKPOINT_FILE = "zyncr4ker_checkpoint.json"
VERBOSITY = 1  # 0=quiet, 1=normal, 2=debug

def log(msg, level=1):
    if VERBOSITY >= level:
        print(msg)

def safe_path(path):
    # Prevent path traversal and absolute paths
    if not path or not isinstance(path, str):
        return None
    path = os.path.normpath(path)
    if os.path.isabs(path) or ".." in path.split(os.sep):
        return None
    return path

def set_terminal_size(columns=120, lines=40):
    try:
        if os.name == 'nt':
            os.system(f'mode con: cols={columns} lines={lines}')
        else:
            sys.stdout.write(f"\x1b[8;{lines};{columns}t")
    except:
        pass

set_terminal_size(140, 40)

def print_banner():
    print(Fore.GREEN + r"""
 ███████████ █████ █████ ██████   █████               █████   ████ ███████████     █████████   █████   ████ ██████████ ███████████  
░█░░░░░░███ ░░███ ░░███ ░░██████ ░░███               ░░███   ███░ ░░███░░░░░███   ███░░░░░███ ░░███   ███░ ░░███░░░░░█░░███░░░░░███ 
░     ███░   ░░███ ███   ░███░███ ░███                ░███  ███    ░███    ░███  ░███    ░███  ░███  ███    ░███  █ ░  ░███    ░███ 
     ███      ░░█████    ░███░░███░███  ██████████    ░███████     ░██████████   ░███████████  ░███████     ░██████    ░██████████  
    ███        ░░███     ░███ ░░██████ ░░░░░░░░░░     ░███░░███    ░███░░░░░███  ░███░░░░░███  ░███░░███    ░███░░█    ░███░░░░░███ 
  ████     █    ░███     ░███  ░░█████                ░███ ░░███   ░███    ░███  ░███    ░███  ░███ ░░███   ░███ ░   █ ░███    ░███ 
 ███████████    █████    █████  ░░█████               █████ ░░████ █████   █████ █████   █████ █████ ░░████ ██████████ █████   █████
░░░░░░░░░░░    ░░░░░    ░░░░░    ░░░░░               ░░░░░   ░░░░ ░░░░░   ░░░░░ ░░░░░   ░░░░░ ░░░░░   ░░░░ ░░░░░░░░░░ ░░░░░   ░░░░░ 
""" + Style.RESET_ALL)
    print(Fore.CYAN + "=" * 70)
    print(Fore.GREEN + "||" + Fore.WHITE + "  ZYN-CR4K3R - BY ZYNCRIPTA Brutal Advanced Password Cracker  " + Fore.GREEN + "||")
    print(Fore.GREEN + "||" + Fore.WHITE + "  DEVELOPER - V4MP1R3  " + Fore.GREEN + "||")
    print(Fore.CYAN + "=" * 70)
    print(Fore.MAGENTA + "Use Ethically Only - Authorized Penetration Testing Tool\n" + Style.RESET_ALL)

def get_hash_function(hash_type):
    hash_type = hash_type.lower()
    if hash_type == 'md5':
        return hashlib.md5
    elif hash_type == 'sha1':
        return hashlib.sha1
    elif hash_type == 'sha256':
        return hashlib.sha256
    elif hash_type == 'sha512':
        return hashlib.sha512
    elif hash_type == 'bcrypt':
        return None
    else:
        log(Fore.RED + f"[-] Unsupported hash type: {hash_type}", 0)
        sys.exit(1)

def load_wordlist(path):
    safe = safe_path(path)
    if not safe or not os.path.isfile(safe):
        log(Fore.RED + f"[-] Wordlist file not found or invalid: {path}", 0)
        return None
    try:
        with open(safe, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        log(Fore.RED + f"[-] Error loading wordlist: {e}", 0)
        return None

LEET_MAP = {
    'a': ['4', '@'],
    'e': ['3'],
    'i': ['1', '!'],
    'o': ['0'],
    's': ['5', '$'],
    't': ['7']
}

def leetspeak_variants(word):
    variants = set()
    def helper(w, idx):
        if idx == len(w):
            variants.add(w)
            return
        c = w[idx]
        helper(w, idx+1)
        if c.lower() in LEET_MAP:
            for sub in LEET_MAP[c.lower()]:
                helper(w[:idx] + sub + w[idx+1:], idx+1)
    helper(word, 0)
    return variants

def save_checkpoint(data):
    try:
        with open(CHECKPOINT_FILE, 'w') as f:
            json.dump(data, f)
    except Exception as e:
        log(Fore.RED + f"[-] Failed to save checkpoint: {e}", 0)

def load_checkpoint():
    if os.path.exists(CHECKPOINT_FILE):
        try:
            with open(CHECKPOINT_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            log(Fore.RED + f"[-] Failed to load checkpoint: {e}", 0)
    return {}

def estimate_cracking_time(charset_len, max_length, hashes_per_sec=1000000):
    total = sum(charset_len ** i for i in range(1, max_length + 1))
    seconds = total / hashes_per_sec
    return seconds

COMMON_SUFFIXES = ['123', '!', '2024', '2025', '@', '1', '12', '1234', 'password', 'admin']

def dictionary_attack(target_hash, wordlist, hash_type='md5', checkpoint=None, verbose=True):
    hash_func = get_hash_function(hash_type)
    start_time = time.time()
    attempts = 0
    checkpoint = checkpoint or {}
    start_index = checkpoint.get('dict_index', 0)

    if verbose:
        log(Fore.BLUE + f"\n[+] Starting dictionary attack (hash: {target_hash}, type: {hash_type})", 1)
        log(Fore.BLUE + f"[+] Wordlist size: {len(wordlist):,}", 1)
        est_time = estimate_cracking_time(95, 8)
        log(Fore.CYAN + f"[i] Estimated cracking time for brute force of length 8: {est_time/3600:.2f} hours", 2)
        log(Fore.MAGENTA + "-" * 60, 1)

    for idx in range(start_index, len(wordlist)):
        password = wordlist[idx]
        attempts += 1

        candidates = set([password])
        candidates.update(leetspeak_variants(password))
        candidates.update([password.lower(), password.upper(), password.capitalize()])
        for suffix in COMMON_SUFFIXES:
            candidates.add(password + suffix)
            candidates.add(password.capitalize() + suffix)

        for candidate in candidates:
            if hash_type == 'bcrypt':
                if bcrypt.checkpw(candidate.encode(), target_hash.encode()):
                    elapsed = time.time() - start_time
                    print_success(candidate, target_hash, attempts, elapsed)
                    return candidate
            else:
                if hash_func(candidate.encode()).hexdigest() == target_hash:
                    elapsed = time.time() - start_time
                    print_success(candidate, target_hash, attempts, elapsed)
                    return candidate

        if attempts % 1000 == 0:
            save_checkpoint({'dict_index': idx + 1})

        if verbose and attempts % 1000 == 0:
            elapsed = time.time() - start_time
            speed = attempts / elapsed if elapsed > 0 else 0
            log(Fore.BLUE + f"[*] Attempts: {attempts:,} | Speed: {speed:,.0f} hashes/s | Elapsed: {elapsed:.2f}s", 2)

    log(Fore.RED + "\n[-] Password not found in wordlist", 0)
    return None

def hybrid_attack(target_hash, wordlist, hash_type='md5', max_mutate_length=2, charset=None, checkpoint=None, verbose=True):
    hash_func = get_hash_function(hash_type)
    charset = charset or '0123456789'
    start_time = time.time()
    attempts = 0
    checkpoint = checkpoint or {}
    start_index = checkpoint.get('hybrid_index', 0)

    for idx in range(start_index, len(wordlist)):
        base = wordlist[idx]
        candidates = set([base])
        candidates.update(leetspeak_variants(base))
        candidates.update([base.lower(), base.upper(), base.capitalize()])
        for suffix in COMMON_SUFFIXES:
            candidates.add(base + suffix)
            candidates.add(base.capitalize() + suffix)
        for length in range(1, max_mutate_length + 1):
            for suf in itertools.product(charset, repeat=length):
                candidates.add(base + ''.join(suf))

        for candidate in candidates:
            attempts += 1
            if hash_type == 'bcrypt':
                if bcrypt.checkpw(candidate.encode(), target_hash.encode()):
                    elapsed = time.time() - start_time
                    print_success(candidate, target_hash, attempts, elapsed)
                    return candidate
            else:
                if hash_func(candidate.encode()).hexdigest() == target_hash:
                    elapsed = time.time() - start_time
                    print_success(candidate, target_hash, attempts, elapsed)
                    return candidate

        if attempts % 1000 == 0:
            save_checkpoint({'hybrid_index': idx + 1})

        if verbose and attempts % 1000 == 0:
            elapsed = time.time() - start_time
            speed = attempts / elapsed if elapsed > 0 else 0
            log(Fore.BLUE + f"[*] Hybrid Attempts: {attempts:,} | Speed: {speed:,.0f} hashes/s | Elapsed: {elapsed:.2f}s", 2)

    log(Fore.RED + "\n[-] Password not found in hybrid attack", 0)
    return None

def brute_force_worker_mp(args):
    target_hash, charset, length, hash_type, start, end = args
    hash_func = get_hash_function(hash_type)
    for idx in range(start, end):
        candidate = index_to_password(idx, length, charset)
        if hash_type == 'bcrypt':
            if bcrypt.checkpw(candidate.encode(), target_hash.encode()):
                return candidate
        else:
            if hash_func(candidate.encode()).hexdigest() == target_hash:
                return candidate
    return None

def index_to_password(index, length, charset):
    base = len(charset)
    chars = []
    for _ in range(length):
        chars.append(charset[index % base])
        index //= base
    return ''.join(reversed(chars))

def brute_force_cracker(target_hash, max_length=6, charset=None, hash_type='md5', processes=4, verbose=True):
    charset = charset or 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()'
    total_attempts = sum(len(charset) ** i for i in range(1, max_length + 1))
    start_time = time.time()
    found = None

    if verbose:
        log(Fore.BLUE + f"\n[+] Starting multiprocessing brute force (hash: {target_hash}, type: {hash_type})", 1)
        log(Fore.BLUE + f"[+] Max length: {max_length}", 1)
        log(Fore.BLUE + f"[+] Charset length: {len(charset)}", 1)
        log(Fore.MAGENTA + "-" * 60, 1)

    with multiprocessing.Pool(processes=processes) as pool, tqdm(total=total_attempts, desc="Brute Force", unit="pwds", disable=VERBOSITY < 1) as pbar:
        tasks = []
        for length in range(1, max_length + 1):
            n = len(charset) ** length
            chunk = max(10000, n // (processes * 10))
            for start in range(0, n, chunk):
                end = min(start + chunk, n)
                tasks.append((target_hash, charset, length, hash_type, start, end))
        results = pool.imap_unordered(brute_force_worker_mp, tasks)
        checked = 0
        for result in results:
            checked += 1
            pbar.update(1)
            if result:
                found = result
                pool.terminate()
                break

    elapsed = time.time() - start_time
    if found:
        print_success(found, target_hash, checked, elapsed)
        return found
    else:
        log(Fore.RED + "\n[-] Password not found with given parameters", 0)
        return None

def print_success(password, target_hash, attempts, elapsed):
    print("\n" + Fore.GREEN + "-" * 60)
    print(Fore.GREEN + "[+] Password found!")
    print(Fore.GREEN + f"[+] Password: {Fore.YELLOW}{password}")
    print(Fore.GREEN + f"[+] Hash: {Fore.CYAN}{target_hash}")
    print(Fore.GREEN + f"[+] Attempts: {Fore.MAGENTA}{attempts:,}")
    print(Fore.GREEN + f"[+] Time elapsed: {Fore.RED}{elapsed:.2f} seconds")
    print(Fore.GREEN + f"[+] Speed: {Fore.CYAN}{attempts/elapsed:,.0f} hashes/s")
    print(Fore.GREEN + f"[+] End time: {Fore.CYAN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(Fore.GREEN + "-" * 60 + Style.RESET_ALL)

def crack_zip_file(zip_path, wordlist=None, max_length=6, charset=None, threads=4):
    safe = safe_path(zip_path)
    if not safe or not os.path.isfile(safe):
        log(Fore.RED + f"[-] ZIP file not found or invalid: {zip_path}", 0)
        return None

    try:
        with zipfile.ZipFile(safe) as zip_file:
            test_file = zip_file.namelist()[0]

            if wordlist:
                passwords = load_wordlist(wordlist)
                if not passwords:
                    log(Fore.RED + "[-] Wordlist could not be loaded. Check the path and try again.", 0)
                    return None
                log(Fore.BLUE + "[+] Starting dictionary attack on ZIP file", 1)
                for password in passwords:
                    try:
                        zip_file.extract(test_file, pwd=password.encode())
                        log(Fore.GREEN + f"\n[+] Password found: {password}", 1)
                        return password
                    except (RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile):
                        continue
                log(Fore.RED + "[-] Password not found in wordlist for ZIP file", 0)
                return None
            else:
                log(Fore.BLUE + "[+] Starting brute force attack on ZIP file", 1)
                charset = charset or 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
                for length in range(1, max_length + 1):
                    for candidate in itertools.product(charset, repeat=length):
                        candidate = ''.join(candidate)
                        try:
                            zip_file.extract(test_file, pwd=candidate.encode())
                            log(Fore.GREEN + f"\n[+] Password found: {candidate}", 1)
                            return candidate
                        except (RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile):
                            continue
                log(Fore.RED + "[-] Password not found with brute force for ZIP file", 0)
                return None
    except Exception as e:
        log(Fore.RED + f"[-] Error processing ZIP file: {e}", 0)
        return None

def write_result_to_file(password, hash_value, attack_type, elapsed, attempts, output_file="cracked_results.txt"):
    safe = safe_path(output_file)
    if not safe:
        log(Fore.RED + f"[!] Unsafe or invalid output file path: {output_file}", 0)
        return
    try:
        with open(safe, "a") as f:
            f.write(f"Attack: {attack_type}\n")
            f.write(f"Hash: {hash_value}\n")
            f.write(f"Password: {password}\n")
            f.write(f"Attempts: {attempts}\n")
            f.write(f"Elapsed: {elapsed:.2f} seconds\n")
            f.write(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*40 + "\n")
        log(Fore.GREEN + f"[+] Results written to {output_file}", 1)
    except Exception as e:
        log(Fore.RED + f"[!] Could not write results to file: {e}", 0)

def interactive_menu():
    print(Fore.CYAN + "\n[ INTERACTIVE MODE ]")
    print("1. Dictionary Attack")
    print("2. Hybrid Attack (Dictionary + Mutations)")
    print("3. Brute Force Attack")
    print("4. Crack ZIP File")
    print("0. Exit")
    choice = input("Select attack type [1-4]: ").strip()
    return choice

def main():
    import argparse

    print_banner()

    parser = argparse.ArgumentParser(description="ZYN-CR4K3R - Brutal Advanced Password Cracker")
    parser.add_argument("-H", "--hash", help="Target hash to crack")
    parser.add_argument("-t", "--hash-type", default="md5",
                        choices=["md5", "sha1", "sha256", "sha512", "bcrypt"],
                        help="Hash algorithm (default: md5)")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist file for dictionary attack")
    parser.add_argument("-m", "--max-length", type=int, default=6,
                        help="Maximum password length for brute force (default: 6)")
    parser.add_argument("-c", "--charset",
                        help="Custom character set for brute force (default: a-zA-Z0-9 and symbols)")
    parser.add_argument("-T", "--threads", type=int, default=4,
                        help="Number of processes to use (default: 4)")
    parser.add_argument("-z", "--zip", help="Path to password-protected ZIP file to crack")
    parser.add_argument("--resume", action="store_true", help="Resume from last checkpoint if available")
    parser.add_argument("--hybrid", action="store_true", help="Enable hybrid attack (dictionary + mutations)")
    parser.add_argument("--output", help="Write cracked password and stats to this file")
    parser.add_argument("-v", "--verbose", action="count", default=1,
                        help="Increase output verbosity (use -vv for debug)")

    args, unknown = parser.parse_known_args()
    global VERBOSITY
    VERBOSITY = args.verbose
    charset = args.charset or 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()'

    # If no CLI args, enter interactive mode
    if len(sys.argv) == 1:
        while True:
            choice = interactive_menu()
            if choice == "1":
                args.hash = input("Enter hash: ").strip()
                args.hash_type = input("Enter hash type [md5/sha1/sha256/sha512/bcrypt]: ").strip() or "md5"
                args.wordlist = input("Enter path to wordlist: ").strip()
                args.output = input("Output file (leave blank for none): ").strip() or None
                attack_type = "Dictionary"
                break
            elif choice == "2":
                args.hash = input("Enter hash: ").strip()
                args.hash_type = input("Enter hash type [md5/sha1/sha256/sha512/bcrypt]: ").strip() or "md5"
                args.wordlist = input("Enter path to wordlist: ").strip()
                args.output = input("Output file (leave blank for none): ").strip() or None
                attack_type = "Hybrid"
                args.hybrid = True
                break
            elif choice == "3":
                args.hash = input("Enter hash: ").strip()
                args.hash_type = input("Enter hash type [md5/sha1/sha256/sha512/bcrypt]: ").strip() or "md5"
                args.max_length = int(input("Max brute force length [default 6]: ").strip() or "6")
                args.output = input("Output file (leave blank for none): ").strip() or None
                attack_type = "Brute Force"
                break
            elif choice == "4":
                args.zip = input("Enter path to ZIP file: ").strip()
                args.wordlist = input("Enter path to wordlist (leave blank for brute force): ").strip() or None
                args.max_length = int(input("Max brute force length [default 6]: ").strip() or "6")
                args.output = input("Output file (leave blank for none): ").strip() or None
                attack_type = "ZIP"
                break
            elif choice == "0":
                print("Exiting.")
                sys.exit(0)
            else:
                log(Fore.YELLOW + "[!] Invalid choice. Try again.", 0)

    # --- Error handling and attack logic ---
    if args.zip:
        wordlist = None
        if args.wordlist:
            wordlist = load_wordlist(args.wordlist)
            if not wordlist:
                log(Fore.RED + "[-] Wordlist could not be loaded. Check the path and try again.", 0)
                return
        result = crack_zip_file(args.zip, wordlist, args.max_length, charset, args.threads)
        if not result:
            log(Fore.RED + "[-] Failed to crack ZIP file password. Try a different wordlist or increase max length.", 0)
        elif args.output:
            write_result_to_file(result, args.zip, "ZIP", 0, 0, args.output)
        return

    if not args.hash:
        log(Fore.RED + "[-] You must specify a target hash with -H or a ZIP file with -z", 0)
        parser.print_help()
        return

    if args.hybrid and args.wordlist:
        wordlist = load_wordlist(args.wordlist)
        if not wordlist:
            log(Fore.RED + "[-] Wordlist could not be loaded. Check the path and try again.", 0)
            return
        checkpoint = load_checkpoint() if args.resume else None
        start = time.time()
        result = hybrid_attack(args.hash, wordlist, args.hash_type, max_mutate_length=2, charset=charset, checkpoint=checkpoint, verbose=VERBOSITY > 0)
        elapsed = time.time() - start
        if result and args.output:
            write_result_to_file(result, args.hash, "Hybrid", elapsed, len(wordlist), args.output)
    elif args.wordlist:
        wordlist = load_wordlist(args.wordlist)
        if not wordlist:
            log(Fore.RED + "[-] Wordlist could not be loaded. Check the path and try again.", 0)
            return
        checkpoint = load_checkpoint() if args.resume else None
        start = time.time()
        result = dictionary_attack(args.hash, wordlist, args.hash_type, checkpoint, verbose=VERBOSITY > 0)
        elapsed = time.time() - start
        if result and args.output:
            write_result_to_file(result, args.hash, "Dictionary", elapsed, len(wordlist), args.output)
    else:
        checkpoint = load_checkpoint() if args.resume else None
        start = time.time()
        result = brute_force_cracker(args.hash, args.max_length, charset, args.hash_type, args.threads, verbose=VERBOSITY > 0)
        elapsed = time.time() - start
        if result and args.output:
            write_result_to_file(result, args.hash, "Brute Force", elapsed, 0, args.output)

    if not result:
        log(Fore.RED + "[-] Failed to crack the password. Try a different attack, wordlist, or charset.", 0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Operation cancelled by user")
        sys.exit(1)
