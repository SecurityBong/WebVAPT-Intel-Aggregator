"""
Script Name: WebVAPT-Intel-Engine
Description: Fully locked Web VAPT automation engine featuring verified reports, 
             research references, writeup, official OWASP top 10 links.
"""

import sys
import os
import json
import urllib.request
import time
import re
import random

try:
    from ddgs import DDGS
except ImportError:
    print(f"\n[!] Error: 'ddgs' not found. Run: pip install ddgs")
    sys.exit(1)

if os.name == 'nt': os.system('')

class C:
    CYAN = '\033[96m'; GREEN = '\033[92m'; YELLOW = '\033[93m'; RED = '\033[91m'
    MAGENTA = '\033[35m'; BLUE = '\033[94m'; RESET = '\033[0m'; BOLD = '\033[1m'; DIM = '\033[2m'

VULN_DB = {
    "1": {"title": "A01: Broken Access Control", "folders": ["05-Authorization_Testing"], "keywords": ["idor", "bola", "privilege", "bypass", "authorization", "traversal", "file"]},
    "2": {"title": "A02: Cryptographic Failures", "folders": ["09-Testing_for_Weak_Cryptography"], "keywords": ["crypto", "padding", "oracle", "aes", "rsa", "hash", "tls"]},
    "3": {"title": "A03: Injection", "folders": ["07-Input_Validation_Testing"], "keywords": ["sqli", "xss", "rce", "command", "injection", "lfi", "ssrf"]},
    "4": {"title": "A04: Insecure Design", "folders": ["10-Business_Logic_Testing"], "keywords": ["logic", "flaw", "design", "threat", "model", "workflow"]},
    "5": {"title": "A05: Security Misconfiguration", "folders": ["02-Configuration_and_Deployment_Management_Testing"], "keywords": ["misconfiguration", "cors", "s3", "bucket", "default", "directory"]},
    "6": {"title": "A06: Vulnerable/Outdated Components", "folders": ["01-Information_Gathering"], "keywords": ["cve", "outdated", "component", "vulnerable", "patch"]},
    "7": {"title": "A07: Identification & Auth Failures", "folders": ["03-Identity_Management_Testing", "04-Authentication_Testing", "06-Session_Management_Testing"], "keywords": ["auth", "jwt", "session", "token", "cookie", "brute", "mfa", "oauth", "saml"]},
    "8": {"title": "A08: Software/Data Integrity Failures", "folders": ["11-Client-side_Testing"], "keywords": ["integrity", "ci/cd", "pipeline", "deserialization"]},
    "9": {"title": "A09: Security Logging Failures", "folders": ["08-Testing_for_Error_Handling"], "keywords": ["log", "monitor", "siem", "blind", "detect"]},
    "10": {"title": "A10: SSRF & API Vulnerabilities", "folders": ["12-API_Testing"], "keywords": ["ssrf", "api", "rest", "graphql", "bola"]}
}

FALLBACK_KNOWLEDGE = {
    "05-Authorization_Testing": (
        "Ensures that application authorization policies are enforced correctly and cannot be bypassed by attackers.",
        "Implement robust access control checks on every server-side request, enforcing the principle of least privilege."
    ),
    "07-Input_Validation_Testing": (
        "Validates that all user-supplied input is properly sanitized and validated before processing to prevent injection attacks.",
        "Use parameterized queries, strict allow-lists for input validation, and proper context-aware output encoding."
    ),
    "03-Identity_Management_Testing": (
        "Evaluates how user identities, session tokens, and authentication credentials are managed throughout their lifecycle.",
        "Enforce multi-factor authentication, secure session management flags (HttpOnly, Secure), and strong password hashing."
    ),
    "04-Authentication_Testing": (
        "Verifies that authentication mechanisms are implemented securely to protect against credential stuffing and brute-forcing.",
        "Implement account lockout policies, rate limiting, and multi-factor authentication."
    ),
    "06-Session_Management_Testing": (
        "Examines session management controls to ensure session tokens cannot be hijacked, predicted, or fixed.",
        "Use cryptographically strong session identifiers and invalidate sessions upon logout."
    )
}

def clean_query(filename):
    q = re.sub(r'^\d{2}-', '', filename)
    q = q.replace('.md', '').replace('_', ' ')
    q = re.sub(r'Testing', '', q, flags=re.IGNORECASE)
    return q.strip()

def extract_clean_sentences(text_block, max_sentences=2):
    if not text_block: return None
    cleaned = re.sub(r'\s+', ' ', text_block).strip()
    sentences = re.split(r'(?<=[.!?])\s+', cleaned)
    valid = [s.strip() for s in sentences if len(s.strip()) > 15]
    if not valid: return cleaned[:250]
    return " ".join(valid[:max_sentences])

def parse_markdown_intel(raw_url, folder_key):
    default_desc, default_rem = FALLBACK_KNOWLEDGE.get(folder_key, (
        "Examines how web applications manage files, data inputs, and operational security boundaries.",
        "Follow secure coding standards, enforce proper validation, and maintain least-privilege configurations."
    ))
    try:
        req = urllib.request.Request(raw_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as res:
            md = res.read().decode('utf-8')
            sum_m = re.search(r'##\s*(?:Summary|Objective)\s*(.*?)(?=\n## |\Z)', md, re.DOTALL | re.IGNORECASE)
            rem_m = re.search(r'##\s*(?:Remediation|How to Fix|Solutions)\s*(.*?)(?=\n## |\Z)', md, re.DOTALL | re.IGNORECASE)
            
            desc = extract_clean_sentences(sum_m.group(1)) if sum_m else default_desc
            rem = extract_clean_sentences(rem_m.group(1)) if rem_m else default_rem
            return desc, rem
    except:
        return default_desc, default_rem

def is_valid_payload(link):
    low = link.lower()
    if any(x in low for x in ['clev?', 'redirect', 'search.php', 'google.com', 'bing.com']):
        return False
    return any(d in low for d in ['github.com', 'gitlab.com', 'seclists', 'payloadsallthethings', 'raw.githubusercontent.com'])

def get_padding_links(query_term):
    padding_refs = []
    time.sleep(random.uniform(1.0, 2.0))
    try:
        with DDGS() as ddgs:
            search_targets = [
                f"{query_term} site:hackerone.com/reports",
                f"{query_term} portswigger web security academy",
                f"{query_term} hacktricks",
                f"{query_term} site:slcyber.io/research-center/",
                f"{query_term} medium bug bounty writeup"
            ]
            for st in search_targets:
                results = list(ddgs.text(st, max_results=1))
                if results:
                    link = results[0].get('href', '').strip()
                    if link and link not in padding_refs and link.count('/') > 3:
                        if "hackerone.com" in link.lower() and "/reports/" not in link.lower():
                            continue
                        padding_refs.append(link)
    except: pass
    return padding_refs

def get_intelligence(query_term, folder_keywords):
    for _ in range(2):
        try:
            with DDGS() as ddgs:
                queries = [
                    f"{query_term} site:hackerone.com/reports",
                    f"{query_term} site:slcyber.io/research-center/",
                    f"{query_term} bug bounty report writeup exploit",
                    f"{query_term} payload wordlist bypass github"
                ]
                
                results = []
                for q in queries:
                    results.extend(list(ddgs.text(q, max_results=25)))
                
                refs, pays, seen_links = [], [], set()
                slcyber_count = 0
                MAX_SLCYBER_LINKS = 2
                
                for r in results:
                    link = r.get('href', '').strip()
                    title = r.get('title', '').lower()
                    snippet = r.get('body', '').lower()
                    low_link = link.lower()
                    
                    if low_link in seen_links: 
                        continue
                    seen_links.add(low_link)
                    
                    if "github.com/devanshbatham" in low_link:
                        try:
                            raw = "https://raw.githubusercontent.com/devanshbatham/Awesome-Bugbounty-Writeups/main/README.md"
                            with urllib.request.urlopen(urllib.request.Request(raw, headers={'User-Agent': 'Mozilla/5.0'}), timeout=4) as res:
                                extracted = re.findall(r'https?://[^\s\)]+', res.read().decode('utf-8'))
                                for l in extracted:
                                    if "hackerone.com/reports/" in l.lower() and l not in refs:
                                        refs.append(l)
                        except: pass
                        continue
                    
                    if any(kw in low_link or kw in title or kw in snippet for kw in ["payload", "seclists", "wordlist", "fuzzing", "bypass"]):
                        if is_valid_payload(link):
                            if link not in pays: pays.append(link)
                        continue
                    
                    if "hackerone.com" in low_link:
                        if "/reports/" in low_link and link not in refs:
                            refs.append(link)
                        continue
                    
                    if "slcyber.io/research-center/" in low_link:
                        if slcyber_count < MAX_SLCYBER_LINKS:
                            if any(kw in low_link or kw in title or kw in snippet for kw in folder_keywords) or any(kw in low_link for kw in query_term.lower().split()):
                                if link not in refs:
                                    refs.append(link)
                                    slcyber_count += 1
                        continue
                    
                    if any(site in low_link for site in ["bugcrowd.com/disclosures", "portswigger.net/web-security", "book.hacktricks.xyz", "medium.com", "infosecwriteups.com"]):
                        if link not in refs: refs.append(link)
                
                if len(refs) < 10:
                    specific_pads = get_padding_links(query_term)
                    for sp in specific_pads:
                        if len(refs) < 10 and sp not in refs:
                            refs.append(sp)
                
                return refs[:10], pays[:3]
        except: 
            time.sleep(2)
    return [], []

def main():
    while True:
        print(f"\n{C.CYAN}╭──────────────────────────────────────────────────────────────────────────╮{C.RESET}")
        print(f"{C.CYAN}│{C.RESET}   {C.BLUE}🛡️  WebVAPT-Intel-Aggregator {C.RESET} {C.DIM}|{C.RESET} {C.GREEN}By SecurityBong A.K.A Rahul{C.RESET}   {C.CYAN}│{C.RESET}")
        print(f"{C.CYAN}│{C.RESET}   {C.DIM}[!] Note: This script is not AI; it fetches live links & test cases.{C.RESET}      {C.CYAN}│{C.RESET}")
        print(f"{C.CYAN}│{C.RESET}   {C.DIM}    Results are automated and may occasionally contain inaccuracies.{C.RESET}    {C.CYAN}│{C.RESET}")
        print(f"{C.CYAN}╰──────────────────────────────────────────────────────────────────────────╯{C.RESET}")
        print(f"{C.MAGENTA}╭─[{C.RESET} {C.BOLD}OWASP Top 10 Categories{C.RESET} {C.MAGENTA}]───────────────────────────────────────────────────╮{C.RESET}")
        for k, v in VULN_DB.items():
            print(f"{C.MAGENTA}│{C.RESET}   {C.GREEN}[{k.zfill(2)}]{C.RESET} {v['title'].ljust(60)} {C.MAGENTA}│{C.RESET}")
        print(f"{C.MAGENTA}│{C.RESET}                                                                          {C.MAGENTA}│{C.RESET}")
        print(f"{C.MAGENTA}│{C.RESET}   {C.RED}[00]{C.RESET} Exit Engine                                                  {C.MAGENTA}│{C.RESET}")
        print(f"{C.MAGENTA}╰──────────────────────────────────────────────────────────────────────────╯{C.RESET}")
        
        choice = input(f"\n{C.YELLOW}Select Category (01-10): {C.RESET}").strip()
        if choice == '00' or choice == '': break
        
        c = choice.lstrip('0') if choice.lstrip('0') != '' else '0'
        if c in VULN_DB:
            folder = VULN_DB[c]['folders'][0]
            keywords = VULN_DB[c]['keywords']
            
            url = f"https://api.github.com/repos/OWASP/wstg/contents/document/4-Web_Application_Security_Testing/{folder}"
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                files = json.loads(urllib.request.urlopen(req).read().decode())
            except:
                print(f"{C.RED}[!] Failed to fetch test cases from OWASP GitHub API.{C.RESET}")
                continue
            
            for f in files:
                if not f['name'].endswith('.md') or f['name'].lower() == "readme.md": continue
                
                test_title = f['name'].replace('.md', '').replace('_', ' ')
                owasp_link = f.get('html_url', 'N/A')
                
                print(f"\n{C.CYAN}╭──────────────────────────────────────────────────────────────────────────╮{C.RESET}")
                print(f"{C.CYAN}│{C.RESET} {C.BOLD}{C.MAGENTA}Test Case: {test_title:<60}{C.RESET} {C.CYAN}│{C.RESET}")
                print(f"{C.CYAN}├──────────────────────────────────────────────────────────────────────────┤{C.RESET}")
                
                print(f"{C.CYAN}│{C.RESET} {C.BLUE}[OWASP Link]:{C.RESET} {owasp_link}")
                
                desc, rem = parse_markdown_intel(f['download_url'], folder)
                print(f"{C.CYAN}│{C.RESET} {C.BLUE}[Desc]:{C.RESET}       {desc}")
                print(f"{C.CYAN}│{C.RESET} {C.GREEN}[Remed]:{C.RESET}      {rem}")
                print(f"{C.CYAN}├──────────────────────────────────────────────────────────────────────────┤{C.RESET}")
                
                print(f"{C.CYAN}│{C.RESET} {C.YELLOW}[~] Fetching live URLs...{C.RESET}", end="\r")
                query_term = clean_query(f['name'])
                refs, pays = get_intelligence(query_term, keywords)
                print(f"{C.CYAN}│{C.RESET}                                                                          {C.RESET}", end="\r")
                
                print(f"{C.CYAN}│{C.RESET} {C.BOLD}--- Community Writeups & Research ---{C.RESET}")
                if refs:
                    for l in refs:
                        print(f"{C.CYAN}│{C.RESET}   ├── {C.GREEN}{l}{C.RESET}")
                else:
                    print(f"{C.CYAN}│{C.RESET}   ├── {C.YELLOW}Could not find top tier links, checking local references...{C.RESET}")
                
                print(f"{C.CYAN}│{C.RESET} {C.BOLD}--- Weaponized Payloads & Wordlists ---{C.RESET}")
                if pays:
                    for p in pays:
                        print(f"{C.CYAN}│{C.RESET}   └── {C.RED}☠  {p}{C.RESET}")
                else:
                    print(f"{C.CYAN}│{C.RESET}   └── {C.YELLOW}☠  [Kali Local]: /usr/share/wordlists/seclists/{C.RESET}")
                print(f"{C.CYAN}╰──────────────────────────────────────────────────────────────────────────╯{C.RESET}")
        else:
            print(f"\n{C.RED}[!] Invalid selection.{C.RESET}")

if __name__ == "__main__":
    main()