import os
import re
import argparse
import urllib.parse
from collections import defaultdict

class BugBountyAnalyzer:
    def __init__(self, input_dir, output_dir, scope_file=None):
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.scope = set()
        
        # Load scope if provided
        if scope_file and os.path.exists(scope_file):
            with open(scope_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.scope.add(line.lower())
        
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        # Regex patterns
        self.url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
        self.param_pattern = re.compile(r'[?&]([a-zA-Z0-9_]+)=')
        self.js_pattern = re.compile(r'\.(js|json|xml|env|git|bak|config)(\?|$)', re.IGNORECASE)
        
        # High-value keywords to hunt for
        self.interesting_keywords = ['admin', 'api', 'dev', 'test', 'staging', 'token', 'secret', 'key', 'auth', 'login', 'upload', 'redirect', 'url=']

    def read_files(self):
        """Reads all txt files in the directory line by line (memory safe)."""
        all_lines = set()
        for filename in os.listdir(self.input_dir):
            if filename.endswith('.txt'):
                filepath = os.path.join(self.input_dir, filename)
                print(f"[*] Reading {filename}...")
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            all_lines.add(line)
        return all_lines

    def is_in_scope(self, url):
        """Checks if a URL/domain is within the provided scope."""
        if not self.scope:
            return True
        domain = urllib.parse.urlparse(url).netloc if 'http' in url else url
        # Remove port if present
        domain = domain.split(':')[0]
        return any(scope_domain in domain for scope_domain in self.scope)

    def analyze(self):
        print("[*] Starting analysis...")
        unique_lines = self.read_files()
        print(f"[+] Total unique lines found: {len(unique_lines)}")

        results = defaultdict(set)
        
        for line in unique_lines:
            # 1. Scope Check
            if not self.is_in_scope(line):
                continue

            # 2. Extract URLs with Parameters (Prime XSS/SQLi targets)
            if '?' in line and '=' in line:
                params = self.param_pattern.findall(line)
                if params:
                    results['urls_with_params'].add(line)

            # 3. Find JavaScript and sensitive files
            if self.js_pattern.search(line):
                results['interesting_files'].add(line)

            # 4. Find high-value keywords
            line_lower = line.lower()
            for keyword in self.interesting_keywords:
                if keyword in line_lower:
                    results[f'keyword_{keyword}'].add(line)

            # 5. Extract clean subdomains (if no http)
            if 'http' not in line and '.' in line and '/' not in line:
                results['subdomains'].add(line)

        self.save_results(results)

    def save_results(self, results):
        print("\n[*] Saving results...")
        summary = []
        for category, items in results.items():
            if not items:
                continue
            output_file = os.path.join(self.output_dir, f"{category}.txt")
            with open(output_file, 'w', encoding='utf-8') as f:
                for item in sorted(items):
                    f.write(f"{item}\n")
            summary.append(f"[+] {category}: {len(items)} items -> {output_file}")

        print("\n".join(summary))
        print(f"\n[!] Analysis complete. Check the '{self.output_dir}' directory.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bug Bounty Recon Analyzer")
    parser.add_argument("-i", "--input", required=True, help="Directory containing your recon txt files")
    parser.add_argument("-o", "--output", default="analyzed_output", help="Directory to save analyzed results")
    parser.add_argument("-s", "--scope", help="Optional file containing in-scope domains (one per line)")
    
    args = parser.parse_args()
    
    analyzer = BugBountyAnalyzer(args.input, args.output, args.scope)
    analyzer.analyze()
