# The-Bug-Bounty-Analyzer-Tool

Below is a Python-based analyzer script designed specifically to process these large files safely (line-by-line to prevent memory crashes), deduplicate the data, and extract actionable intelligence.



### 🚀 How to Use It

1. **Create a scope file (Optional but highly recommended):**
   Create a file named `scope.txt` and put your target domains in it (e.g., `*.example.com`).
2. **Run the tool:**
   Open your terminal in the folder where your files are (or point to the folder) and run:
   ```bash
   python3 analyzer.py -i /path/to/your/recon/folder -o analyzed_output -s scope.txt
   ```
   *(If you are already in the folder, just use `-i .`)*
3. **Review the Output:**
   The script will create an `analyzed_output` folder containing:
   * `urls_with_params.txt` (Your #1 priority for manual testing)
   * `interesting_files.txt` (`.js`, `.env`, `.git` leaks)
   * `keyword_admin.txt`, `keyword_api.txt`, etc.
   * `subdomains.txt` (Cleaned up list)

---

### ⚡ Pro-Tips for Handling "Huge" Files

If your files are truly massive (gigabytes), Python might still be slow. You should integrate standard command-line tools into your workflow:

**1. Quick Deduplication & Sorting (Bash):**
```bash
cat *.txt | sort -u > all_unique.txt
```

**2. The "GF" Tool (Go Fast):**
If you don't have it, install `gf` (Grep Finder). It uses JSON patterns to extract specific vulnerabilities instantly.
```bash
# Extract URLs with parameters
cat all_unique.txt | gf xss > xss_candidates.txt
cat all_unique.txt | gf sqli > sqli_candidates.txt
```

**3. Filter for "Live" Hosts:**
Your screenshot shows `live-subs.txt`, which is great. But if you want to verify them again, use `httpx`:
```bash
cat subdomains.txt | httpx -silent -status-code -title -o live_detailed.txt
```

**4. Automate the Pipeline:**
Instead of analyzing after the fact, chain them:
```bash
subfinder -d target.com -silent | httpx -silent | gau | gf xss | nuclei -t xss/
```

The Python script above is designed to be your **central clearinghouse**. Run it after your initial recon to drastically reduce the noise before you start manual testing.
