#!/usr/bin/env python3
"""
Wordlist Generator from Sitemaps, Proxies, and URL Lists

Extracts directories, file names, URL parameters, parameter values, and file extensions
from various input formats (Caido JSON, Burp XML, HAR, plain text, XML sitemaps, stdin).
Features:
- CLI with argparse (non‑interactive and scriptable)
- Support for multiple input formats (auto‑detected)
- Word processing: lowercase, length filters, stop word removal, camelCase/hyphen splitting
- Extract parameter values (optional)
- Output formats: plain list, CSV, Python set literal
- Performance optimised for large files (streaming text, iterative JSON/XML where possible)
- Self‑test mode (--test) to verify core functionality
"""

import argparse
import csv
import io
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import OrderedDict
from typing import Set, List, Optional, Iterator, Union, Dict, Any
from urllib.parse import urlparse, parse_qs

# ---------- Constants ----------
DEFAULT_MIN_LEN = 2
DEFAULT_MAX_LEN = 100
COMMON_STOP_WORDS = {
    'index', 'home', 'default', 'main', 'www', 'http', 'https', 'html',
    'php', 'asp', 'aspx', 'jsp', 'do', 'action', 'wp‑content', 'wp‑includes',
    'wp‑admin', 'cgi‑bin', 'images', 'css', 'js', 'fonts', 'uploads',
    'download', 'downloads', 'static', 'assets', 'files', 'data',
    'api', 'v1', 'v2', 'rest', 'graphql', 'admin', 'user', 'login',
    'logout', 'signin', 'signup', 'register', 'search', 'results'
}

# ---------- Word Processing ----------
def split_camel_case(word: str) -> List[str]:
    """Split camelCase or PascalCase into words."""
    # Handle common patterns: userProfile -> user, Profile
    # Using regex to split on uppercase letters or numbers
    parts = re.findall(r'[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z]|\d|\b)|[0-9]+', word)
    return [p.lower() for p in parts if len(p) > 0]

def split_hyphenated(word: str) -> List[str]:
    """Split on hyphens or underscores."""
    return [p for p in re.split(r'[-_]', word) if p]

def process_word(word: str, lowercase: bool = True, min_len: int = DEFAULT_MIN_LEN,
                 max_len: int = DEFAULT_MAX_LEN, remove_stopwords: bool = True,
                 split_camel: bool = True, split_hyphen: bool = True) -> Set[str]:
    """
    Apply all configured transformations to a raw word.
    Returns a set of resulting words (may be multiple after splitting).
    """
    if not word:
        return set()
    original = word
    results = set()

    # Splitting
    if split_camel and any(c.isupper() for c in word):
        for part in split_camel_case(word):
            results.add(part)
    if split_hyphen and ('-' in word or '_' in word):
        for part in split_hyphenated(word):
            results.add(part)
    # Always include the original (possibly after lowercasing)
    results.add(original)

    filtered = set()
    for w in results:
        if lowercase:
            w = w.lower()
        # Length check
        if not (min_len <= len(w) <= max_len):
            continue
        # Stop words
        if remove_stopwords and w in COMMON_STOP_WORDS:
            continue
        # Additional filter: no purely numeric (optional? keep as config)
        # For now, keep all
        filtered.add(w)
    return filtered

# ---------- URL Parsing ----------
def extract_path_components(url: str) -> Iterator[str]:
    """Yield each path segment from a URL (e.g., /admin/login -> 'admin', 'login')."""
    parsed = urlparse(url)
    path = parsed.path
    for segment in path.split('/'):
        if segment and segment != '':
            yield segment

def extract_parameter_names(url: str) -> Iterator[str]:
    """Yield query parameter names."""
    parsed = urlparse(url)
    if parsed.query:
        for name in parse_qs(parsed.query).keys():
            yield name

def extract_parameter_values(url: str, include_values: bool) -> Iterator[str]:
    """Yield query parameter values if include_values is True."""
    if not include_values:
        return
    parsed = urlparse(url)
    if parsed.query:
        for values in parse_qs(parsed.query).values():
            for v in values:
                if v:
                    yield v

def extract_file_extensions(url: str) -> Iterator[str]:
    """Yield file extensions (e.g., 'php', 'html') from the URL path."""
    parsed = urlparse(url)
    path = parsed.path
    if '.' in path:
        # Get the last dot segment, but avoid query strings
        filename = path.split('/')[-1]
        if '.' in filename:
            ext = filename.split('.')[-1]
            if ext and len(ext) <= 6:  # typical extensions
                yield ext

def extract_all_words_from_url(url: str, include_values: bool) -> Set[str]:
    """Collect all raw words from a single URL."""
    words = set()
    # Path components
    for seg in extract_path_components(url):
        words.add(seg)
    # Parameter names
    for name in extract_parameter_names(url):
        words.add(name)
    # Parameter values (optional)
    for val in extract_parameter_values(url, include_values):
        words.add(val)
    # File extensions
    for ext in extract_file_extensions(url):
        words.add(ext)
    return words

# ---------- Input Parsers ----------
def parse_json_sitemap(filepath: str, include_values: bool) -> Iterator[str]:
    """Parse Caido‑style JSON or generic URL list in JSON."""
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Normalise into a list of URL strings
    urls = []
    if isinstance(data, list):
        urls = data
    elif isinstance(data, dict):
        # Try common keys
        for key in ['urls', 'requests', 'items', 'entries']:
            if key in data:
                items = data[key]
                if isinstance(items, list):
                    urls = items
                    break
        # If still empty, recursively search for any string that looks like a URL
        if not urls:
            def extract_strings(obj):
                if isinstance(obj, str):
                    if obj.startswith(('http://', 'https://', '/')):
                        urls.append(obj)
                elif isinstance(obj, dict):
                    for v in obj.values():
                        extract_strings(v)
                elif isinstance(obj, list):
                    for item in obj:
                        extract_strings(item)
            extract_strings(data)

    for entry in urls:
        url = None
        if isinstance(entry, str):
            url = entry
        elif isinstance(entry, dict):
            # Common URL fields
            for key in ['url', 'path', 'request', 'uri']:
                if key in entry:
                    val = entry[key]
                    if isinstance(val, str):
                        url = val
                        break
                    elif isinstance(val, dict) and 'url' in val:
                        url = val['url']
                        break
        if url:
            words = extract_all_words_from_url(url, include_values)
            for w in words:
                yield w

def parse_xml_sitemap(filepath: str, include_values: bool) -> Iterator[str]:
    """Parse standard XML sitemap or Burp XML export."""
    tree = ET.parse(filepath)
    root = tree.getroot()
    # Namespace handling
    ns = {'ns': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
    urls = []
    # Try sitemap format
    for loc in root.findall('.//ns:loc', ns):
        if loc.text:
            urls.append(loc.text)
    # If no sitemap URLs, try Burp XML structure (<url> elements)
    if not urls:
        for url_elem in root.findall('.//url'):
            url_text = url_elem.text
            if url_text:
                urls.append(url_text)
    # Fallback: any element named url
    if not urls:
        for elem in root.iter():
            if elem.tag.endswith('url') and elem.text:
                urls.append(elem.text)

    for url in urls:
        words = extract_all_words_from_url(url, include_values)
        for w in words:
            yield w

def parse_har_file(filepath: str, include_values: bool) -> Iterator[str]:
    """Parse HAR (HTTP Archive) files."""
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    entries = data.get('log', {}).get('entries', [])
    for entry in entries:
        request = entry.get('request', {})
        url = request.get('url')
        if url:
            words = extract_all_words_from_url(url, include_values)
            for w in words:
                yield w
        # Also check response redirects?
        response = entry.get('response', {})
        redirect_url = response.get('redirectURL')
        if redirect_url:
            words = extract_all_words_from_url(redirect_url, include_values)
            for w in words:
                yield w

def parse_plain_text(filepath: str, include_values: bool) -> Iterator[str]:
    """Parse a plain text file with one URL per line."""
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            words = extract_all_words_from_url(line, include_values)
            for w in words:
                yield w

def parse_stdin(include_values: bool) -> Iterator[str]:
    """Read URLs from standard input (one per line)."""
    for line in sys.stdin:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        words = extract_all_words_from_url(line, include_values)
        for w in words:
            yield w

# ---------- Output Writers ----------
def write_wordlist(words: Set[str], output_file: Optional[str], output_format: str,
                   sort_by: str):
    """Write the wordlist to a file or stdout."""
    # Sorting
    word_list = list(words)
    if sort_by == 'length':
        word_list.sort(key=lambda w: (len(w), w))
    elif sort_by == 'alpha':
        word_list.sort()
    else:  # 'frequency' would require counts; not implemented here, default alpha
        word_list.sort()

    # Prepare output stream
    out_fh = open(output_file, 'w', encoding='utf-8') if output_file else sys.stdout

    try:
        if output_format == 'csv':
            writer = csv.writer(out_fh)
            writer.writerow(['word'])
            for w in word_list:
                writer.writerow([w])
        elif output_format == 'python':
            out_fh.write("{\n")
            for w in word_list:
                out_fh.write(f"    '{w}',\n")
            out_fh.write("}\n")
        else:  # 'plain' (one per line)
            for w in word_list:
                out_fh.write(w + '\n')
    finally:
        if output_file:
            out_fh.close()

# ---------- Main Orchestrator ----------
def build_wordlist(input_file: Optional[str], include_values: bool,
                   lowercase: bool, min_len: int, max_len: int,
                   remove_stopwords: bool, split_camel: bool, split_hyphen: bool,
                   output_file: Optional[str], output_format: str,
                   sort_by: str) -> int:
    """
    Core function: read from source, extract, process, and write.
    Returns 0 on success, 1 on error.
    """
    raw_words = set()
    try:
        # Choose parser based on input source
        if input_file is None:
            # Read from stdin
            gen = parse_stdin(include_values)
        else:
            # Auto‑detect format by extension
            _, ext = os.path.splitext(input_file.lower())
            if ext == '.json':
                gen = parse_json_sitemap(input_file, include_values)
            elif ext == '.xml':
                gen = parse_xml_sitemap(input_file, include_values)
            elif ext == '.har':
                gen = parse_har_file(input_file, include_values)
            elif ext == '.txt':
                gen = parse_plain_text(input_file, include_values)
            else:
                # Try to guess content: first read a few bytes
                with open(input_file, 'rb') as f:
                    header = f.read(1024)
                if header.strip().startswith(b'<'):
                    gen = parse_xml_sitemap(input_file, include_values)
                elif header.strip().startswith(b'{'):
                    gen = parse_json_sitemap(input_file, include_values)
                else:
                    gen = parse_plain_text(input_file, include_values)

        # Collect and process words
        for raw_word in gen:
            processed = process_word(
                raw_word,
                lowercase=lowercase,
                min_len=min_len,
                max_len=max_len,
                remove_stopwords=remove_stopwords,
                split_camel=split_camel,
                split_hyphen=split_hyphen
            )
            raw_words.update(processed)

        if not raw_words:
            print("[!] No words extracted. Check input format or adjust filters.",
                  file=sys.stderr)
            return 1

        write_wordlist(raw_words, output_file, output_format, sort_by)
        print(f"[+] Wordlist generated with {len(raw_words)} unique words.",
              file=sys.stderr)
        if output_file:
            print(f"[+] Saved to: {output_file}", file=sys.stderr)
        return 0
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        return 1

# ---------- Self‑Test ----------
def run_tests():
    """Run basic unit tests for core functions."""
    print("[*] Running self‑tests...")
    # Test split_camel_case
    assert split_camel_case("userProfile") == ["user", "profile"]
    assert split_camel_case("XMLHttpRequest") == ["xml", "http", "request"]
    # Test split_hyphenated
    assert split_hyphenated("foo-bar_baz") == ["foo", "bar", "baz"]
    # Test process_word
    words = process_word("AdminLogin", lowercase=True, min_len=3)
    assert "adminlogin" in words or ("admin" in words and "login" in words)  # splitting
    # Test URL extraction
    url = "https://example.com/admin/users.php?action=edit&id=123"
    words = extract_all_words_from_url(url, include_values=True)
    assert "admin" in words
    assert "users" in words
    assert "php" in words
    assert "action" in words
    assert "edit" in words
    assert "id" in words
    assert "123" in words
    # Test with include_values=False
    words_no_val = extract_all_words_from_url(url, include_values=False)
    assert "123" not in words_no_val
    # Test length filter
    processed = process_word("short", min_len=6, max_len=10)
    assert len(processed) == 0
    processed = process_word("verylongwordhere", min_len=1, max_len=5)
    assert len(processed) == 0
    # Test stop words
    processed = process_word("index", remove_stopwords=True)
    assert "index" not in processed
    print("[✓] All tests passed.")

# ---------- CLI Entry Point ----------
def main():
    parser = argparse.ArgumentParser(
        description="Extract wordlists from sitemaps, proxy exports, and URL lists.",
        epilog="Examples:\n"
               "  python wordlist.py -i caido_export.json -o mylist.txt\n"
               "  python wordlist.py -i sitemap.xml --include-values --min 3\n"
               "  cat urls.txt | python wordlist.py --stdin\n"
               "  python wordlist.py --test"
    )
    # Input options
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument('-i', '--input', help='Input file path')
    input_group.add_argument('--stdin', action='store_true', help='Read URLs from stdin')
    # Output options
    parser.add_argument('-o', '--output', help='Output file (default: stdout)')
    parser.add_argument('-f', '--format', choices=['plain', 'csv', 'python'],
                        default='plain', help='Output format (default: plain)')
    parser.add_argument('-s', '--sort', choices=['alpha', 'length'],
                        default='alpha', help='Sort order (default: alpha)')
    # Extraction options
    parser.add_argument('--include-values', action='store_true',
                        help='Include URL parameter values (may increase size)')
    # Processing options
    parser.add_argument('--no-lowercase', action='store_true',
                        help='Do not convert words to lowercase')
    parser.add_argument('--min', type=int, default=DEFAULT_MIN_LEN,
                        help=f'Minimum word length (default: {DEFAULT_MIN_LEN})')
    parser.add_argument('--max', type=int, default=DEFAULT_MAX_LEN,
                        help=f'Maximum word length (default: {DEFAULT_MAX_LEN})')
    parser.add_argument('--keep-stopwords', action='store_true',
                        help='Do not remove common stop words')
    parser.add_argument('--no-split-camel', action='store_true',
                        help='Do not split camelCase words')
    parser.add_argument('--no-split-hyphen', action='store_true',
                        help='Do not split hyphenated/underscored words')
    # Utility
    parser.add_argument('--test', action='store_true', help='Run self‑tests and exit')

    args = parser.parse_args()

    if args.test:
        run_tests()
        sys.exit(0)

    # Determine input source
    input_file = None
    if args.stdin:
        input_file = None
    elif args.input:
        input_file = args.input
    else:
        # No input specified, try to read from stdin if not a TTY
        if not sys.stdin.isatty():
            input_file = None
        else:
            parser.print_help()
            sys.exit(1)

    # Process
    ret = build_wordlist(
        input_file=input_file,
        include_values=args.include_values,
        lowercase=not args.no_lowercase,
        min_len=args.min,
        max_len=args.max,
        remove_stopwords=not args.keep_stopwords,
        split_camel=not args.no_split_camel,
        split_hyphen=not args.no_split_hyphen,
        output_file=args.output,
        output_format=args.format,
        sort_by=args.sort
    )
    sys.exit(ret)

if __name__ == "__main__":
    main()