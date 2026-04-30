#!/usr/bin/python3

import os
import sys
import re
import time
import requests
import argparse
import threading
import tldextract
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.parse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

TOKENS_FILE      = os.path.dirname(os.path.realpath(__file__)) + '/.tokens'
GITHUB_MAX_PAGES = 10

FILE_TYPES = [
    'JavaScript', 'Python', 'Java', 'Go', 'Ruby', 'PHP', 'Shell',
    'CSV', 'Markdown', 'XML', 'JSON', 'Text', 'CSS', 'HTML',
    'Perl', 'ActionScript', 'Lua', 'C',
]

try:
    from colored import fg, attr
    def color(text, c): return "%s%s%s" % (fg(c), text, attr(0))
except ImportError:
    def color(text, _): return text


# ── Shared state ──────────────────────────────────────────────────────────────
t_lock      = threading.Lock()
t_history   = set()
t_seen_urls = set()


# ── Per-thread sessions ───────────────────────────────────────────────────────
_tls = threading.local()

def _make_session(pool_size: int) -> requests.Session:
    s = requests.Session()
    retry = Retry(total=3, backoff_factor=0.4,
                  status_forcelist=[500, 502, 503, 504],
                  allowed_methods=["GET"])
    adapter = HTTPAdapter(max_retries=retry,
                          pool_connections=pool_size,
                          pool_maxsize=pool_size * 2)
    s.mount("https://", adapter)
    s.mount("http://",  adapter)
    return s

def get_search_session():
    if not hasattr(_tls, 'search'):
        _tls.search = _make_session(8)
    return _tls.search

def get_fetch_session():
    if not hasattr(_tls, 'fetch'):
        _tls.fetch = _make_session(32)
    return _tls.fetch


# ── Token manager ─────────────────────────────────────────────────────────────
class TokenManager:
    def __init__(self, tokens):
        self.tokens = list(tokens)
        self.lock   = threading.Lock()
        self.index  = 0
        self.rl     = {}

    def get_next_token(self):
        with self.lock:
            if not self.tokens:
                return None
            now = time.time()
            for _ in range(len(self.tokens)):
                t = self.tokens[self.index % len(self.tokens)]
                self.index += 1
                reset = self.rl.get(t)
                if reset is None or now >= reset:
                    self.rl.pop(t, None)
                    return t
            return None

    def mark_limited(self, token, reset=None):
        with self.lock:
            self.rl[token] = reset or (time.time() + 60)

    def wait_for_token(self, raw_mode=False, timeout=120):
        deadline = time.time() + timeout
        while time.time() < deadline:
            t = self.get_next_token()
            if t:
                return t
            if not raw_mode:
                sys.stderr.write(color("[!] all tokens rate-limited, waiting 10s…\n", 'yellow'))
            time.sleep(10)
        return None

    @property
    def active_count(self):
        with self.lock:
            now = time.time()
            return sum(1 for t in self.tokens
                       if t not in self.rl or now >= self.rl[t])


# ── GitHub search (one page) ──────────────────────────────────────────────────
def github_search(token_manager, search, page, sort, order, raw_mode=False):
    while True:
        token = token_manager.wait_for_token(raw_mode)
        if not token:
            if not raw_mode:
                sys.stderr.write(color("[-] no token available, giving up.\n", 'red'))
            return None

        headers = {"Authorization": "token " + token}
        url = (
            "https://api.github.com/search/code"
            f"?per_page=100&s={sort}&type=Code&o={order}&q={search}&page={page}"
        )
        try:
            r = get_search_session().get(url, headers=headers, timeout=12)
            remaining  = r.headers.get('X-RateLimit-Remaining')
            reset_time = r.headers.get('X-RateLimit-Reset')

            if remaining is not None and int(remaining) == 0:
                token_manager.mark_limited(token, int(reset_time) if reset_time else None)

            if r.status_code == 403:
                token_manager.mark_limited(token, int(reset_time) if reset_time else None)
                if not raw_mode:
                    sys.stderr.write(color("[!] 403 – rotating token…\n", 'yellow'))
                continue

            if r.status_code == 422:
                if not raw_mode:
                    sys.stderr.write(color(f"[-] 422 on page {page} (query too broad?)\n", 'red'))
                return None

            data = r.json()
            if 'message' in data:
                msg = data['message'].lower()
                if 'rate limit' in msg or 'abuse' in msg:
                    token_manager.mark_limited(token, int(reset_time) if reset_time else None)
                    continue
                if not raw_mode:
                    sys.stderr.write(color(f"[-] API: {data['message']}\n", 'red'))
                return None

            return data

        except requests.exceptions.Timeout:
            if not raw_mode:
                sys.stderr.write(color(f"[-] timeout p{page}, retrying…\n", 'yellow'))
            time.sleep(2)
        except Exception as e:
            if not raw_mode:
                sys.stderr.write(color(f"[-] error: {e}\n", 'red'))
            return None


# ── Raw URL helpers ───────────────────────────────────────────────────────────
def get_raw_url(item):
    url = item['html_url']
    url = url.replace('https://github.com/', 'https://raw.githubusercontent.com/')
    url = url.replace('/blob/', '/')
    return url

def fetch_code(url, raw_mode=False):
    try:
        r = get_fetch_session().get(url, timeout=8)
        return r.text
    except Exception as e:
        if not raw_mode:
            sys.stderr.write(color(f"[-] fetch err: {e}\n", 'red'))
        return None


# ── Extract matches from fetched code ────────────────────────────────────────
def extract_matches(code, item, domain_regexp, source, raw_mode):
    matches = re.findall(domain_regexp, code, re.IGNORECASE)
    if not matches:
        return '', 0

    local_new  = []
    local_seen = set()

    for match in matches:
        sub = match[0].replace('2F', '').lower().strip()
        if not sub or sub in local_seen:
            continue
        local_seen.add(sub)
        local_new.append(sub)

    if not local_new:
        return '', 0

    block_lines = []
    with t_lock:
        for sub in local_new:
            if source:
                t_history.add(sub)
                block_lines.append(sub)
            elif sub not in t_history:
                t_history.add(sub)
                block_lines.append(sub)

    if not block_lines:
        return '', 0

    if source and not raw_mode:
        header = color(f">>> {item['html_url']}", 'yellow') + "\n\n"
        return header + "\n".join(block_lines), len(block_lines)
    return "\n".join(block_lines), len(block_lines)


# ── Process one page's items ──────────────────────────────────────────────────
def process_page_items(items, domain_regexp, source, raw_mode, fetch_executor):
    """
    Returns: count of NEW subdomains found on this page.
    Used by caller for early-stop decisions.
    """
    to_fetch = []
    with t_lock:
        for item in items:
            url = get_raw_url(item)
            if url not in t_seen_urls:
                t_seen_urls.add(url)
                to_fetch.append((item, url))

    if not to_fetch:
        return 0

    future_map = {
        fetch_executor.submit(fetch_code, url, raw_mode): item
        for item, url in to_fetch
    }

    page_new_count = 0
    for future in as_completed(future_map):
        item = future_map[future]
        code = future.result()
        if not code:
            continue
        out, n = extract_matches(code, item, domain_regexp, source, raw_mode)
        if out:
            sys.stdout.write(out + "\n")
            sys.stdout.flush()
        page_new_count += n

    return page_new_count


# ── CORE: process one (file_type, sort, order) ────────────────────────────────
def process_file_type(token_manager, base_search, file_type, sort, order,
                      domain_regexp, source, raw_mode, fetch_executor,
                      dry_pages_limit=2):
    """
    KEY CHANGE — Sequential page fetching with early-stop:

    Instead of submitting all 10 pages at once (which burns API quota
    regardless of whether results are useful), we fetch page-by-page and
    stop as soon as `dry_pages_limit` consecutive pages yield zero NEW
    subdomains. This typically cuts API calls by 60-80%.

    dry_pages_limit=2 means: stop after 2 pages in a row with no new finds.
    """
    search = base_search + '+language:' + file_type

    consecutive_dry = 0

    for page in range(1, GITHUB_MAX_PAGES + 1):
        data = github_search(token_manager, search, page, sort, order, raw_mode)
        if not data:
            break

        items = data.get('items', [])
        total = data.get('total_count', 0)

        if page == 1 and not raw_mode:
            sys.stderr.write(
                color(f"[*] {file_type} ({sort or 'best'}/{order}): {total}\n", 'cyan')
            )

        if not items:
            break

        new_found = process_page_items(items, domain_regexp, source, raw_mode, fetch_executor)

        if new_found == 0:
            consecutive_dry += 1
            if consecutive_dry >= dry_pages_limit:
                if not raw_mode:
                    sys.stderr.write(
                        color(f"[~] {file_type}: {dry_pages_limit} dry pages, stopping early\n", 'yellow')
                    )
                break
        else:
            consecutive_dry = 0

        # If this was the last page according to total_count, stop
        if page * 100 >= total:
            break

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t",  "--token",         help="GitHub token(s), comma-separated")
    parser.add_argument("-d",  "--domain",         help="Target domain (required)")
    parser.add_argument("-e",  "--extend",         help="Also match substrings of domain", action="store_true")
    parser.add_argument("-s",  "--source",         help="Show source URL for each result",  action="store_true")
    parser.add_argument("-v",  "--verbose",        help="Verbose/debug output",             action="store_true")
    parser.add_argument("-raw","--raw",            help="Raw output (no colors/logs)",      action="store_true")
    parser.add_argument("--sort-once",help="Use only 1 sort order instead of 3 (saves ~66%% of API calls)",action="store_true",)
    parser.add_argument("--dry-pages",help="Stop a file-type query after N consecutive pages with no new subdomains (default: 2)",type=int, default=2,)
    parser.add_argument("-sw", "--search-workers",help="Threads for GitHub API calls (default: tokens × 2)",type=int, default=0,)
    parser.add_argument("-fw", "--fetch-workers",help="Threads for raw content fetching (default: 150)",type=int, default=150,)
    args = parser.parse_args()

    # ── Load tokens ──
    t_tokens = []
    if args.token:
        t_tokens = args.token.split(',')
    elif os.path.isfile(TOKENS_FILE):
        with open(TOKENS_FILE) as f:
            t_tokens = [l.strip() for l in f if l.strip()]

    valid_tokens = [
        t for t in t_tokens
        if t.startswith('ghp_') or t.startswith('github_pat_') or len(t) >= 40
    ]

    for bad in set(t_tokens) - set(valid_tokens):
        if not args.raw:
            sys.stderr.write(color(f"[!] skipping invalid token: {bad[:10]}…\n", 'yellow'))

    if not valid_tokens:
        parser.error('no valid auth tokens found')
    if not args.domain:
        parser.error('domain is missing')

    # ── Sort orders ──
    # CHANGE: --sort-once uses only indexed/desc (most recent, usually best).
    # Default still runs all 3, but users hitting RL should pass --sort-once.
    sort_orders = [{'sort': 'indexed', 'order': 'desc'}] if args.sort_once else [
        {'sort': 'indexed', 'order': 'desc'},
        {'sort': 'indexed', 'order': 'asc'},
        {'sort': '',        'order': 'desc'},
    ]

    n_search = args.search_workers or max(len(valid_tokens) * 3, 30)
    n_fetch  = args.fetch_workers

    if not args.raw:
        sys.stderr.write(color(f"[*] {len(valid_tokens)} token(s) loaded\n", 'green'))
        sys.stderr.write(color(f"[*] search workers: {n_search}  fetch workers: {n_fetch}\n", 'green'))
        sys.stderr.write(color(f"[*] sort orders: {len(sort_orders)}  dry-page stop: {args.dry_pages}\n", 'green'))
        sys.stderr.write(color("[*] GitHub caps at 1000 results (10 pages) per query\n", 'yellow'))

    token_manager = TokenManager(valid_tokens)
    
    parsed = tldextract.extract(args.domain)

    if args.extend:
        base_search   = '%22' + parsed.domain + '%22'
        domain_regexp = (
            r'([0-9a-z_\.\-]+\.([0-9a-z_\-]+)?' +
            parsed.domain +
            r'([0-9a-z_\.\-]+)?\.[a-z]{1,5})'
        )
    else:
        base_search   = '%22' + parsed.domain + '.' + parsed.suffix + '%22'
        domain_regexp = r'(([0-9a-z_\.\-]+)\.' + args.domain.replace('.', r'\.') + ')'

    base_search = base_search.replace('-', '%2D')
    if args.verbose:
        sys.stderr.write(f"Base search   : {base_search}\n")
        sys.stderr.write(f"Regexp        : {domain_regexp}\n")
        sys.stderr.write(f"File types    : {len(FILE_TYPES)}\n")
        sys.stderr.write(f"Sort orders   : {len(sort_orders)}\n")
        sys.stderr.write(f"Dry-page limit: {args.dry_pages}\n")
        sys.stderr.write(f"Search workers: {n_search}\n")
        sys.stderr.write(f"Fetch workers : {n_fetch}\n")

    # ── Two dedicated executors ───────────────────────────────────────────────
    # NOTE: process_file_type is now sequential per file-type (early-stop),
    # but multiple file-types still run in parallel via search_ex.
    with ThreadPoolExecutor(max_workers=n_fetch,  thread_name_prefix="fetch") as fetch_ex, \
         ThreadPoolExecutor(max_workers=n_search, thread_name_prefix="search") as search_ex:

        top_futures = [
            search_ex.submit(
                process_file_type,
                token_manager, base_search,
                ft, so['sort'], so['order'],
                domain_regexp, args.source, args.raw,
                fetch_ex,
                args.dry_pages,
            )
            for so in sort_orders
            for ft in FILE_TYPES
        ]

        if not args.raw:
            sys.stderr.write(
                color(f"[*] {len(top_futures)} top-level tasks submitted\n", 'green')
            )

        for f in as_completed(top_futures):
            try:
                f.result()
            except Exception as e:
                if not args.raw:
                    sys.stderr.write(color(f"[-] task error: {e}\n", 'red'))

    if not args.raw:
        sys.stderr.write(color(f"\n[+] done — {len(t_history)} unique result(s)\n", 'green'))


if __name__ == '__main__':
    main()
