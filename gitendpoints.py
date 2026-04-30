#!/usr/bin/python3

import os
import sys
import re
import time
import requests
import random
import argparse
import threading
import tldextract
from urllib.parse import urlparse
from functools import partial
from colored import fg, bg, attr
from multiprocessing.dummy import Pool

TOKENS_FILE = os.path.dirname(os.path.realpath(__file__))+'/.tokens'
MIN_LENGTH = 5
_url_chars = r'[a-zA-Z0-9\-\.\?\#\$&@%=_:/\]\[]'
_not_url_chars = r'[^a-zA-Z0-9\-\.\?\#\$&@%=_:/\]\[]'
t_endpoints_lock = threading.Lock()
t_endpoints = []
t_history_urls = []
t_history_urls_lock = threading.Lock()
t_exclude = [
    r'^http://$',
    r'^https://$',
    r'^javascript:$',
    r'^tel:$',
    r'^mailto:$',
    r'^text/javascript$',
    r'^application/json$',
    r'^application/javascript$',
    r'^text/plain$',
    r'^text/html$',
    r'^text/x-python$',
    r'^text/css$',
    r'^image/png$',
    r'^image/jpeg$',
    r'^image/x-icon$',
    r'^img/favicon.ico$',
    r'^application/x-www-form-urlencoded$',
    r'/Users/[0-9a-zA-Z\-\_]/Desktop',
    r'www.w3.org',
    r'schemas.android.com',
    r'www.apple.com',
]
t_regexp = [
    r'[\'"\(].*(http[s]?://'+_url_chars+r'*?)[\'"\)]',
    r'[\'"\(](http[s]?://'+_url_chars+r'+)',

    r'[\'"\(]('+_url_chars+r'+\.sdirect'+_url_chars+r'*)',
    r'[\'"\(]('+_url_chars+r'+\.htm'+_url_chars+r'*)',
    r'[\'"\(]('+_url_chars+r'+\.php'+_url_chars+r'*)',
    r'[\'"\(]('+_url_chars+r'+\.asp'+_url_chars+r'*)',
    r'[\'"\(]('+_url_chars+r'+\.js'+_url_chars+r'*)',
    r'[\'"\(]('+_url_chars+r'+\.xml'+_url_chars+r'*)',
    r'[\'"\(]('+_url_chars+r'+\.ini'+_url_chars+r'*)',
    r'[\'"\(]('+_url_chars+r'+\.conf'+_url_chars+r'*)',
    r'[\'"\(]('+_url_chars+r'+\.cfm'+_url_chars+r'*)',

    r'href\s*[.=]\s*[\'"\']('+_url_chars+r'+)',
    r'src\s*[.=]\s*[\'"\']('+_url_chars+r'+)',
    r'url\s*[:=]\s*[\'"\']('+_url_chars+r'+)',

    r'urlRoot\s*[:=]\s*[\'"\']('+_url_chars+r'+)',
    r'endpoint[s]\s*[:=]\s*[\'"\']('+_url_chars+r'+)',
    r'script[s]\s*[:=]\s*[\'"\']('+_url_chars+r'+)',

    r'\.ajax\s*\(\s*[\'"\']('+_url_chars+r'+)',
    r'\.get\s*\(\s*[\'"\']('+_url_chars+r'+)',
    r'\.post\s*\(\s*[\'"\']('+_url_chars+r'+)',
    r'\.load\s*\(\s*[\'"\']('+_url_chars+r'+)',
]

class TokenManager:
    def __init__(self, tokens):
        self.tokens = list(tokens)
        self.lock = threading.Lock()
        self.index = 0
        self.rate_limited_tokens = {}
    
    def get_next_token(self):
        with self.lock:
            if not self.tokens:
                return None
            
            current_time = time.time()
            attempts = 0
            max_attempts = len(self.tokens)
            
            while attempts < max_attempts:
                token = self.tokens[self.index % len(self.tokens)]
                self.index += 1
                attempts += 1
                
                if token in self.rate_limited_tokens:
                    reset_time = self.rate_limited_tokens[token]
                    if current_time < reset_time:
                        continue
                    else:
                        del self.rate_limited_tokens[token]
                
                return token
            
            return None
    
    def mark_rate_limited(self, token, reset_time=None):
        with self.lock:
            if reset_time is None:
                reset_time = time.time() + 60
            self.rate_limited_tokens[token] = reset_time
    
    def get_active_token_count(self):
        with self.lock:
            current_time = time.time()
            active = 0
            for token in self.tokens:
                if token not in self.rate_limited_tokens or current_time >= self.rate_limited_tokens[token]:
                    active += 1
            return active
    
    def get_total_tokens(self):
        with self.lock:
            return len(self.tokens)

def githubApiSearchCode( token_manager, search, page, sort, order ):
    token = token_manager.get_next_token()
    if not token:
        print( "%s[-] all tokens are rate limited, waiting 60 seconds...%s" % (fg('red'),attr(0)) )
        time.sleep(60)
        return githubApiSearchCode(token_manager, search, page, sort, order)
    
    headers = { "Authorization":"token "+token }
    url = 'https://api.github.com/search/code?per_page=100&s=' + sort + '&type=Code&o=' + order + '&q=' + search + '&page=' + str(page)

    try:
        r = requests.get( url, headers=headers, timeout=10 )
        
        remaining = r.headers.get('X-RateLimit-Remaining')
        reset_time = r.headers.get('X-RateLimit-Reset')
        
        if r.status_code == 403:
            json_data = r.json()
            if 'message' in json_data and 'rate limit' in json_data['message'].lower():
                if reset_time:
                    token_manager.mark_rate_limited(token, int(reset_time))
                else:
                    token_manager.mark_rate_limited(token)
                print( "%s[!] token rate limited (403), switching...%s" % (fg('yellow'),attr(0)) )
                return githubApiSearchCode(token_manager, search, page, sort, order)
            else:
                print( "%s[-] API error (403): %s%s" % (fg('red'), json_data.get('message', 'Unknown'), attr(0)) )
                return None
        
        if remaining is not None and int(remaining) == 0:
            print( "%s[!] token nearly exhausted (remaining=0), marking...%s" % (fg('yellow'),attr(0)) )
            if reset_time:
                token_manager.mark_rate_limited(token, int(reset_time))
            else:
                token_manager.mark_rate_limited(token)
        
        json_data = r.json()
        
        if 'documentation_url' in json_data or 'message' in json_data:
            msg = json_data.get('message', '').lower()
            if 'rate limit' in msg or 'abuse' in msg:
                if reset_time:
                    token_manager.mark_rate_limited(token, int(reset_time))
                else:
                    token_manager.mark_rate_limited(token)
                print( "%s[!] rate limit detected, switching token...%s" % (fg('yellow'),attr(0)) )
                return githubApiSearchCode(token_manager, search, page, sort, order)
            else:
                print( "%s[-] API error: %s%s" % (fg('red'), json_data.get('message', 'Unknown'), attr(0)) )
                return None
        
        return json_data
    except Exception as e:
        print( "%s[-] error occurred: %s%s" % (fg('red'),e,attr(0)) )
        return None

def getRawUrl( result ):
    raw_url = result['html_url']
    raw_url = raw_url.replace( 'https://github.com/', 'https://raw.githubusercontent.com/' )
    raw_url = raw_url.replace( '/blob/', '/' )
    return raw_url

def readCode( regexp, source, confirm, relative, alldomains, result ):
    time.sleep( random.random() )
    url = getRawUrl( result )
    with t_history_urls_lock:
        if url in t_history_urls:
            return
        t_history_urls.append( url )
    
    str_output = ''
    t_local_endpoints = []
    code = doGetCode( url )

    if code:
        if source:
            str_output = "\n%s>>> %s%s\n\n" % (fg('yellow'),result['html_url'],attr(0))
        
        all_endpoints = []
        for r in t_regexp:
            edpt = re.findall( r, code, re.IGNORECASE )
            if edpt:
                for endpoint in edpt:
                    endpoint = endpoint.strip()
                    if len(endpoint) >= MIN_LENGTH:
                        all_endpoints.append(endpoint)
        
        for endpoint in all_endpoints:
            exclude_match = False
            for exclude in t_exclude:
                if re.match(exclude, endpoint):
                    exclude_match = True
                    break
            if exclude_match:
                continue
            
            if endpoint.startswith('http'):
                is_relative = False
            else:
                is_relative = True
            
            if not relative and is_relative:
                continue
            
            if endpoint in t_local_endpoints:
                continue
            
            with t_endpoints_lock:
                if not source and endpoint in t_endpoints:
                    continue
            
            if not alldomains and not is_relative:
                try:
                    t_url_parse = urlparse( endpoint )
                    t_host_parse = tldextract.extract( t_url_parse.netloc )
                    domain = t_host_parse.domain
                    sss = re.findall( regexp, t_url_parse.netloc )
                    if not sss:
                        continue
                except Exception as e:
                    sys.stdout.write( "%s[-] error occurred: %s%s\n" % (fg('red'),e,attr(0)) )
                    continue
            
            with t_endpoints_lock:
                t_endpoints.append( endpoint )
            t_local_endpoints.append( endpoint )
            
            if source:
                str_output = str_output + ("%s\n" % endpoint)
            else:
                sys.stdout.write( "%s\n" % endpoint )

    if source and len(t_local_endpoints):
        sys.stdout.write( str_output )


def doGetCode( url ):
    try:
        r = requests.get( url, timeout=5 )
    except Exception as e:
        sys.stdout.write( "%s[-] error occurred: %s%s\n" % (fg('red'),e,attr(0)) )
        return False

    return r.text


parser = argparse.ArgumentParser()
parser.add_argument( "-t","--token",help="your github token (required)" )
parser.add_argument( "-d","--domain",help="domain you are looking for (required)" )
parser.add_argument( "-e","--extend",help="also look for <dummy>example.com", action="store_true" )
parser.add_argument( "-a","--all",help="displays urls of all other domains", action="store_true" )
parser.add_argument( "-r","--relative",help="also displays relative urls", action="store_true" )
parser.add_argument( "-s","--source",help="display urls where endpoints are found", action="store_true" )
parser.add_argument( "-v","--verbose",help="verbose mode, for debugging purpose", action="store_true" )
parser.parse_args()
args = parser.parse_args()

t_tokens = []
if args.token:
    t_tokens = args.token.split(',')
else:
    if os.path.isfile(TOKENS_FILE):
        with open(TOKENS_FILE,'r') as fp:
            t_tokens = [line.strip() for line in fp.readlines() if line.strip()]

if not len(t_tokens):
    parser.error( 'auth token is missing' )

valid_tokens = []
for token in t_tokens:
    if token.startswith('ghp_') or token.startswith('github_pat_') or len(token) >= 40:
        valid_tokens.append(token)
    else:
        print( "%s[!] invalid token format skipped: %s...%s" % (fg('yellow'),token[:10],attr(0)) )

t_tokens = valid_tokens
if not t_tokens:
    parser.error( 'no valid auth tokens found' )

print( "%s[*] loaded %d token(s)%s" % (fg('green'),len(t_tokens),attr(0)) )
print( "%s[*] note: GitHub API limits to 1000 results max (10 pages)%s" % (fg('yellow'),attr(0)) )

if args.source:
    _source = True
else:
    _source = False

if args.domain:
    _domain = args.domain
else:
    parser.error( 'domain is missing' )

if args.relative:
    _relative = True
else:
    _relative = False

if args.all:
    _alldomains = True
else:
    _alldomains = False

t_sort_order = [
    { 'sort':'indexed', 'order':'desc',  },
    { 'sort':'indexed', 'order':'asc',  },
    { 'sort':'', 'order':'desc',  }
]

t_history = []
t_history_urls = []
_search = '"' + _domain + '"'

import tldextract
t_host_parse = tldextract.extract( _domain )

if args.extend:
    _search = '"' + t_host_parse.domain + '"'
else:
    _search = '"' + t_host_parse.domain + '.' + t_host_parse.suffix + '"'

if args.extend:
    _regexp = r'(([0-9a-z_\.\-]+\.)?([0-9a-z_\-]+)?'+t_host_parse.domain+r'([0-9a-z_\.\-]+)?\.[a-z]{1,5})'
    _confirm = t_host_parse.domain
else:
    _regexp = r'((([0-9a-z_\.\-]+)\.)?' + _domain.replace('.',r'\.')+')'
    _confirm = _domain

if args.verbose:
    print( "Search: %s" % _search )
    print( "Regexp: %s" % _regexp)
    print( "Confirm: %s" % _confirm)

token_manager = TokenManager(t_tokens)
pool = Pool(30)
for so in t_sort_order:

    page = 1

    if args.verbose:
        print( '\n----- %s %s\n' % (so['sort'],so['order']) )

    while True:
        active_tokens = token_manager.get_active_token_count()
        if active_tokens == 0:
            print( "%s[-] all tokens exhausted, waiting for reset...%s" % (fg('red'),attr(0)) )
            time.sleep(60)
            continue

        if args.verbose:
            print("page %d (active tokens: %d)" % (page, active_tokens))

        t_json = githubApiSearchCode( token_manager, _search, page, so['sort'], so['order'] )

        if t_json is None:
            if args.verbose:
                print("No response or API error")
            break

        page = page + 1

        if 'items' in t_json and len(t_json['items']):
            total_count = t_json.get('total_count', 0)
            if page == 2:
                print( "%s[*] total results available: %d (max 1000 due to API limit)%s" % (fg('cyan'), total_count, attr(0)) )
            pool.map( partial(readCode,_regexp,_source,_confirm,_relative,_alldomains), t_json['items'] )
        else:
            print( "%s[*] no more results on page %d%s" % (fg('green'), page-1, attr(0)) )
            break

pool.close()
pool.join()
