import argparse
import ast
from collections import Counter
import concurrent.futures
import dataclasses
import datetime
import json
import math
from pathlib import Path
import re
import ssl
import traceback
from typing import Iterator, Optional, TextIO, Tuple

from bs4 import BeautifulSoup  # pip install beautifulsoup4
import M2Crypto  # sudo apt install swig; pip install M2Crypto
import requests  # pip install requests
import urllib3.util  # pip install urllib3
import whois  # pip install python-whois


# https://ihateregex.io/expr/ip
REGEX_IPV4 = re.compile(r'(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}')
REGEX_IPV6 = re.compile(r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))')


URL_SHORTENERS = {
    'tinyurl.com',
    'tiny.cc',
    'is.gd',
    'bit.ly',
    'lc.chat',
    'soo.gd',
    'clicky.me',
    'goo.gl',
    'budurl.com',
    's2r.co',
}

# Trademarks list verified with the US Patent and Trademark Office (uspto.gov)
# The following most popular and common firms, companies, institutions, and services providers
# hold an active registration of their trademark with the US Patent and Trademark Office.
TRADEMARKS = {
    '4chan', 'abcnews', 'accuweather', 'adobe', 'airbnb', 'alibaba', 'aliexpress', 'alliantenergy',
    'allrecipes', 'amazon', 'americanexpress', 'angieslist', 'arstechnica', 'atlassian', 'atmosenergy',
    'audible', 'azlyrics', 'baidu', 'bankofamerica', 'barnesandnoble', 'bedbathandbeyond', 'bestbuy',
    'bhphotovideo', 'biblegateway', 'bizjournals', 'bleacherreport', 'blogger', 'blogspot', 'bloomberg',
    'bongacams', 'booking', 'breitbart', 'britishgas', 'businessinsider', 'buzzfeed', 'capitalone',
    'capitalone360', 'cargurus', 'cbslocal', 'cbsnews', 'cbssports', 'chaturbate', 'chevron',
    'chicagotribune', 'citibankonline', 'comcast', 'comenity', 'concursolutions', 'conservativetribune',
    'costco', 'craigslist', 'creditkarma', 'crooksandliars', 'crunchyroll', 'custhelp', 'dailykos',
    'dailymail', 'dailymotion', 'darpa', 'delta', 'democraticunderground', 'deviantart',
    'dickssportinggoods', 'diply', 'discovercard', 'disney', 'diynetwork', 'docusign', 'donaldjtrump',
    'dropbox', 'drudgereport', 'duckduckgo', 'duke-energy', 'ebates', 'edfenergy', 'eventbrite',
    'eversource', 'expedia', 'exxonmobil', 'facebook', 'fbcdn', 'fedex', 'feedly', 'fidelity',
    'firstenergycorp', 'fitbit', 'fivethirtyeight', 'flickr', 'forbes', 'foxnews', 'gamepedia', 'gamestop',
    'gawker', 'geico', 'gfycat', 'giphy', 'github', 'gizmodo', 'godaddy', 'gofundme', 'goodhousekeeping',
    'google', 'groupon', 'halliburton', 'harvard', 'hbogo', 'hbonow', 'hclips', 'hilton', 'homedepot',
    'hotnewhiphop', 'houzz', 'howtogeek', 'huffingtonpost', 'humblebundle', 'icims', 'icloud', 'imgur',
    'indiatimes', 'infusionsoft', 'instagram', 'instructables', 'instructure', 'investopedia', 'jalopnik',
    'jcpenney', 'jezebel', 'kaiserpermanente', 'khanacademy', 'kickstarter', 'kinja', 'kissanime', 'kohls',
    'kotaku', 'latimes', 'lifebuzz', 'lifehacker', 'linkedin', 'livejasmin', 'lowes', 'mariott', 'mashable',
    'mayoclinic', 'microsoft', 'motherjones', 'mozilla', 'myfitnesspal', 'naver', 'nbcnews', 'nbcsports',
    'netflix', 'newegg', 'nexusmods', 'nordstrom', 'norton', 'nymag', 'nypost', 'nytimes', 'officedepot',
    'okcupid', 'onclickads', 'outbrain', 'overstock', 'ozock', 'papajohns', 'patheos', 'paypal',
    'photobucket', 'pinterest', 'pixnet', 'pizzahut', 'politico', 'popads', 'pornhub', 'progress-energy',
    'putlocker', 'qualtrics', 'quizlet', 'quora', 'realclearpolitics', 'realtor', 'reddit', 'redfin',
    'redtube', 'retailmenot', 'reuters', 'roblox', 'salesforce', 'samsclub', 'samsung', 'schneider-electric',
    'schwab', 'searchincognito', 'sears', 'sephora', 'sfgate', 'shopify', 'shutterfly', 'shutterstock',
    'signupgenius', 'skype', 'slickdeals', 'slideshare', 'smugmug', 'solarcity', 'soundcloud', 'southwest',
    'spotify', 'stackexchange', 'stackoverflow', 'stanford', 'staples', 'starbucks', 'stubhub', 'suntrust',
    'surveymonkey', 'swagbucks', 'taboola', 'talkingpointsmemo', 'tdbank', 'thameswater', 'thedailybeast',
    'theguardian', 'thekitchn', 'thepennyhoarder', 'thepiratebay', 'ticketmaster', 'timewarnercable',
    'tomshardware', 'toysrus', 'travelocity', 'trello', 'tripadvisor', 'trulia', 'tumblr', 'twitch',
    'twitter', 'upornia', 'upstreamonline', 'urbandictionary', 'usatoday', 'verizon', 'victoriassecret',
    'vimeo', 'w3schools', 'walgreens', 'walmart', 'washingtonpost', 'wayfair', 'webex', 'webmd', 'weebly',
    'wellsfargo', 'whatsapp', 'wikia', 'wikihow', 'wikimedia', 'wikipedia', 'wittyfeed', 'wordpress',
    'wunderground', 'xfinity', 'xhamster', 'xvideos', 'yahoo', 'youporn', 'youtube', 'zappos', 'zillow',
    'zulily'}


@dataclasses.dataclass
class Context:
    """Context from which we can extract features"""
    url: urllib3.util.Url
    page: BeautifulSoup
    whois: Optional[whois.WhoisEntry]
    certificate: Optional[M2Crypto.X509.X509]
    accessed_time: datetime.datetime


def difference_in_days(datetime_1: datetime.datetime, datetime_2: datetime.datetime) -> int:
    """Return the number of days difference between the two datetimes"""
    return int((datetime_2 - datetime_1).total_seconds() / (60 * 60 * 24))


def get_port_from_url(url: urllib3.util.Url, default:int=None) -> int:
    """Get the port number from a URL, using an appropriate default if
    it doesn't explicitly specify one
    """
    if url.port is not None:
        return url.port

    if default is not None:
        return default

    return 443 if url.scheme.lower() == 'https' else 80


def download_x509(url: urllib3.util.Url) -> Optional[M2Crypto.X509.X509]:
    """Download a remote server's X509 cert, ignoring validation errors
    as much as possible
    """
    def fake_check(*args, **kwargs) -> bool:
        return True

    def try_with_protocol(protocol_name: str) -> M2Crypto.X509.X509:
        ctx = M2Crypto.SSL.Context(
            protocol=protocol_name,
            weak_crypto=True,
            post_connection_check=fake_check)

        conn = M2Crypto.SSL.Connection(ctx)
        conn.connect((url.host, get_port_from_url(url)))

        return conn.get_peer_cert()

    try:
        return try_with_protocol('tls')
    except M2Crypto.SSL.SSLError:
        try:
            return try_with_protocol('sslv23')
        except Exception:
            return None


FeatureExtractors = {}

def register_feature(name: str):
    """Decorator that registers a function as a feature extractor"""
    def decorator(func):
        FeatureExtractors[name] = func
        return func
    return decorator


@register_feature('url_length')
def extract_feature_url_length(ctx: Context) -> int:
    """Measure the length of the URL"""
    return len(ctx.url.url)


@register_feature('is_https')
def extract_feature_is_https(ctx: Context) -> bool:
    """Measure the length of the URL"""
    return ctx.url.scheme.lower() == 'https'


@register_feature('ip_in_url')
def extract_feature_ip_in_url(ctx: Context) -> bool:
    """Check if the URL contains an IP address"""
    # Checking if an IP address appears *anywhere* in the URL, since
    # it's suspicious regardless of whether it's the actual host or not
    return bool(REGEX_IPV4.search(ctx.url.url) or REGEX_IPV6.search(ctx.url.url))


@register_feature('num_external_images')
def extract_feature_num_external_images(ctx: Context) -> int:
    """Count the number of external images on the page"""
    this_domain = ctx.url.host

    count = 0
    for tag in ctx.page.find_all('img'):
        img_src = urllib3.util.parse_url(tag.get('src'))
        if img_src.host is not None and img_src.host.lower() != this_domain.lower():
            # External image
            count += 1

    # TODO: also consider CSS?

    return count


@register_feature('num_https_links')
def extract_feature_num_https_links(ctx: Context) -> int:
    """Count the number of HTTPS links"""
    count = 0
    for tag in ctx.page.find_all('a'):
        href = urllib3.util.parse_url(tag.get('href'))

        scheme = href.scheme
        if scheme is None:
            # relative link
            scheme = ctx.url.scheme

        if scheme.lower() == 'https':
            count += 1

    return count


@register_feature('num_images')
def extract_feature_num_images(ctx: Context) -> int:
    """Count the number of images (<img>) on the page"""
    return len(ctx.page.find_all('img'))


@register_feature('favicon_matches')
def extract_feature_favicon_matches(ctx: Context) -> Optional[bool]:
    """Check whether the favicon is from the same domain"""
    link = ctx.page.find('link', rel=re.compile(r'.*shortcut.*'))

    if link:
        favicon_domain = urllib3.util.parse_url(link.get('href')).host
        if favicon_domain is None:
            # relative link -- implicitly on same domain
            return True

        return favicon_domain.lower() == ctx.url.host.lower()

    else:
        # no favicon found

        return None


@register_feature('has_trademark')
def extract_feature_has_trademark(ctx: Context) -> bool:
    """Check if any common trademarks appear in the URL"""
    # ctx.url.url is a dynamic property, so reusing a string should be
    # more efficient
    url = ctx.url.url

    for tm in TRADEMARKS:
        if tm in url:
            return True

    return False


@register_feature('days_since_creation')
def extract_feature_days_since_creation(ctx: Context) -> Optional[int]:
    """Check the number of days since the domain was created"""
    if ctx.whois is None:
        return None

    creation_date = ctx.whois.creation_date

    if isinstance(creation_date, list):
        # ???
        creation_date = creation_date[0]

    if creation_date is None:
        return None

    if creation_date.tzinfo is None:
        # assume UTC if not specified
        creation_date = creation_date.replace(tzinfo=datetime.timezone.utc)

    return difference_in_days(creation_date, ctx.accessed_time)


@register_feature('days_since_last_update')
def extract_feature_days_since_last_update(ctx: Context) -> Optional[int]:
    """Check the number of days since the domain was last updated"""
    if ctx.whois is None:
        return None

    updated_date = ctx.whois.updated_date

    if isinstance(updated_date, list):
        # ???
        updated_date = updated_date[0]

    if updated_date is None:
        return None

    if updated_date.tzinfo is None:
        # assume UTC if not specified
        updated_date = updated_date.replace(tzinfo=datetime.timezone.utc)

    return difference_in_days(updated_date, ctx.accessed_time)


@register_feature('days_until_expiration')
def extract_feature_days_until_expiration(ctx: Context) -> int:
    """Check the number of days until the domain is set to expire"""
    if ctx.whois is None:
        return None

    expiration_date = ctx.whois.expiration_date

    if isinstance(expiration_date, list):
        # ???
        expiration_date = expiration_date[0]

    if expiration_date is None:
        return None

    if expiration_date.tzinfo is None:
        # assume UTC if not specified
        expiration_date = expiration_date.replace(tzinfo=datetime.timezone.utc)

    return difference_in_days(ctx.accessed_time, expiration_date)


@register_feature('days_until_cert_expiration')
def extract_feature_days_until_cert_expiration(ctx: Context) -> Optional[int]:
    """Check the number of days until the domain certificate is set to
    expire. https://stackoverflow.com/a/7691293
    """
    if ctx.certificate is None:
        return None
    else:
        expiration_date = ctx.certificate.get_not_after().get_datetime()
        return difference_in_days(ctx.accessed_time, expiration_date)


@register_feature('num_links')
def extract_feature_num_links(ctx: Context) -> int:
    """Count the number of links (<a>) on the page"""
    return len(ctx.page.find_all('a'))


@register_feature('mean_link_length')
def extract_feature_mean_link_length(ctx: Context) -> Optional[float]:
    """Calculate the average link length"""
    hrefs = []
    for tag in ctx.page.find_all('a'):
        if tag.get('href'):
            hrefs.append(tag['href'])
    if hrefs:
        return sum(len(href) for href in hrefs) / len(hrefs)
    else:
        return None


@register_feature('num_shortened_urls')
def extract_feature_num_shortened_urls(ctx: Context) -> int:
    """Count the number of links using known URL shorteners"""
    count = 0
    for tag in ctx.page.find_all('a'):
        if tag.get('href'):
            url = urllib3.util.parse_url(tag['href'])
            if url.host is not None and url.host.lower() in URL_SHORTENERS:
                count += 1

    return count


@register_feature('num_double_slash_redirects')
def extract_feature_num_double_slash_redirects(ctx: Context) -> int:
    """Count the number of links with double-slash redirects"""
    count = 0
    for tag in ctx.page.find_all('a'):
        if tag.get('href'):
            url = urllib3.util.parse_url(tag['href'])
            if url.path is not None and '//' in url.path:
                count += 1

    return count


@register_feature('url_entropy')
def extract_feature_url_entropy(ctx: Context) -> float:
    """Calculate URL entropy"""
    p, lns = Counter(ctx.url), len(ctx.url)
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())


def iter_phish_urls(file: TextIO, limit:int=None) -> Iterator[urllib3.util.Url]:
    """Iterate over URLs from a phish-type file"""
    for i, item in enumerate(ast.literal_eval(file.read())):
        if limit is not None and i >= limit:
            break

        if 'url' in item:
            yield urllib3.util.parse_url(item['url'])


def iter_tranco_urls(file: TextIO, limit:int=None) -> Iterator[urllib3.util.Url]:
    """Iterate over URLs from a Tranco-type file"""
    for i, line in enumerate(file):
        if limit is not None and i >= limit:
            break

        line = line.strip()
        split = line.split(',')
        yield urllib3.util.parse_url(split[1])


def parse_args(argv=None) -> argparse.Namespace:
    """
    Parse CLI arguments
    """
    parser = argparse.ArgumentParser(
        description='HTML feature extractor for CS 6262 project')

    DEFAULT_CONN_TIMEOUT = 5
    parser.add_argument('--connection-timeout', type=int, default=DEFAULT_CONN_TIMEOUT,
        help=f'set the connection timeout in seconds (default: {DEFAULT_CONN_TIMEOUT})')

    subparsers = parser.add_subparsers(dest='subparser_name', required=True)

    single_parser = subparsers.add_parser('single',
        help='analyze a single URL')

    input_group = single_parser.add_argument_group('input',
        description='options related to input')

    input_group.add_argument('url', type=urllib3.util.parse_url,
        help='URL of the page')

    html_source_group = input_group.add_mutually_exclusive_group(required=True)
    html_source_group.add_argument('--active-html-download', action='store_true',
        help='download the HTML source from the URL')
    html_source_group.add_argument('--html', type=Path,
        help='use the provided HTML source file (no network access will be performed for this step)')

    whois_source_group = input_group.add_mutually_exclusive_group(required=True)
    whois_source_group.add_argument('--active-whois-download', action='store_true',
        help='download the whois data from the URL')
    whois_source_group.add_argument('--whois', type=Path,
        help='use the provided whois text file (no network access will be performed for this step)')

    cert_source_group = input_group.add_mutually_exclusive_group(required=True)
    cert_source_group.add_argument('--active-certificate-download', action='store_true',
        help='download the certificate data from the URL')
    cert_source_group.add_argument('--certificate', type=Path,
        help='use the provided X.509 certificate PEM file (no network access will be performed for this step)')

    time_source_group = input_group.add_mutually_exclusive_group(required=True)
    time_source_group.add_argument('--current-time', action='store_true',
        help='use the current time as the page-access time')
    time_source_group.add_argument('--time', type=datetime.datetime.fromisoformat,
        help='use the provided ISO time as the page-access time')

    input_group.add_argument('--encoding', default='utf-8',
        help='override the encoding of the HTML file (default: utf-8) (only used if --html is specified)')

    output_group = single_parser.add_argument_group('output',
        description='options related to output')

    output_group.add_argument('--output', type=Path,
        help='JSON file to save output to (if not specified, write to stdout)')

    debug_group = single_parser.add_argument_group('debug',
        description='options related to debug output')
    debug_group.add_argument('--save-html', type=Path,
        help='save analyzed HTML document to this file (utf-8)')
    debug_group.add_argument('--save-whois', type=Path,
        help='save analyzed whois data to this file')
    debug_group.add_argument('--save-certificate', type=Path,
        help='save analyzed certificate PEM data to this file')
    debug_group.add_argument('--save-time', type=Path,
        help='save analyzed ISO timestamp to this file')

    multi_parser = subparsers.add_parser('multi',
        help='analyze URLs from a file')

    multi_parser.add_argument('input_type', choices=['phish', 'tranco'],
        help='type of input file')
    multi_parser.add_argument('input_file', type=Path,
        help='input file')
    multi_parser.add_argument('output_file', type=Path,
        help='JSON Lines (https://jsonlines.org/) file to save output to')
    multi_parser.add_argument('--limit', type=int, metavar='N',
        help='only analyze the first N URLs')
    DEFAULT_NUM_THREADS = 20
    multi_parser.add_argument('--max-threads', type=int, metavar='N', default=DEFAULT_NUM_THREADS,
        help=f'number of threads to use for concurrent connections (default: {DEFAULT_NUM_THREADS})')

    return parser.parse_args(argv)


def main_single(args: argparse.Namespace) -> None:
    """Handle the "single" command"""
    # URL
    url = args.url

    # HTML
    if args.active_html_download:
        html = requests.get(url.url, timeout=args.connection_timeout).text
    else:
        html = args.html.read_text(encoding=args.encoding)

    # Whois
    if args.active_whois_download:
        try:
            whois_entry = whois.whois(url.url)
        except whois.parser.PywhoisError:
            whois_entry = None
    else:
        whois_entry = whois.parser.WhoisEntry.load(url.url, args.whois.read_text(encoding='utf-8'))

    # Certificate
    if args.active_certificate_download:
        cert = download_x509(url)
    else:
        cert = M2Crypto.X509.load_cert(str(args.certificate))

    # Time
    if args.current_time:
        time = datetime.datetime.now(datetime.timezone.utc)
    else:
        time = args.time
        if time.tzinfo is None:
            # assume current timezone
            time = time.replace(tzinfo=datetime.datetime.now(datetime.timezone.utc).astimezone().tzinfo)

    assert time.tzinfo is not None, 'naive datetimes are not allowed'

    # Optional debug output
    if args.save_html is not None:
        args.save_html.write_text(html, encoding='utf-8')
    if args.save_whois is not None:
        args.save_whois.write_text(whois_entry.text, encoding='utf-8')
    if args.save_certificate is not None:
        args.save_certificate.write_bytes(pem)
    if args.save_time is not None:
        args.save_time.write_text(time.isoformat(), encoding='utf-8')

    ctx = Context(
        url,
        BeautifulSoup(html, 'html.parser'),
        whois_entry,
        cert,
        time)

    result = {'url': url.url}
    result.update({key: func(ctx) for key, func in FeatureExtractors.items()})

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=4)
    else:
        print(json.dumps(result, indent=4))


def main_multi(args: argparse.Namespace) -> None:
    """Handle the "multi" command"""

    if args.input_type == 'phish':
        iter_func = iter_phish_urls
    elif args.input_type == 'tranco':
        iter_func = iter_tranco_urls
    else:
        raise ValueError(f'Unknown input file type: "{args.input_type}"')

    def handle_url(url: urllib3.util.Url) -> Tuple[urllib3.util.Url, Optional[dict]]:
        """Process one URL (thread entrypoint)"""
        # Add "https://" if no scheme was specified
        if url.scheme is None:
            url = url._replace(scheme='https')

        failure_return_value = (url, None)

        try:
            try:
                html = requests.get(url.url, timeout=args.connection_timeout).text
            except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
                # just return None instead of spamming the console with "couldn't connect" errors
                return failure_return_value

            try:
                whois_entry = whois.whois(url.url)
            except whois.parser.PywhoisError:
                whois_entry = None

            # Download certificate if available (may return None)
            cert = download_x509(url)

            # Create context
            ctx = Context(
                url,
                BeautifulSoup(html, 'html.parser'),
                whois_entry,
                cert,
                datetime.datetime.now(datetime.timezone.utc))

            # Run analysis and build result dict
            result = {'url': url.url}
            result.update({key: func(ctx) for key, func in FeatureExtractors.items()})

            return url, result

        except Exception:
            traceback.print_exc()
            return failure_return_value

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=args.max_threads)

    with args.input_file.open('r', encoding='utf-8') as f_in:
        with args.output_file.open('w', encoding='utf-8') as f_out:
            for i, (url, result_dict) in enumerate(executor.map(handle_url, iter_func(f_in, args.limit))):
                if result_dict is None:
                    print(f'Error while analyzing {url.url} (skipping...)')
                else:
                    f_out.write(json.dumps(result_dict, separators=(',', ':')))
                    f_out.write('\n')
                    print(f'Finished analyzing {url.url}')


def main(argv=None) -> None:
    """Main function"""

    args = parse_args(argv)

    if args.subparser_name == 'single':
        main_single(args)
    elif args.subparser_name == 'multi':
        main_multi(args)
    else:
        print('No command specified...?')


if __name__ == '__main__':
    main()
