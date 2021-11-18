import argparse
import dataclasses
import datetime
import json
from pathlib import Path
import re
from typing import Optional

from bs4 import BeautifulSoup  # pip install beautifulsoup4
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


@dataclasses.dataclass
class Context:
    """Context from which we can extract features"""
    url: urllib3.util.Url
    page: BeautifulSoup
    whois: whois.WhoisEntry
    current_time: datetime.datetime


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
    return ctx.url.scheme == 'https'


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
        if href.scheme == 'https':
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

        # TODO: maybe also check if there's a favicon.ico on the server root?

        return None


# TODO: trademark


@register_feature('days_since_creation')
def extract_feature_days_since_creation(ctx: Context) -> int:
    """Check the number of days since the domain was created"""
    return int((ctx.current_time - ctx.whois.creation_date).total_seconds() / (60 * 60 * 24))


# TODO: days since update


@register_feature('days_until_expiration')
def extract_feature_days_until_expiration(ctx: Context) -> int:
    """Check the number of days until the domain is set to expire"""
    expiration_date = ctx.whois.expiration_date
    if isinstance(expiration_date, list):
        # ???
        expiration_date = expiration_date[0]
    return int((expiration_date - ctx.current_time).total_seconds() / (60 * 60 * 24))


# TODO: days until certificate expiration


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
            # TODO: is this the correct test here?
            if url.path is not None and '//' in url.path:
                count += 1

    return count


# TODO: url entropy



def parse_args(argv=None) -> argparse.Namespace:
    """
    Parse CLI arguments
    """
    parser = argparse.ArgumentParser(
        description='HTML feature extractor for CS 6262 project')

    input_group = parser.add_argument_group('input',
        description='options related to input')

    input_group.add_argument('url', type=urllib3.util.parse_url,
        help='URL of the page (needed to count things like "external images")')

    html_source_group = input_group.add_mutually_exclusive_group(required=True)
    html_source_group.add_argument('--active-html-download', action='store_true',
        help='download the HTML source from the URL')
    html_source_group.add_argument('--html', type=Path,
        help='use the provided HTML source file')

    whois_source_group = input_group.add_mutually_exclusive_group(required=True)
    whois_source_group.add_argument('--active-whois-download', action='store_true',
        help='download the whois data from the URL')
    # no option to load whois data locally yet, sorry

    # TODO: option to specify the "current time" instead of using system time?

    input_group.add_argument('--encoding', default='utf-8',
        help='override the encoding of the HTML file (default: utf-8) (ignored if using --download)')

    output_group = parser.add_argument_group('output',
        description='options related to output')

    output_group.add_argument('--output', type=Path,
        help='JSON file to save output to (if not specified, write to stdout)')


    return parser.parse_args(argv)


def main(argv=None) -> None:

    args = parse_args(argv)

    if args.active_html_download:
        html = requests.get(args.url.url).text
    else:
        html = args.html.read_text(encoding=args.encoding)

    ctx = Context(
        args.url,
        BeautifulSoup(html, 'html.parser'),
        whois.whois(args.url.url),
        datetime.datetime.now())

    result = {key: func(ctx) for key, func in FeatureExtractors.items()}

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=4)
    else:
        print(json.dumps(result, indent=4))


if __name__ == '__main__':
    main()
