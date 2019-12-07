#!/usr/bin/env python3

from html.parser import HTMLParser
from collections import OrderedDict
from socket import getaddrinfo, AF_INET6, AF_INET, gaierror
import urllib.request
import urllib.parse 
import argparse


# Implementation of an HTMLParser
# pulls the links out of the 2nd column of table
# specifically designed for Curl DoH wiki page
class LinkParser(HTMLParser):

    def reset(self):
        HTMLParser.reset(self)
        self.extracting = False
        self.links      = []
        self.count      = 0

    def handle_starttag(self, tag, attrs):
        if tag == 'td' or tag == 'a':
            attrs = dict(attrs)   # save us from iterating over the attrs
        if tag == 'td':
            self.extracting = True
            self.count += 1
        elif tag == 'a' and 'href' in attrs and self.extracting and self.count == 2:
            self.links.append(attrs['href'])

    def handle_endtag(self, tag):
        if tag == 'td':
            self.extracting = False
        if tag == 'tr':
            self.count = 0

# parse list of links and enrich data, output dictionary
def parseResults(parser): 
    doh_locations = OrderedDict()
    for url in parser.links:
        purl = urllib.parse.urlparse(url)

        if purl.hostname not in doh_locations:
            doh_locations[purl.hostname] = {'domain': purl.hostname,
                                            'url': purl.geturl()}
        try:
            if purl.hostname:
                ips = set([x[-1][0] for x in getaddrinfo(purl.hostname, None, AF_INET)])
                doh_locations[purl.hostname]['ip'] = ips
        except gaierror:
            doh_locations[purl.hostname]['ip'] = []
            pass

        try:
            ipv6s = set([x[-1][0] for x in getaddrinfo(purl.hostname, None, AF_INET6)])
            doh_locations[purl.hostname]['ipv6'] = [ipv6 for ipv6 in ipv6s if '::ffff' not in ipv6]

        except gaierror:
            doh_locations[purl.hostname]['ipv6'] = []
            pass

    return doh_locations

# support for command line flag parsing
argparser = argparse.ArgumentParser(description=
                'Output indicators on known DoH (DNS over HTTPS) endpoints')
argparser.add_argument('-4', '--ip', help='print only IPv4 addresses',
                    action='store_true')
argparser.add_argument('-6', '--ipv6', help='print only IPv6 addresses',
                    action='store_true')
argparser.add_argument('-u', '--url', help='print only URLs',
                    action='store_true')
argparser.add_argument('-n', '--hostname', help='print only hostnames',
                    action='store_true')
argparser.add_argument('-d', '--delimiter', type=str, default=' ', 
                    help='change delimeter for default output')
#TODO support arbitrary text order output using nargs='*'
args = argparser.parse_args()


# download html of Curl wiki page listing DoH endpoints
req = urllib.request.Request('https://github.com/curl/curl/wiki/DNS-over-HTTPS')
f = urllib.request.urlopen(req)
xhtml = f.read().decode('utf-8')

# feed html to get links out of table
parser = LinkParser()
parser.feed(xhtml)

# enrich the endpoint information
results = parseResults(parser)

if args.ip:
    to_print = set()
    for endpoint,values in results.items():
        for ip in values['ip']:
            to_print.add(ip)
    print('\n'.join(sorted(to_print)))

elif args.ipv6:
    to_print = set()
    for endpoint,values in results.items():
        for ipv6 in values['ipv6']:
            to_print.add(ipv6)
    print('\n'.join(sorted(to_print)))

elif args.url:
    to_print = set()
    for endpoint,values in results.items():
        to_print.add(values['url'])
    print('\n'.join(sorted(to_print)))

elif args.hostname:
    print('\n'.join([i for i in results.keys()]))

else:
    for endpoint,values in results.items():
        for ip in values['ip']:
            print(args.delimiter.join([endpoint, values['url'], ip]))
        for ipv6 in values['ipv6']:
            print(args.delimiter.join([endpoint, values['url'], ipv6]))

