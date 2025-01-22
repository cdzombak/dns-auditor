#!/usr/bin/env python3

import argparse
import configparser
import os
import sys

from dns import resolver
from dotenv import load_dotenv
from termcolor import cprint

from audits import rdns
from digitalocean_api import DigitalOceanAPI
from eprint import eprint
from exc import AuthException, APIException


class Auditor(object):
    verbose: bool

    def __init__(self, policy, do_api_instance):
        self.policy = policy
        self.do_api = do_api_instance
        self.verbose = False
        self.resolver = resolver.Resolver(configure=False)
        self.resolver.nameservers = [
            '8.8.8.8', '1.1.1.1',
            '2001:4860:4860::8888', '2606:4700:4700::1111',
        ]

    def audit_all(self):
        """
        Returns False if any anomalies were found; True otherwise.
        """
        domain_names = [d['name'] for d in self.do_api.get_all_domains()]
        retv = True
        for n in domain_names:
            retv = retv & self.audit(n)
        return retv

    def audit(self, domain_name: str):
        """
        Returns False if any anomalies were found; True otherwise.
        """
        cprint("Auditing {:s} ...".format(domain_name), 'white')
        all_records = self.do_api.get_all_dns_records(domain_name)
        retv = True
        retv = retv and rdns.audit(policy['rdns'], self.resolver, self.verbose, all_records)
        if retv:
            cprint("... ok", 'green')
        return retv


if __name__ == '__main__':
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="Check a domain's A and AAAA records against rDNS for the IPs they point to.",
        epilog="Authentication:  Set your DigitalOcean API token in the DIGITALOCEAN_TOKEN "
               "environment variable. It can also be provided via a .env file, in this directory "
               "(see .env.sample).")
    parser.add_argument('--domain', type=str,
                        help="The domain to audit. "
                             "If left empty, all domains in the account will be audited.")
    parser.add_argument('--fail-return', type=int, default=3,
                        help="Return code in case audit problems were detected. Default: 3.")
    parser.add_argument('--debug-log-ratelimit', action='store_true',
                        help="Log API rate limit information to stderr.")
    parser.add_argument('--verbose', action='store_true',
                        help="Print each check as it is performed, regardless of outcome.")
    parser.add_argument('--policy', type=str,
                        help="INI policy file.")
    args = parser.parse_args()

    if args.fail_return in (1, 2):
        cprint(
            "Error: Return codes 1 and 2 are reserved for general "
            "and authentication errors, respectively.",
            'red', file=sys.stderr,
        )
        sys.exit(1)

    do_token = os.getenv('DIGITALOCEAN_TOKEN')
    if not do_token:
        cprint(
            "DigitalOcean API token must be set using an environment variable.",
            'red', file=sys.stderr,
        )
        eprint("Copy .env.sample to .env and fill it out to provide credentials.")
        sys.exit(2)
    do_api = DigitalOceanAPI(do_token)
    do_api.logRatelimit = args.debug_log_ratelimit
    try:
        do_api.check_auth()
    except AuthException:
        cprint(
            "DigitalOcean authentication check failed.",
            'red', file=sys.stderr,
        )
        eprint("Check your credentials and try again.")
        sys.exit(2)
    except APIException as e:
        cprint(
            "DigitalOcean authentication check failed.",
            'red', file=sys.stderr,
        )
        eprint(e.human_str)
        sys.exit(2)

    policy = configparser.ConfigParser()
    policy['rdns'] = {
        'FailOnMissingPTR': 'no',
    }
    if args.policy:
        policy.read(args.policy)

    domain_name = None
    if args.domain:
        domain_name = args.domain.lower().strip()
    auditor = Auditor(policy, do_api)
    auditor.verbose = args.verbose
    try:
        if domain_name:
            result = auditor.audit(domain_name)
        else:
            result = auditor.audit_all()
    except APIException as e:
        eprint(e.human_str)
        sys.exit(1)
    except AuthException:
        cprint(
            "Check your DigitalOcean credentials and try again.",
            'red', file=sys.stderr,
        )
        sys.exit(2)

    if not result:
        sys.exit(args.fail_return)
