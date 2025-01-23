#!/usr/bin/env python3

import argparse
import configparser
import os
import sys

from dns import resolver
from dotenv import load_dotenv
from termcolor import cprint

from api.client import Client
from api.digitalocean import DigitalOceanAPI, AuthException, APIException
from api.namecom import NamecomAPI
from api.porkbun import PorkbunAPI
from audits import rdns, caa, cname, mail
from eprint import eprint


class Auditor(object):
    _policy: configparser.ConfigParser
    _verbose: bool
    _resolver: resolver.Resolver
    _api_client: Client

    def __init__(self, p: configparser.ConfigParser, v: bool, cli: Client):
        self._policy = p
        self._api_client = cli
        self._verbose = v
        self._resolver = resolver.Resolver(configure=False)
        self._resolver.nameservers = [
            "8.8.8.8",
            "1.1.1.1",
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
        ]

    def audit_all(self):
        """
        Returns False if any failures or anomalies were found; True otherwise.
        """
        retv = True
        domains = list(self._api_client.get_all_domains())
        for d in domains:
            retv = retv & self.audit(d)
        return retv

    def audit(self, d: str):
        """
        Returns False if any failures or anomalies were found; True otherwise.
        """
        cprint("Auditing {:s} ...".format(d), "white")
        retv = True
        all_records = list(self._api_client.get_all_dns_records(d))

        retv = retv & rdns.audit(
            policy["rdns"], self._resolver, self._verbose, all_records
        )
        retv = retv & mail.audit(
            policy["mail"], self._resolver, self._verbose, all_records
        )
        retv = retv & caa.audit(policy["caa"], self._verbose, all_records)
        retv = retv & cname.audit(self._resolver, self._verbose, all_records)

        if retv:
            cprint("... OK", "green")
        else:
            cprint("... FAIL", "red")
        return retv


if __name__ == "__main__":
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="Check your DNS records for a variety of potential issues"
    )
    parser.add_argument(
        "--domain",
        type=str,
        help="The domain to audit. "
        "If left empty, all domains in the account will be audited.",
    )
    parser.add_argument(
        "--debug-log-ratelimit",
        action="store_true",
        help="Log API rate limit information to stderr.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print each check as it is performed, regardless of outcome.",
    )
    parser.add_argument("--policy", type=str, help="INI policy file.")
    parser.add_argument(
        "--host",
        type=str,
        default="do",
        help="Hosting service for your DNS records. One of: do (DigitalOcean), pb (Porkbun), nc (Name.com).",
    )
    args = parser.parse_args()

    client = None
    if args.host == "do":
        do_token = os.getenv("DIGITALOCEAN_TOKEN")
        if not do_token:
            cprint(
                "DigitalOcean API token must be set using an environment variable.",
                "red",
                file=sys.stderr,
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
                "red",
                file=sys.stderr,
            )
            eprint("Check your credentials and try again.")
            sys.exit(2)
        except APIException as e:
            cprint(
                "DigitalOcean authentication check failed.",
                "red",
                file=sys.stderr,
            )
            eprint(e.human_str)
            sys.exit(2)
        client = do_api
    elif args.host == "pb":
        pb_api_key = os.getenv("PORKBUN_API_KEY")
        pb_secret_key = os.getenv("PORKBUN_SECRET_KEY")
        if not pb_api_key or not pb_secret_key:
            cprint(
                "Porkbun API key and secret must be set using environment variables.",
                "red",
                file=sys.stderr,
            )
            eprint("Copy .env.sample to .env and fill it out to provide credentials.")
            sys.exit(2)
        client = PorkbunAPI(pb_api_key, pb_secret_key)
    elif args.host == "nc":
        nc_username = os.getenv("NAMECOM_USERNAME")
        nc_tok = os.getenv("NAMECOM_API_TOKEN")
        if not nc_username or not nc_tok:
            cprint(
                "Name.com username and API token must be set using environment variables.",
                "red",
                file=sys.stderr,
            )
            eprint("Copy .env.sample to .env and fill it out to provide credentials.")
            sys.exit(2)
        client = NamecomAPI(nc_username, nc_tok)

    if not client:
        eprint("Invalid --host given.")
        sys.exit(1)

    policy = configparser.ConfigParser()
    policy["rdns"] = {
        "FailOnMissingPTR": "no",
    }
    policy["caa"] = {
        "RequireIssue": "no",
        "RequireIodef": "no",
    }
    policy["mail"] = {
        "RequireSPF": "no",
        "RequireDMARC": "no",
    }
    if args.policy:
        policy.read(args.policy)

    auditor = Auditor(policy, args.verbose, client)

    domain_name = None
    if args.domain:
        domain_name = args.domain.lower().strip()

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
            "Check your credentials and try again.",
            "red",
            file=sys.stderr,
        )
        sys.exit(2)

    if not result:
        sys.exit(3)
