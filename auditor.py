#!venv/bin/python3

import argparse
import datetime
import json
import os
import requests
import sys
from dns import name, resolver, reversename

from dotenv import load_dotenv
load_dotenv()


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


class AuthException(Exception):
    pass


class APIException(Exception):

    def __init__(self, message=None, status_code=None, errors=None, url=None, method=None):
        if errors and not message:
            message = json.dumps(errors)
        super(APIException, self).__init__(message)
        self.message = message
        self.status_code = status_code
        self.errors = errors or []
        self.url = url
        self.method = method

    @property
    def human_str(self):
        return 'API Error: {msg:s}\n{method:s}: {url:s}\nHTTP Status: {status}\nError Detail:\n{detail}'.format(
            msg=self.__str__(),
            status=self.status_code or '[unknown]',
            detail=json.dumps(self.errors, sort_keys=True, indent=2),
            method='HTTP {}'.format(self.method or '[unknown method]'),
            url=self.url or '[URL unknown]'
        )


class HTTPBearerAuth(requests.auth.AuthBase):

    def __init__(self, token):
        self.token = token

    def __eq__(self, other):
        return isinstance(other, HTTPBearerAuth) \
            and self.token == other.token

    def __ne__(self, other):
        return not self == other

    def __call__(self, r):
        r.headers['Authorization'] = 'Bearer ' + self.token
        return r


class DigitalOceanAPI(object):

    API_BASE = 'https://api.digitalocean.com/v2'

    def __init__(self, token):
        self.auth = HTTPBearerAuth(token)

    def _check_response(self, r):
        if r.status_code in (401, 403):
            raise AuthException()
        if r.status_code not in (200, 201, 202, 203, 204):
            decoded = r.json()
            raise APIException(
                message=decoded.get('message'),
                status_code=r.status_code,
                method=r.request.method,
                errors=[decoded.get('id', 'no additional detail available')],
                url=r.request.url,
            )

    def _get(self, endpoint, params=None):
        url = '{base:s}/{endpoint:s}'.format(base=DigitalOceanAPI.API_BASE, endpoint=endpoint)
        resp = requests.get(url, auth=self.auth, params=params)
        # self._log_ratelimit(resp)
        self._check_response(resp)
        return resp

    def _get_decoded(self, endpoint, params=None):
        return self._get(endpoint, params).json()

    def _log_ratelimit(self, response):
        ratelimit = response.headers.get('RateLimit-Limit')
        remaining = response.headers.get('RateLimit-Remaining')
        reset = response.headers.get('RateLimit-Reset')
        if not ratelimit or not remaining or not reset:
            return
        reset_dt = datetime.datetime.utcfromtimestamp(int(reset.strip()))\
            .replace(tzinfo=datetime.timezone.utc)
        eprint(" -  DO Rate Limit: {:s}/{:s} remain; reset {:s}".format(
            remaining, ratelimit, reset_dt.isoformat(' ')))

    def check_auth(self):
        return self._get_decoded('account')

    def get_all_domains(self):
        return self._get_decoded('domains')['domains']

    def get_all_dns_records(self, domain):
        return self._get_decoded('domains/{name:s}/records'.format(name=domain))['domain_records']


class Auditor(object):

    def __init__(self, do_api):
        self.do_api = do_api
        self.resolver = resolver.Resolver(configure=False)
        self.resolver.nameservers = ['8.8.8.8', '8.8.4.4']

    def audit_all(self):
        """
        Returns False if any anomalies were found; True otherwise.
        """
        domain_names = [d['name'] for d in self.do_api.get_all_domains()]
        retv = True
        for n in domain_names:
            retv = retv & self.audit(n)
        return retv

    def audit(self, domain_name):
        """
        Returns False if any anomalies were found; True otherwise.
        """
        print("Auditing {:s}...".format(domain_name))
        records = self.do_api.get_all_dns_records(domain_name)
        retv = True
        for r in records:
            if r['type'] not in ('A', 'AAAA'):
                continue
            try:
                ptr_addr = reversename.from_address(r['data'])
                rev_answer = self.resolver.query(ptr_addr, "PTR")
            except (resolver.NoAnswer, resolver.NXDOMAIN):
                print("[i] {recname:s}: No rDNS found for {ip:s}".format(
                    recname=r['name'], ip=r['data']))
                continue
            for a in rev_answer:
                try:
                    fwd_name = name.from_text(str(a))
                    fwd_answer = self.resolver.query(fwd_name, r['type'])
                except (resolver.NoAnswer, resolver.NXDOMAIN):
                    print("[!] {recname:s}: Reverse DNS for {ip:s} is {revname:s}, but no forward "
                          "{type:s} record for {revname:s} exists."
                          .format(recname=r['name'], ip=r['data'], revname=str(a), type=r['type']))
                    retv = False
                    continue
                for fwd_ip in fwd_answer:
                    if str(fwd_ip) != r['data']:
                        print("[!] {recname:s}: Reverse DNS for {ip:s} is {revname:s} which has: "
                              "{type:s} -> {fwd_ip:s}.".format(
                                recname=r['name'],
                                ip=r['data'],
                                revname=str(a),
                                type=r['type'],
                                fwd_ip=str(fwd_ip)))
                        retv = False
                        continue
        return retv


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Check a domain's A and AAAA records against rDNS for the IPs they point to.",
        epilog="Authentication:  Set your DigitalOcean API token in the DIGITALOCEAN_TOKEN "
               "environment variable. It can also be provided via a .env file, in this directory "
               "(see .env.sample).")
    parser.add_argument('--domain', type=str,
                        help="The domain to audit. If left empty, all domains in the account will be audited.")
    parser.add_argument('--fail-return', type=int, default=3,
                        help="Return code in case audit problems were detected. Default: 3.")
    args = parser.parse_args()

    if args.fail_return in (1, 2):
        eprint("Error: Return codes 1 and 2 are reserved for general and authentication errors, respectively.")
        sys.exit(1)

    do_token = os.getenv('DIGITALOCEAN_TOKEN')
    if not do_token:
        eprint("DigitalOcean API token must be set using an environment variable.")
        eprint("Copy .env.sample to .env and fill it out to provide credentials.")
        sys.exit(2)
    do_api = DigitalOceanAPI(do_token)
    try:
        do_api.check_auth()
    except AuthException:
        eprint("DigitalOcean authentication check failed.")
        eprint("Check your credentials and try again.")
        sys.exit(2)
    except APIException as e:
        eprint("DigitalOcean authentication check failed.")
        eprint(e.human_str)
        sys.exit(2)

    domain_name = None
    if args.domain:
        domain_name = args.domain.lower().strip()
    auditor = Auditor(do_api)
    try:
        if domain_name:
            result = auditor.audit(domain_name)
        else:
            result = auditor.audit_all()
    except APIException as e:
        eprint(e.human_str)
        sys.exit(1)
    except AuthException:
        eprint("Check your DigitalOcean credentials and try again.")
        sys.exit(2)

    if not result:
        sys.exit(args.fail_return)
