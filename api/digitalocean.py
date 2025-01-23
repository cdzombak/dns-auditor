import datetime
import typing

import requests

from api.client import Client
from eprint import eprint
from exc import AuthException, APIException
from normalizedrecord import NormalizedRecord


def record_from_digitalocean(d: typing.Dict) -> NormalizedRecord:
    if d['type'] == 'SRV':
        raise ValueError('SRV records are not supported by this tool at this time.')

    prior = None
    if 'priority' in d:
        prior = str(d['priority'])

    if d['type'] == 'CAA':
        return NormalizedRecord(
            name=d['name'],
            type=d['type'],
            data='{:d} {:s} {:s}'.format(d['flags'], d['tag'], d['data']),
            ttl=str(d['ttl']),
            priority=prior,
        )

    return NormalizedRecord(
        name=d['name'],
        type=d['type'],
        data=d['data'],
        ttl=str(d['ttl']),
        priority=prior,
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


class DigitalOceanAPI(Client):
    _API_BASE = 'https://api.digitalocean.com/v2'
    logRatelimit: bool

    def __init__(self, token: str):
        self.logRatelimit = False
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
        url = '{base:s}/{endpoint:s}'.format(base=DigitalOceanAPI._API_BASE, endpoint=endpoint)
        resp = requests.get(url, auth=self.auth, params=params)
        self._log_ratelimit(resp)
        self._check_response(resp)
        return resp

    def _get_decoded(self, endpoint, params=None):
        return self._get(endpoint, params).json()

    def _log_ratelimit(self, response):
        if not self.logRatelimit:
            return

        ratelimit = response.headers.get('RateLimit-Limit')
        remaining = response.headers.get('RateLimit-Remaining')
        reset = response.headers.get('RateLimit-Reset')
        if not ratelimit or not remaining or not reset:
            return
        reset_dt = datetime.datetime.utcfromtimestamp(int(reset.strip())) \
            .replace(tzinfo=datetime.timezone.utc)
        eprint(" [DO Rate Limit] {:s}/{:s} remain; reset {:s}".format(
            remaining, ratelimit, reset_dt.isoformat(' ')))

    def check_auth(self):
        return self._get_decoded('account')

    def get_all_domains(self) -> typing.Generator[str, None, None]:
        page = 0
        more = True
        while more:
            page += 1
            resp = self._get_decoded('domains', params={'page': page})
            for d in resp['domains']:
                yield d['name']
            more = resp.get('links', {}).get('pages', {}).get('next') is not None

    def get_all_dns_records(self, domain: str) -> typing.Generator[NormalizedRecord, None, None]:
        page = 0
        more = True
        while more:
            page += 1
            resp = self._get_decoded('domains/{name:s}/records'.format(name=domain), params={'page': page})
            for r in resp['domain_records']:
                yield record_from_digitalocean(r)
            more = resp.get('links', {}).get('pages', {}).get('next') is not None
