import typing

from api.client import Client
from namecom import Auth, DnsApi, DomainApi, Record

from normalizedrecord import NormalizedRecord


def record_from_namecom(r: Record) -> NormalizedRecord:
    if r.type == 'SRV':
        raise ValueError('SRV records are not supported by this tool at this time.')

    n = r.host
    if not n:
        n = '@'

    prior = None
    if r.priority:
        prior = str(r.priority)

    return NormalizedRecord(
        name=n,
        type=r.type,
        data=r.answer,
        ttl=str(r.ttl),
        priority=prior,
    )


class NamecomAPI(Client):
    _auth: Auth

    def __init__(self, username: str, token: str):
        self._auth = Auth(username, token)

    def get_all_domains(self) -> typing.Generator[str, None, None]:
        more = True
        page = 0
        while more:
            page += 1
            resp = DomainApi(self._auth).list_domains(page=page, perPage=50)
            for d in resp.domains:
                yield d.domainName
            more = resp.nextPage is not None

    def get_all_dns_records(self, domain: str) -> typing.Generator[NormalizedRecord, None, None]:
        more = True
        page = 0
        while more:
            page += 1
            resp = DnsApi(domain, self._auth).list_records(page=page,perPage=50)
            for r in resp.records:
                yield record_from_namecom(r)
            more = resp.nextPage is not None
