import typing

import pkb_client.client

from api.client import Client
from normalizedrecord import NormalizedRecord


def record_from_porkbun(r: pkb_client.client.DNSRecord) -> NormalizedRecord:
    if r.type == 'SRV':
        raise ValueError('SRV records are not supported by this tool at this time.')

    n = r.name
    if not n:
        n = '@'

    prior = None
    if r.prio:
        prior = str(r.prio)

    return NormalizedRecord(
        name=n,
        type=str(r.type),
        data=r.content,
        ttl=str(r.ttl),
        priority=prior,
    )


class PorkbunAPI(Client):
    _client: pkb_client.client.PKBClient

    def __init__(self, api_key: str, secret_key: str):
        self._client = pkb_client.client.PKBClient(api_key, secret_key)

    def get_all_domains(self) -> typing.Generator[str, None, None]:
        # start: "An index to start at when retrieving the domains, defaults to 0.
        #        To get all domains increment by 1000 until you receive an empty array."
        more = True
        idx = -1000
        while more:
            idx += 1000
            domains = self._client.get_domains(start=idx)
            for d in domains:
                yield d.domain
            more = len(domains) > 0

    def get_all_dns_records(self, domain: str) -> typing.Generator[NormalizedRecord, None, None]:
        for r in self._client.get_dns_records(domain):
            yield record_from_porkbun(r)
