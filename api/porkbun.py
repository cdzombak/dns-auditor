import typing

import pkb_client.client

from api.client import Client
from record import Record


def record_from_porkbun(r: pkb_client.client.DNSRecord) -> Record:
    if r.type == 'SRV':
        raise ValueError('SRV records are not supported by this tool at this time.')

    prior = None
    if r.prio:
        prior = str(r.prio)

    return Record(
        name=r.name,
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
        # TODO(cdzombak): does not support chunks over 1000
        for d in self._client.get_domains():
            yield d.domain

    def get_all_dns_records(self, domain: str) -> typing.Generator[Record, None, None]:
        for r in self._client.get_dns_records(domain):
            yield record_from_porkbun(r)
