import typing
from dataclasses import dataclass

@dataclass(frozen=True)
class Record(object):
    name: str
    type: str
    data: str
    ttl: str
    priority: typing.Optional[str]

def record_from_digitalocean(d: typing.Dict) -> Record:
    if d['type'] == 'SRV':
        raise ValueError('SRV records are not supported by this tool at this time.')

    prior = None
    if 'priority' in d:
        prior = str(d['priority'])

    if d['type'] == 'CAA':
        return Record(
            name=d['name'],
            type=d['type'],
            data='{:d} {:s} {:s}'.format(d['flags'], d['tag'], d['data']),
            ttl=str(d['ttl']),
            priority=prior,
        )

    return Record(
        name=d['name'],
        type=d['type'],
        data=d['data'],
        ttl=str(d['ttl']),
        priority=prior,
    )
