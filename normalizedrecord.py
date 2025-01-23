import typing
from dataclasses import dataclass

@dataclass(frozen=True)
class NormalizedRecord(object):
    name: str
    type: str
    data: str
    ttl: str
    priority: typing.Optional[str]
