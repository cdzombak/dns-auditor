import typing
from dataclasses import dataclass

@dataclass(frozen=True)
class Record(object):
    name: str
    type: str
    data: str
    ttl: str
    priority: typing.Optional[str]
