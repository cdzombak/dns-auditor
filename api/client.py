import typing
from abc import ABC, abstractmethod

from normalizedrecord import NormalizedRecord


class Client(ABC):

    @abstractmethod
    def get_all_domains(self) -> typing.Generator[str, None, None]:
        pass

    @abstractmethod
    def get_all_dns_records(self, domain: str) -> typing.Generator[NormalizedRecord, None, None]:
        pass
