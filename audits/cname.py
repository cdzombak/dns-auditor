import typing

import dns
from dns import resolver
from termcolor import cprint

from record import Record


def audit(res: resolver.Resolver, verbose: bool, records: typing.Iterable[Record]) -> bool:
    """
    Checks whether CNAME records point to names with A records.
    Returns False if any failures were found; True otherwise.
    """
    retv = True
    for r in records:
        if r.type != 'CNAME':
            continue
        try:
            cname_answer = res.resolve(r.data, "A", lifetime=10.0)
        except (resolver.NoAnswer, resolver.NXDOMAIN, resolver.NoNameservers):
            cprint("[!] {recname:s}: CNAME {cname:s} does not resolve to an A record"
                   .format(recname=r.name, cname=r.data), 'red')
            retv = False
            continue
        except resolver.LifetimeTimeout:
            cprint("[!] {recname:s}: CNAME {cname:s} lookup timed out"
                   .format(recname=r.name, cname=r.data), 'yellow')
            continue
        except dns.exception.DNSException as e2:
            cprint("[!] {recname:s}: CNAME {cname:s} lookup failed: {exc:s}"
                   .format(recname=r.name, cname=r.data, exc=str(e2)), 'red')
            retv = False
            continue
        if verbose:
            for a in cname_answer:
                print(f"    {r.name}: {r.type} -> {r.data} -> {a}")
    return retv
