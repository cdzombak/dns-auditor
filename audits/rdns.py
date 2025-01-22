import typing

import dns
from dns import resolver
from termcolor import cprint

def audit(res: resolver.Resolver, verbose: bool, records: typing.List) -> bool:
    """
    Check a domain's A and AAAA records against rDNS for the IPs they point to.
    Returns False if any anomalies were found; True otherwise.
    """
    retv = True
    for r in records:
        if r['type'] not in ('A', 'AAAA'):
            continue
        try:
            ptr_addr = dns.reversename.from_address(r['data'])
            rev_answer = res.resolve(ptr_addr, "PTR", lifetime=10.0)
        except (resolver.NoAnswer, resolver.NXDOMAIN, resolver.NoNameservers):
            print("[i] {recname:s}: No rDNS found for {ip:s}".format(
                recname=r['name'], ip=r['data']))
            continue
        except resolver.LifetimeTimeout:
            cprint("[i] {recname:s}: rDNS lookup for {ip:s} timed out"
                   .format(recname=r['name'], ip=r['data']),
                   'yellow')
            continue
        except dns.exception.DNSException as e2:
            cprint("[!] {recname:s}: rDNS lookup for {ip:s} failed: {exc:s}"
                   .format(recname=r['name'], ip=r['data'], exc=str(e2)),
                   'red')
            retv = False
            continue
        for a in rev_answer:
            if verbose:
                print(f"    {r['name']}: {r['type']} -> {r['data']} -> {a}")
            try:
                fwd_name = dns.name.from_text(str(a))
                fwd_answer = res.resolve(fwd_name, r['type'], lifetime=10.0)
            except (resolver.NoAnswer, resolver.NXDOMAIN, resolver.NoNameservers):
                cprint(
                    "[!] {recname:s}: Reverse DNS for {ip:s} is {revname:s}, but no forward "
                    "{type:s} record for {revname:s} exists."
                    .format(recname=r['name'], ip=r['data'], revname=str(a), type=r['type']),
                    'red')
                retv = False
                continue
            except resolver.LifetimeTimeout:
                cprint("[!] {recname:s}: Reverse DNS for {ip:s} is {revname:s}, but forward "
                       "{type:s} lookup for {revname:s} timed out"
                       .format(recname=r['name'], ip=r['data'], revname=str(a),
                               type=r['type']),
                       'yellow')
                continue
            except dns.exception.DNSException as e2:
                cprint(
                    "[!] {recname:s}: Reverse DNS for {ip:s} is {revname:s}, but forward "
                    "{type:s} lookup for {revname:s} failed: {exc:s}".format(
                        recname=r['name'],
                        ip=r['data'],
                        revname=str(a),
                        type=r['type'],
                        exc=str(e2),
                    ), 'red')
                retv = False
                continue
            for fwd_ip in fwd_answer:
                if verbose:
                    print(f"    {r['name']}: {r['type']} -> {r['data']} -> {a} -> {fwd_ip}")
                if str(fwd_ip) != r['data']:
                    cprint(
                        "[!] {recname:s}: Reverse DNS for {ip:s} is {revname:s} which has: "
                        "{type:s} -> {fwd_ip:s}.".format(
                            recname=r['name'],
                            ip=r['data'],
                            revname=str(a),
                            type=r['type'],
                            fwd_ip=str(fwd_ip),
                        ), 'red')
                    retv = False
                    continue
    return retv
