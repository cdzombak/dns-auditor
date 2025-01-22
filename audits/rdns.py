import typing
import ipaddress

import dns
from dns import resolver
from termcolor import cprint

from record import Record


def is_tailscale(ip: typing.Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    return ipaddress.ip_address(ip) in ipaddress.ip_network("100.64.0.0/10")

def audit(policy, res: resolver.Resolver, verbose: bool, records: typing.List[Record]) -> bool:
    """
    Check a domain's A and AAAA records against rDNS for the IPs they point to.
    Returns False if any anomalies were found; True otherwise.
    """
    retv = True
    for r in records:
        if r.type not in ('A', 'AAAA'):
            continue
        ipaddr = ipaddress.ip_address(r.data)
        if is_tailscale(ipaddr):
            print("[i] {recname:s}: {type:s} points to Tailscale ({ip:s}); skipping".format(
                recname=r.name, ip=r.data, type=r.type))
            continue
        if ipaddr.is_private:
            print("[i] {recname:s}: {type:s} points to private IP ({ip:s}); skipping".format(
                recname=r.name, ip=r.data, type=r.type))
            continue
        try:
            ptr_addr = dns.reversename.from_address(r.data)
            rev_answer = res.resolve(ptr_addr, "PTR", lifetime=10.0)
        except (resolver.NoAnswer, resolver.NXDOMAIN, resolver.NoNameservers):
            if policy.getboolean('FailOnMissingPTR'):
                cprint("[!] {recname:s}: No rDNS found for {ip:s}".format(
                    recname=r.name, ip=r.data),
                       'red')
                retv = False
            else:
                print("[i] {recname:s}: No rDNS found for {ip:s}".format(
                    recname=r.name, ip=r.data))
            continue
        except resolver.LifetimeTimeout:
            cprint("[i] {recname:s}: rDNS lookup for {ip:s} timed out"
                   .format(recname=r.name, ip=r.data),
                   'yellow')
            retv = False
            continue
        except dns.exception.DNSException as e2:
            cprint("[!] {recname:s}: rDNS lookup for {ip:s} failed: {exc:s}"
                   .format(recname=r.name, ip=r.data, exc=str(e2)),
                   'red')
            retv = False
            continue
        for a in rev_answer:
            if verbose:
                print(f"    {r.name}: {r.type} -> {r.data} -> {a}")
            try:
                fwd_name = dns.name.from_text(str(a))
                fwd_answer = res.resolve(fwd_name, r.type, lifetime=10.0)
            except (resolver.NoAnswer, resolver.NXDOMAIN, resolver.NoNameservers):
                cprint(
                    "[!] {recname:s}: Reverse DNS for {ip:s} is {revname:s}, but no forward "
                    "{type:s} record for {revname:s} exists."
                    .format(recname=r.name, ip=r.data, revname=str(a), type=r.type),
                    'red')
                retv = False
                continue
            except resolver.LifetimeTimeout:
                cprint("[!] {recname:s}: Reverse DNS for {ip:s} is {revname:s}, but forward "
                       "{type:s} lookup for {revname:s} timed out"
                       .format(recname=r.name, ip=r.data, revname=str(a),
                               type=r.type),
                       'yellow')
                retv = False
                continue
            except dns.exception.DNSException as e2:
                cprint(
                    "[!] {recname:s}: Reverse DNS for {ip:s} is {revname:s}, but forward "
                    "{type:s} lookup for {revname:s} failed: {exc:s}".format(
                        recname=r.name,
                        ip=r.data,
                        revname=str(a),
                        type=r.type,
                        exc=str(e2),
                    ), 'red')
                retv = False
                continue
            for fwd_ip in fwd_answer:
                if verbose:
                    print(f"    {r.name}: {r.type} -> {r.data} -> {a} -> {fwd_ip}")
                if str(fwd_ip) != r.data:
                    cprint(
                        "[!] {recname:s}: Reverse DNS for {ip:s} is {revname:s} which has: "
                        "{type:s} -> {fwd_ip:s}.".format(
                            recname=r.name,
                            ip=r.data,
                            revname=str(a),
                            type=r.type,
                            fwd_ip=str(fwd_ip),
                        ), 'red')
                    retv = False
                    continue
    return retv
