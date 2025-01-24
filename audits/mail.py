import configparser
import typing

import dns
import validators
from dns import resolver
from termcolor import cprint

from normalizedrecord import NormalizedRecord


def audit(
    policy: configparser.SectionProxy,
    res: resolver.Resolver,
    verbose: bool,
    records: typing.Iterable[NormalizedRecord],
) -> bool:
    """
    Checks that the domain's MX records point to names with A records.
    If a DMARC record exists, validates it.
    If the domain has MX records, policy may require presence of SPF and DMARC records.
    Returns False if any failures were found; True otherwise.
    """
    retv = True
    valid_mx_records = {}
    has_spf_records = {}
    valid_dmarc_records = {}

    for r in records:
        if r.type == "MX":
            try:
                ans = res.resolve(r.data, "A", lifetime=10.0)
            except (resolver.NoAnswer, resolver.NXDOMAIN, resolver.NoNameservers):
                cprint(
                    "[!] {recname:s}: MX {recdat:s} does not resolve to an A record".format(
                        recname=r.name, recdat=r.data
                    ),
                    "red",
                )
                retv = False
                continue
            except resolver.LifetimeTimeout:
                cprint(
                    "[!] {recname:s}: MX {recdat:s} lookup timed out".format(
                        recname=r.name, recdat=r.data
                    ),
                    "yellow",
                )
                continue
            except dns.exception.DNSException as e2:
                cprint(
                    "[!] {recname:s}: MX {recdat:s} lookup failed: {exc:s}".format(
                        recname=r.name, recdat=r.data, exc=str(e2)
                    ),
                    "red",
                )
                retv = False
                continue
            if verbose:
                for a in ans:
                    print(f"    {r.name}: {r.type} -> {r.data} -> {a}")
            valid_mx_records[r.name] = r.data
        elif r.type == "TXT" and r.data.startswith("v=spf"):
            has_spf_records[r.name] = r.data
        elif r.type == "TXT" and r.name == "_dmarc":
            parts = r.data.split(";")
            has_v = False
            has_p = False
            has_rua = False
            for pair in parts:
                pair = pair.strip()
                if not pair:
                    continue
                pair_parts = pair.split("=")
                if len(pair_parts) != 2:
                    cprint(
                        "[!] {recname:s}: DMARC pair {pair:s} is invalid".format(
                            recname=r.name,
                            pair=pair,
                        ),
                        "red",
                    )
                    retv = False
                    continue
                tag = pair_parts[0].strip()
                value = pair_parts[1].strip()
                if tag == "v":
                    if value != "DMARC1":
                        cprint(
                            "[!] {recname:s}: DMARC version is invalid: {recdat:s}".format(
                                recname=r.name, recdat=r.data
                            ),
                            "red",
                        )
                        retv = False
                        continue
                    has_v = True
                elif tag == "p":
                    if value not in ("none", "quarantine", "reject"):
                        cprint(
                            "[!] {recname:s}: DMARC policy is invalid: {recdat:s}".format(
                                recname=r.name, recdat=r.data
                            ),
                            "red",
                        )
                        retv = False
                        continue
                    has_p = True
                elif tag == "rua":
                    if not value.startswith("mailto:"):
                        cprint(
                            "[!] {recname:s}: DMARC rua is invalid: {recdat:s}".format(
                                recname=r.name, recdat=r.data
                            ),
                            "red",
                        )
                        retv = False
                        continue
                    if not validators.email(value[7:]):
                        cprint(
                            "[!] {recname:s}: DMARC rua is not a valid email address: {recdat:s}".format(
                                recname=r.name, recdat=r.data
                            ),
                            "red",
                        )
                        retv = False
                        continue
                    has_rua = True
            if has_v and has_p and has_rua:
                valid_dmarc_records[r.name] = r.data
                if verbose:
                    print(f"    {r.name}: {r.data}")
            elif not has_v:
                cprint(
                    "[!] {recname:s}: DMARC {recdat:s} is missing version tag".format(
                        recname=r.name, recdat=r.data
                    ),
                    "red",
                )
                retv = False
            elif not has_p:
                cprint(
                    "[!] {recname:s}: DMARC {recdat:s} is missing policy tag".format(
                        recname=r.name, recdat=r.data
                    ),
                    "red",
                )
                retv = False
            elif not has_rua:
                cprint(
                    "[!] {recname:s}: DMARC {recdat:s} is missing rua tag".format(
                        recname=r.name, recdat=r.data
                    ),
                    "yellow",
                )
                retv = False

    if policy.getboolean("RequireSPF"):
        for name in valid_mx_records.keys():
            if name not in has_spf_records:
                cprint(
                    "[!] {recname:s}: MX record exists, but no SPF record found".format(
                        recname=name
                    ),
                    "red",
                )
                retv = False
            elif verbose:
                print(f"    {name}: has SPF record")

    if policy.getboolean("RequireDMARC"):
        if len(valid_mx_records) and not len(valid_dmarc_records):
            cprint("[!] No DMARC records found for domain with MX records", "red")
            retv = False

    return retv
