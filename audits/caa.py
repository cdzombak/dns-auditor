import configparser
import typing

import validators
from termcolor import cprint

from normalizedrecord import NormalizedRecord


def audit(
    policy: configparser.SectionProxy,
    verbose: bool,
    records: typing.Iterable[NormalizedRecord],
) -> bool:
    """
    Checks whether CAA records are valid.
    If specified by policy, requires issue and iodef fields to be present.
    Returns False if any failures were found; True otherwise.
    """
    retv = True
    has_issue = False
    has_iodef = False
    for r in records:
        if r.type != "CAA":
            continue

        parts = r.data.split(" ")
        if len(parts) != 3:
            cprint(
                "[!] {n:s}: CAA record has wrong number of parts: {data:s}".format(
                    n=r.name, data=r.data
                ),
                "red",
            )
            retv = False
            continue

        flags = int(parts[0])
        if flags != 0 and flags != 128:
            cprint(
                "[!] {n:s}: CAA record has invalid flags: {data:s}".format(
                    n=r.name, data=r.data
                ),
                "yellow",
            )
            retv = False
            continue

        tag = parts[1]
        if tag not in (
            "issue",
            "issuewild",
            "issuemail",
            "issuevmc",
            "iodef",
            "contactemail",
            "contactphone",
        ):
            cprint(
                "[!] {n:s}: CAA record has invalid tag: {data:s}".format(
                    n=r.name, data=r.data
                ),
                "red",
            )
            retv = False
            continue

        value = parts[2]
        if not value:
            cprint(
                "[!] {n:s}: CAA record value is empty: {data:s}".format(
                    n=r.name, data=r.data
                ),
                "red",
            )
            retv = False
            continue

        if tag == "iodef":
            if value.lower().startswith("mailto:"):
                address = value[7:]
                if not validators.email(address):
                    cprint(
                        "[!] {n:s}: CAA iodef value is not a valid email address: {data:s}".format(
                            n=r.name, data=r.data
                        ),
                        "red",
                    )
                    retv = False
                    continue
            if value.lower().startswith("http"):
                if not validators.url(value):
                    cprint(
                        "[!] {n:s}: CAA iodef value is not a valid URL: {data:s}".format(
                            n=r.name, data=r.data
                        ),
                        "red",
                    )
                    retv = False
                    continue

        if tag == "contactemail":
            if not validators.email(value):
                cprint(
                    "[!] {n:s}: CAA contactemail value is not a valid email address: {data:s}".format(
                        n=r.name, data=r.data
                    ),
                    "red",
                )
                retv = False
                continue

        if verbose:
            print("    {n:s}: CAA {data:s}".format(n=r.name, data=r.data))

        if r.name == "@" and (tag == "issue" or tag == "issuewild"):
            has_issue = True
        if r.name == "@" and tag == "iodef":
            has_iodef = True

    if policy.getboolean("RequireIssue") and not has_issue:
        cprint("[!] No valid CAA issue or issuewild record found.", "red")
        retv = False
    if policy.getboolean("RequireIodef") and not has_iodef:
        cprint("[!] No valid CAA iodef record found.", "red")
        retv = False

    return retv
