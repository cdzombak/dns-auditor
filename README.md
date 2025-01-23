# dns-auditor

Check your DNS records for a variety of potential issues.

## Checks

- **CAA:** Checks that extant CAA records are valid. If specified by policy, requires `issue` and `iodef` fields to be present.
- **CNAME:** Checks that CNAME records point to names that have resolvable A records.
- **Mail:** Checks that MX records point to names that have resolvable A records. Partially validates DMARC records, if present. If specified by policy, requires domains with MX records to have SPF and DMARC records.
- **rDNS:** Checks that reverse DNS for the IPs that A/AAAA records point to resolve to the same domain.

## Supported DNS Hosts

### DigitalOcean

Create a new API token in the DigitalOcean control panel: https://cloud.digitalocean.com/account/api/tokens

Note that a read-only token is sufficient.

### Porkbun

Create a new API key and secret here: https://porkbun.com/account/api

Note that you must enable API access for each domain individually. See [Porkbun's API docs](https://kb.porkbun.com/article/190-getting-started-with-the-porkbun-api).

### Name.com

Create a new API token in Name.com Account Settings: https://www.name.com/account/settings/api

## Configuration

### Credentials

Credentials for supported DNS hosts are accepted via environment variables, listed below. `dns-auditor` will attempt to read these from the `.env` file in the working directory, if it exists. See [`.env.sample`](.env.sample) for an example.

#### DigitalOcean

- `DIGITALOCEAN_TOKEN`: your DigitalOcean API token

#### Porkbun

- `PORKBUN_API_KEY`: your Porkbun API key
- `PORKBUN_SECRET_KEY`: your Porkbun API secret key

#### Name.com

- `NAMECOM_USERNAME`: your Name.com username
- `NAMECOM_API_TOKEN`: your Name.com API token

### Policies

Certain checks can be customized with a policy file. See [`policy.ini.sample`](policy.sample.ini) for an example. Pass this file to `dns-auditor` with the `--policy` option.

#### CAA

- `RequireIssue`: If `true`, requires that the domain has a CAA record with an `issue` or `issuewild` field.
- `RequireIodef`: If `true`, requires that the domain has a CAA record with an `iodef` field.

#### Mail

- `RequireSPF`: If `true`, requires that any domain that has MX records also has an SPF record.
- `RequireDMARC`: If `true`, requires that any domain that has MX records also has a DMARC record.

#### rDNS

- `FailOnMissingPTR`: If `true`, a missing PTR record will cause the check to fail.

## Usage

### CLI Options

- `--domain`: Domain to audit. If not given, all domains in the account will be audited. Optional.
- `--host`: Hosting service for your DNS records. One of: `do` (DigitalOcean), `pb` (Porkbun), `nc` (Name.com).
- `--policy`: Path to a .ini policy file. Optional.
- `--verbose`: Print each check that is run regardless of its result. Optional.

### Non-Docker

Clone the repository and run `make dev/bootstrap`, which will create a virtualenv for you:

```
git clone https://github.com/cdzombak/dns-auditor.git
cd dns-auditor
make dev/bootstrap
```

Then, activate the virtualenv and run `main.py`:

```
. venv/bin/activate
./main.py --host pb --domain dzombak.com
```

Alternatively, run `main.py` via the venv's Python interpreter directly:

```
./venv/bin/python ./main.py --host pb --domain dzombak.com
```

### Docker

Pre-built Docker images [are available on Docker Hub](https://hub.docker.com/r/cdzombak/dns-auditor). To run it:

```
docker run --rm -e PORKBUN_API_KEY='pk1_aaaa0000' -e PORKBUN_SECRET_KEY='sk1_0000aaaa' cdzombak/dns-auditor --host pb --domain dzombak.com
```

Remember that:

- You will need to provide environment variables to the container for your DNS host credentials
- Any policy file you want to use must be mounted into the container

## License

GPL 3.0; see [LICENSE](LICENSE) in this repository.

## Author

Chris Dzombak ([dzombak.com](https://www.dzombak.com); [GitHub @cdzombak](https://github.com/cdzombak))

## See Also

- [DigitalOcean to Porkbun DNS Migrator](https://github.com/cdzombak/dns-do-to-porkbun)
- [DigitalOcean to Name.com DNS Migrator](https://github.com/cdzombak/dns-do-to-namecom)
- [Name.com to DigitalOcean DNS Migrator](https://github.com/cdzombak/dns-migrator)
- [DigitalOcean Dynamic DNS tool](https://github.com/cdzombak/do-ddns)
