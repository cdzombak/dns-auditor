FROM python:3.13-alpine
ARG BIN_VERSION=<unknown>

RUN mkdir /app
COPY *.py requirements.txt /app/
COPY api /app/api
COPY audits /app/audits
RUN pip install --no-cache-dir -r /app/requirements.txt
ENTRYPOINT ["python", "/app/main.py"]

LABEL license="GPL-3.0"
LABEL maintainer="Chris Dzombak <https://www.dzombak.com>"
LABEL org.opencontainers.image.authors="Chris Dzombak <https://www.dzombak.com>"
LABEL org.opencontainers.image.url="https://github.com/cdzombak/dns-auditor"
LABEL org.opencontainers.image.documentation="https://github.com/cdzombak/dns-auditor/blob/main/README.md"
LABEL org.opencontainers.image.source="https://github.com/cdzombak/dns-auditor.git"
LABEL org.opencontainers.image.version="${BIN_VERSION}"
LABEL org.opencontainers.image.licenses="GPL-3.0"
LABEL org.opencontainers.image.title="dns-auditor"
LABEL org.opencontainers.image.description="Check your DNS records for a variety of potential issues"
