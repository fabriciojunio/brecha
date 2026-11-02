# Security

*[Versão em português](SECURITY.md)*

This repository is vulnerable on purpose. The 19 flaws in the [report](docs/relatorio-pentest.en.md)
(BRECHA-001 to BRECHA-019) are here to be exploited, each with a proof of concept, a fix and a
retest in the report. They are **not** findings to
report.

## What is worth reporting

- A flaw in the **fixed version** (`/v2` and the services in their fixed form) that the report
  lists as closed: a retest that passes when it should not, or a variant the fix does not cover.
- Anything that takes the lab off the machine running it: a port listening outside `127.0.0.1`, an
  image or script that exposes a service on a network.
- A real secret in the code or history. Lab values are fictitious; a real service credential should not be here.
- A flaw in the pipeline (`.github/workflows/`) or in the evidence that makes CI prove less than it
  claims.

## How to report

Email **fabricioad444@gmail.com** with what you found and how to reproduce it. This is a portfolio
project maintained by one person: response depends on availability.

## Running it safely

Every published port listens on `127.0.0.1` only, and so does the Java application. Do not change
that, do not run the lab on a server or shared network, and do not use real data. The techniques
described here may only be used on systems whose owner has given written authorisation.
