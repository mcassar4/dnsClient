### Manny Cassar
### 2025-02-21
### 20213773


# DNS Client

This project provides a simple DNS client in Python that sends a DNS query to a server and prints the response in a format similar to `nslookup`.

## Features

- Constructs a DNS query following RFC 1035.
- Supports decoding A and CNAME records.
- Pretty-prints the response with server info and answer details.
- Provides helpful usage instructions and troubleshooting tips.

## Files

- **dnsClient.py**: The main Python script that builds, sends, and parses DNS queries.

## Requirements

- Python 3.x

## Usage

Run the script from the command line:
`python dns_client.py <hostname> [<dns_server>]`

- Without `dns_server`, the program will query the local router. I suggest testing with 1.1.1.1 or 8.8.8.8 as this parameter.

