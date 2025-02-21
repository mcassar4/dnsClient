# Manny Cassar
# 2025-02-21
# 20213773
# This script is a simple DNS client that sends a query to a DNS server and prints the response
# Command-line usage: python dns_client.py <hostname> [<dns_server>]

import socket
import sys

# RFC 1035 reference definitions going top to bottom. Not all are necessar for implememntation, but
# serve as a good reference for the DNS protocol regardles: https://tools.ietf.org/html/rfc1035

# Schema for DNS resource records
RESOURCE_RECORD_FIELDS = {
    "NAME": "variable",  # Compresed domain name
    "TYPE": "2 octets",
    "CLASS": "2 octets",
    "TTL": "4 octets",
    "RDLENGTH": "2 octets",
    "RDATA": "variable"  # Depends on TYPE and CLASS of the record.
}

# Type values for DNS resource records
RECORD_TYPES = {
    1: "A",         # Address record
    2: "NS",        # Name server record
    # Skip obsolete types MD, MF
    5: "CNAME",     # Canonical name record
    6: "SOA",       # Start of authority record
    # Skip Experimental types MB, MG, MR, null
    11: "WKS",      # Well-known service description
    12: "PTR",      # Pointer record
    13: "HINFO",    # Host information record
    14: "MINFO",    # Mailbox or mail list information
    15: "MX",       # Mail exchange record
    16: "TXT",      # Text strings
}

# Qtype doesnt seem necessary here

# CLASS values for DNS resource records
RECORD_CLASSES = {
    1: "IN",  # Internet
    # Skip obsolete classes CS
    3: "CH",  # CHAOS
    4: "HS",  # Hesiod
}

# Qclass doesnt seem necessary here

# For each record type, more info is provided:
RECORD_DETAILS = {
    "HINFO": {
        "CPU": "variable",
        "OS": "variable"
    },
    # Skip Experimental
    "MX": {
        "PREFERENCE": "2 octets",
        "EXCHANGE": "variable"
    },
    "SOA": {
        "MNAME": "variable",
        "RNAME": "variable",
        "SERIAL": "4 octets",
        "REFRESH": "4 octets",
        "RETRY": "4 octets",
        "EXPIRE": "4 octets",
        "MINIMUM": "4 octets"
    },
    "WKS": {
        "ADDRESS": "4 octets",
        "PROTOCOL": "1 octet",
        "BITMAP": "variable"
    }
}


# Flags and their possible values in the DNS header.
HEADER_FIELD_DEFS = {
    "QR": {0: "Query", 1: "Response"},  # Query/Response flag.
    "Opcode": {
        0: "Standard Query (QUERY)",
        1: "Inverse Query (IQUERY)",
        2: "Server Status Request (STATUS)"
    },
    "AA": {0: "Non-Authoritative", 1: "Authoritative Answer"},
    "TC": {0: "Not Truncated", 1: "Message Truncated"},
    "RD": {0: "Recursion Not Desired", 1: "Recursion Desired"},
    "RA": {0: "Recursion Not Available", 1: "Recursion Available"},
    "Z": {0: "Reserved as Zero"},
    "RCODE": {
        0: "No Error",
        1: "Format Error",
        2: "Server Failure",
        3: "Name Error (NXDOMAIN)",
        4: "Not Implemented",
        5: "Refused"
    },
    "QDCOUNT": "Number of entries in the Question section",
    "ANCOUNT": "Number of resource records in the Answer section",
    "NSCOUNT": "Number of name server resource records in the Authority section",
    "ARCOUNT": "Number of resource records in the Additional section"
}

# Byte positions of information in the DNS header fields.
HEADER_FIELD_BYTES = {
    "Transaction ID": (0, 2),
    "Flags": (2, 4),
    "QDCOUNT": (4, 6),
    "ANCOUNT": (6, 8),
    "NSCOUNT": (8, 10),
    "ARCOUNT": (10, 12)
}

# Question section fields in a DNS message.
QUESTION_FIELDS = {
    "QNAME": "variable",  # Domain name, may involve pointer compression.
    "QTYPE": "2 octets",
    "QCLASS": "2 octets"
}



# DNSHeader encodes structure of a DNS message header
class DNSHeader:
    def __init__(self, raw_bytes):
        self.raw_bytes = raw_bytes
        self.header = self.parse_header(raw_bytes[:12])     # Parse the fixed header section

    def parse_header(self, header_bytes):
        # Parses the header fields
        parsed = {}
        # Parse each field name using the defined byte positions
        for field, (start, end) in HEADER_FIELD_BYTES.items():
            if field != "Flags":
                parsed[field] = int.from_bytes(header_bytes[start:end])
        # Parse the Flags field using helper method.
        parsed["Flags"] = self.parse_flags(header_bytes[2:4])
        return parsed

