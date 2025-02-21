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

    def parse_flags(self, flag_bytes):
        # Extracts and decodes the flag bits from the 2-byte flag field.
        flag_value = int.from_bytes(flag_bytes)
        parsed = {}
        parsed["QR"]        = HEADER_FIELD_DEFS["QR"]       [(flag_value >> 15) & 0x1] # 1 bit
        parsed["Opcode"]    = HEADER_FIELD_DEFS["Opcode"]   [(flag_value >> 11) & 0xF] # 4 bits
        parsed["AA"]        = HEADER_FIELD_DEFS["AA"]       [(flag_value >> 10) & 0x1] # 1 bit
        parsed["TC"]        = HEADER_FIELD_DEFS["TC"]       [(flag_value >> 9) & 0x1]  # 1 bit
        parsed["RD"]        = HEADER_FIELD_DEFS["RD"]       [(flag_value >> 8) & 0x1]  # 1 bit
        parsed["RA"]        = HEADER_FIELD_DEFS["RA"]       [(flag_value >> 7) & 0x1]  # 1 bit
        parsed["Z"]         = HEADER_FIELD_DEFS["Z"]        [0]  # Reserved so always zero
        parsed["RCODE"]     = HEADER_FIELD_DEFS["RCODE"]    [flag_value & 0xF]
        return parsed

    def _parse_domain_name(self, message, offset):
        """
        Parses a domain name from the DNS message starting at the given offset.
        Supports both uncompressed labels and compressed pointers.

        Parameters:
        - message: The complete DNS message as bytes.
        - offset: The starting position in the message to parse the domain name.

        Returns:
        - A tuple containing the domain name and the updated offset in the message after the domain name read.
        """
        labels = []
        original_offset = offset  # Save the original offset to return if we encounter a pointer.
        jumped = False  # Flag to indicate if we have followed a pointer.

        # Iterate through the message to construct the domain name labels [www, example, com]
        while True:

            # The first byte of the message is the length of the current label
            length = message[offset]  # Read the length of the label.
            if length == 0:     # If the length is zero, we have reached the end of the domain name
                offset += 1     # Move past the null termination.
                break

            # Check if the label is a pointer or a regular label
            if (length & 0xC0) == 0xC0: # First two bits are 1, so this is a pointer
                # Next 14 bits are the offset to the actual location of the label
                pointer_high = (length & 0x3F) # Mask off the pointer indicator bits
                pointer_high <<= 8  # Shift the high bits to the left (8 + 6 = 14)
                pointer_low = message[offset + 1]  # Read the low 8 bits of the pointer
                next_label_loc = pointer_high | pointer_low  # OR together to get 14 bit pointer offset


                if not jumped:
                    original_offset = offset + 2  # Save position after the two pointer bytes to resume later
                offset = next_label_loc  # Update offset to the next label location
                jumped = True  # Set the jumped flag as we are now following a pointer
            
            # If the length is not a pointer, the length means the num label characters
            # so we read that many bytes to get the end of the label
            else:
                offset += 1  # Move past the length octet
                label = message[offset:offset + length].decode()  # Extract the label
                labels.append(label)  # Add the label to the list
                offset += length  # Move to the next label

        # Return the constructed domain name and appropriate offset.
        if not jumped:
            return ".".join(labels), offset  # If no pointer was followed, return the current offset
        else:
            return ".".join(labels), original_offset  # If a pointer was followed, return the original offset


# DNSQuery class constructs a DNS query message for a given domain.
class DNSQuery(DNSHeader):
    def __init__(self, domain, qtype=1, qclass=1):
        # Assemble header fields for the query
        transaction_id = (0x1234).to_bytes(2)  # Random transaction ID
        flags = (0x0100).to_bytes(2)           # Standard query with recursion desired
        qdcount = (1).to_bytes(2)              # Single question in the question section
        ancount = (0).to_bytes(2)              # No answers in the response
        nscount = (0).to_bytes(2)              # No name server records in the authority section
        arcount = (0).to_bytes(2)              # No additional records in the response
        header = (transaction_id + flags + qdcount + ancount + nscount + arcount)
        super().__init__(header)               # DNSHeader (nice dictionary) accessible via self.header

        # Assemble Body fields for the query
        self.domain = domain                   # The domain name to query
        qtype = qtype.to_bytes(2)              # Query type (default A record)
        qclass = qclass.to_bytes(2)            # Query class (default IN class)
        self.question = self.body = self._encode_domain_name() + qtype + qclass # Question section
        
        # Complete Query message
        self.query = header + self.question    # Build the complete query in bytes

    def _encode_domain_name(self):
        # Converts a domain name "www.example.com" to DNS label format
        labels = self.domain.split('.')
        # Encode each label as a length byte followed by the ASCII character bytes
        encoded = b''.join(bytes([len(label)]) + label.encode() for label in labels)
        return encoded + b'\x00'  # null termination for the end of the domain name


# DNSResponse class parses a DNS response message.
class DNSResponse(DNSHeader):
    def __init__(self, raw_bytes):
        super().__init__(raw_bytes)                     # Header accessible via self.header
        self.body = self.parse_body()                   # Process and parse the variable sections
        self.response = {**self.header, **self.body}    # Full response structure by combining dictoinaries

    def parse_body(self):
        # Parses the question, answer, authority, and additional sections.
        offset = 12  # Skip the fixed header.
        questions = []
        for _ in range(self.header["QDCOUNT"]):
            question, offset = self.parse_question(offset)
            questions.append(question)
        answers = []
        for _ in range(self.header["ANCOUNT"]):
            answer, offset = self.parse_resource_record(offset)
            answers.append(answer)
        authorities = []
        for _ in range(self.header["NSCOUNT"]):
            auth, offset = self.parse_resource_record(offset)
            authorities.append(auth)
        additionals = []
        for _ in range(self.header["ARCOUNT"]):
            add, offset = self.parse_resource_record(offset)
            additionals.append(add)
        return {
            "Questions": questions,
            "Answers": answers,
            "Authorities": authorities,
            "Additionals": additionals
        }

    def parse_question(self, offset):
        # Parses one question entry from the DNS message.
        qname, offset = self._parse_domain_name(self.raw_bytes, offset)

        qtype = int.from_bytes(self.raw_bytes[offset:offset + 2])
        offset += 2
        qclass = int.from_bytes(self.raw_bytes[offset:offset + 2])
        offset += 2
        # Convert QTYPE and QCLASS using the dictionaries.
        qtype_str = RECORD_TYPES.get(qtype, str(qtype))
        qclass_str = RECORD_CLASSES.get(qclass, str(qclass))

        return {"QNAME": qname, "QTYPE": qtype_str, "QCLASS": qclass_str}, offset

    def parse_resource_record(self, offset):
        # Parses a resource record (answer, authority, or additional)
        name, offset = self._parse_domain_name(self.raw_bytes, offset)

        rtype = int.from_bytes(self.raw_bytes[offset:offset + 2])
        offset += 2
        rclass = int.from_bytes(self.raw_bytes[offset:offset + 2])
        offset += 2
        ttl = int.from_bytes(self.raw_bytes[offset:offset + 4])
        offset += 4
        rdlength = int.from_bytes(self.raw_bytes[offset:offset + 2])
        offset += 2
        # Save RDATA start position for decoding
        rdata_start = offset
        rdata = self.raw_bytes[offset:offset + rdlength]
        offset += rdlength

        # Convert record type and class using the dictionaries
        type_str = RECORD_TYPES.get(rtype, str(rtype))
        class_str = RECORD_CLASSES.get(rclass, str(rclass))
        
        # Process RDATA based on record type.
        if type_str == "A" and rdlength == 4:  # A record with 4-byte address
            rdata_str = ".".join(str(b) for b in rdata)
        elif type_str == "CNAME":
            # Decode the compressed domain name in RDATA using the original message context
            cname, _ = self._parse_domain_name(self.raw_bytes, rdata_start)
            rdata_str = cname
        else:
            rdata_str = rdata.hex()
            
        return {
            "NAME": name,
            "TYPE": type_str,
            "CLASS": class_str,
            "TTL": ttl,
            "RDLENGTH": rdlength,
            "RDATA": rdata_str
        }, offset



# Helper function to pretty-print the DNS response in nslookup style
def pretty_print_nslookup(response, server):
    # Print DNS server info using f-strings
    print(f"Server:\t\t{server}")
    print(f"Address:\t{server}#53\n")
    
    # Print the answer section in nslookup style output if there are answers
    if response.body["Answers"]:
        print("Non-authoritative answer:")
        # Assume the first question contains the queried domain
        query_name = response.response.get("Questions", [{'QNAME': 'unknown'}])[0]["QNAME"]
        for answer in response.body["Answers"]:
            if answer["TYPE"] == "CNAME":
                # Print canonical name mapping
                print(f"{query_name}\tcanonical name = {answer['RDATA']}")
            elif answer["TYPE"] == "A":
                # Print Name and Address fields
                print(f"\nName:\t{answer['NAME']}")
                print(f"Address:\t{answer['RDATA']}")
            else:
                # Fallback for other types.
                print(f"{answer['TYPE']}: {answer['RDATA']}")
    else:
        print("No Answers.")


# ----------------- Main Script -----------------


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <hostname> [<dns_server>]")
        sys.exit(1)

    hostname = sys.argv[1]
    # Use provided DNS server or default to my router's IP
    dns_server = sys.argv[2] if len(sys.argv) > 2 else "192.168.1.1"

    print("Querying DNS for hostname: {} via server: {}".format(hostname, dns_server))
    try:
        # Create a DNS query message as bytes
        query = DNSQuery(hostname)
        print("\nDNS Query:", query.query)
        print("DNS Query Header", query.header)
        print("DNS Query Body", query.body)

        # Send the query to the DNS server and receive the response
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(5)                         # Set a timeout of 5 seconds for the query
            s.sendto(query.query, (dns_server, 53)) # Send the query to the DNS server on port 53
            response_bytes, _ = s.recvfrom(512)     # Receive up to 512 bytes as per DNS standard
        
        print("-"*60)

        print("RAW DNS RESPONSE:", response_bytes)
        response = DNSResponse(response_bytes)
        print("DNS Response:", response.response)
        print("DNS Response Header:", response.header)
        print("DNS Response Body:", response.body)
        
        print("-"*60)

        # Pretty-print response in nslookup style
        print("\tNSLOOKUP")
        pretty_print_nslookup(response, dns_server)

    except Exception as e:
        print("DNS query failed:", e)
