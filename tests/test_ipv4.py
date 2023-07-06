import pytest

from pynetfilter_conntrack import (
    Conntrack, ConntrackEntry,
    IPPROTO_TCP,
    NFCT_SOPT_SETUP_REPLY,
    NFCT_SOPT_SETUP_ORIGINAL,
    TCP_CONNTRACK_ESTABLISHED, TCP_CONNTRACK_LISTEN
)
from pynetfilter_conntrack.exceptions import (GenericNFCTError, ConntrackEntryExistsError, ConntrackEntryNotFoundError)
from socket import AF_INET, AF_INET6
from IPy import IP
from random import randrange
from time import sleep

import logging
logging.basicConfig(level=logging.DEBUG)

TESTNET1=IP("192.0.2.0")
TESTNET2=IP("198.51.100.0")
TESTNET3=IP("203.0.113.0")

def prepare_v4(srcip=TESTNET1, dstip=TESTNET3, swapip=False, srcport=50000, dstport=443, swapport=False) -> ConntrackEntry:
    # ----------- create conntrack entry -----------
    conntrack = Conntrack()
    v4 = ConntrackEntry.new(conntrack)
    v4.orig_l3proto = AF_INET
    if swapip:
        v4.orig_ipv4_src = dstip
        v4.orig_ipv4_dst = srcip
    else:
        v4.orig_ipv4_src = srcip
        v4.orig_ipv4_dst = dstip
    v4.orig_l4proto = IPPROTO_TCP
    if swapport:
        v4.orig_port_src = dstport
        v4.orig_port_dst = srcport
    else:
        v4.orig_port_src = srcport
        v4.orig_port_dst = dstport
    v4.setobjopt(NFCT_SOPT_SETUP_REPLY)
    v4.tcp_state = TCP_CONNTRACK_LISTEN
    v4.timeout = 300
    return v4

def test_create_ipv4_conntrack():
    # ----------- create conntrack entry -----------
    v4 = prepare_v4()
    v4.create()

def test_get_ipv4_conntrack():
    v4 = prepare_v4()
    v4.get()

def test_destroy_ipv4_conntrack():
    v4 = prepare_v4()
    v4.destroy()

def test_create_ipv4_conntrack_again():
    v4 = prepare_v4()
    v4.create()

def test_create_duplicate_ipv4_conntrack():
    # Trying to create the same entry again will raise an error
    with pytest.raises(ConntrackEntryExistsError):
        v4 = prepare_v4()
        v4.create()

def test_get_nonexistent_ipv4_conntrack(dstip=TESTNET2):
    # Trying to get a nonexistent entry should raise an error
    with pytest.raises(ConntrackEntryNotFoundError):
        v4 = prepare_v4()
        v4.orig_ipv4_dst = TESTNET2
        v4.get()

def test_update_ipv4_conntrack_timeout():
    v4 = prepare_v4()
    v4.timeout = 55
    v4.update()

def test_update_ipv4_conntrack_mark():
    v4 = prepare_v4()
    v4.mark = 1337
    v4.update()

def test_create_ipv4_conntrack_swapped():
    # We expect a failure if we try to create the reverse for an existing flow entry
    with pytest.raises(ConntrackEntryExistsError):
        v4 = prepare_v4(swapip=True, swapport=True)
        v4.create()

def test_create_ipv4_conntrack_swapped_ips():
    # Swapping only IPs and not ports should succeed, as that results in a different flow
    v4 = prepare_v4(swapip=True)
    v4.create()

def test_update_ipv4_conntrack_swapped_timeout():
    # Swapping IPs and ports should and then updating should succeed
    v4 = prepare_v4(swapip=True, swapport=True)
    v4.timeout = 77
    v4.update()

def test_update_ipv4_conntrack_tcpstate():
    v4 = prepare_v4()
    v4.tcp_state = TCP_CONNTRACK_ESTABLISHED
    v4.update()

def test_dump():
    conntrack = Conntrack()
    (table, count) = conntrack.dump_table(AF_INET)
    for entry in table:
        print(entry.format())
    assert count == len(table)

def test_create_a_lot_of_ipv4_conntrack_entries():
    # Use large timeout
    numreps = 10_000
    for _ in range (1, numreps):
        conntrack = Conntrack()
        v4 = ConntrackEntry.new(conntrack)
        v4.orig_l3proto = AF_INET
        v4.orig_ipv4_src = TESTNET1
        v4.orig_ipv4_dst = randrange(0xffffffff)
        v4.orig_l4proto = IPPROTO_TCP
        v4.orig_port_src = randrange(0xffff)
        v4.orig_port_dst = 443
        v4.setobjopt(NFCT_SOPT_SETUP_REPLY)
        v4.tcp_state = TCP_CONNTRACK_LISTEN
        v4.timeout = 333
        v4.create()

def test_cleanup():
    # Remove all conntrack entries where IPv4 source is TESTNET1, TESTNET2 or TESTNET3
    # NOTE if we created a lot of entries with a short timeout, some may expire between dumping the table and removing the table entries
    destroyed = 0
    conntrack = Conntrack()
    (table, count) = conntrack.dump_table(AF_INET)
    for entry in table:
        if entry.orig_ipv4_src in (TESTNET1, TESTNET2, TESTNET3):
            entry.destroy()
            destroyed += 1
    assert destroyed > 0

def test_delayed_cleanup():
    # Remove all conntrack entries where IPv4 source is TESTNET1, TESTNET2 or TESTNET3
    # now with a delay between dumping the table and removing entries
    # ...so we expect a RuntimeError
    found = 0
    destroyed = 0
    v4 = prepare_v4()
    v4.timeout = 2
    v4.create()
    conntrack = Conntrack()
    (table, count) = conntrack.dump_table(AF_INET)
    sleep(3)
    for entry in table:
        if entry.orig_ipv4_src in (TESTNET1, TESTNET2, TESTNET3):
            found += 1
            with pytest.raises(ConntrackEntryNotFoundError):
                entry.destroy()
                destroyed += 1
    # We expect 1 entry to be found, but none (successfully) destroyed
    assert found == 1
    assert destroyed == 0
