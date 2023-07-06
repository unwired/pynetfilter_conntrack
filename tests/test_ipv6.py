import pytest


from pynetfilter_conntrack import (
    Conntrack, ConntrackEntry,
    IPPROTO_TCP,
    NFCT_SOPT_SETUP_REPLY,
    NFCT_SOPT_SETUP_ORIGINAL,
    TCP_CONNTRACK_ESTABLISHED, TCP_CONNTRACK_LISTEN
)
from pynetfilter_conntrack.exceptions import (GenericNFCTError, ConntrackEntryExistsError, ConntrackEntryNotFoundError)
from socket import AF_INET6
from IPy import IP
from random import randrange
from time import sleep

import logging
logging.basicConfig(level=logging.DEBUG)

TESTNET1=IP('2001:db8:0:1::1')
TESTNET2=IP('2001:db8:0:2::1')
TESTNET3=IP('2001:db8:0:3::1')

def prepare_v6(srcip=TESTNET1, dstip=TESTNET3, swapip=False, srcport=50000, dstport=443, swapport=False) -> ConntrackEntry:
    # ----------- create conntrack entry -----------
    conntrack = Conntrack()
    v6 = ConntrackEntry.new(conntrack)
    v6.orig_l3proto = AF_INET6
    if swapip:
        v6.orig_ipv6_src = dstip
        v6.orig_ipv6_dst = srcip
    else:
        v6.orig_ipv6_src = srcip
        v6.orig_ipv6_dst = dstip
    v6.orig_l4proto = IPPROTO_TCP
    if swapport:
        v6.orig_port_src = dstport
        v6.orig_port_dst = srcport
    else:
        v6.orig_port_src = srcport
        v6.orig_port_dst = dstport
    v6.setobjopt(NFCT_SOPT_SETUP_REPLY)
    v6.tcp_state = TCP_CONNTRACK_LISTEN
    v6.timeout = 300
    return v6

def test_create_ipv6_conntrack():
    # ----------- create conntrack entry -----------
    v6 = prepare_v6()
    v6.create()

def test_get_ipv6_conntrack():
    v6 = prepare_v6()
    v6.get()

def test_destroy_ipv6_conntrack():
    v6 = prepare_v6()
    v6.destroy()

def test_create_ipv6_conntrack_again():
    v6 = prepare_v6()
    v6.create()

def test_create_duplicate_ipv6_conntrack():
    # Trying to create the same entry again will raise an error
    with pytest.raises(ConntrackEntryExistsError):
        v6 = prepare_v6()
        v6.create()

def test_get_nonexistent_ipv6_conntrack(dstip=TESTNET2):
    # Trying to get a nonexistent entry should raise an error
    with pytest.raises(ConntrackEntryNotFoundError):
        v6 = prepare_v6()
        v6.orig_ipv6_dst = TESTNET2
        v6.get()

def test_update_ipv6_conntrack_timeout():
    v6 = prepare_v6()
    v6.timeout = 55
    v6.update()

def test_update_ipv6_conntrack_mark():
    v6 = prepare_v6()
    v6.mark = 1337
    v6.update()

def test_create_ipv6_conntrack_swapped():
    # We expect a failure if we try to create the reverse for an existing flow entry
    with pytest.raises(ConntrackEntryExistsError):
        v6 = prepare_v6(swapip=True, swapport=True)
        v6.create()

def test_create_ipv6_conntrack_swapped_ips():
    # Swapping only IPs and not ports should succeed, as that results in a different flow
    v6 = prepare_v6(swapip=True)
    v6.create()

def test_update_ipv6_conntrack_swapped_timeout():
    # Swapping IPs and ports should and then updating should succeed
    v6 = prepare_v6(swapip=True, swapport=True)
    v6.timeout = 77
    v6.update()

def test_update_ipv6_conntrack_tcpstate():
    v6 = prepare_v6()
    v6.tcp_state = TCP_CONNTRACK_ESTABLISHED
    v6.update()

def test_dump():
    conntrack = Conntrack()
    (table, count) = conntrack.dump_table(AF_INET6)
    for entry in table:
        print(entry.format())
    assert count == len(table)

def test_create_a_lot_of_ipv6_conntrack_entries():
    # Use large timeout
    numreps = 10_000
    for _ in range (1, numreps):
        conntrack = Conntrack()
        v6 = ConntrackEntry.new(conntrack)
        v6.orig_l3proto = AF_INET6
        v6.orig_ipv6_src = TESTNET1
        v6.orig_ipv6_dst = randrange((2**128)-1) # 0xffffffffffffffffffffffffffffffff
        v6.orig_l4proto = IPPROTO_TCP
        v6.orig_port_src = randrange(0xffff)
        v6.orig_port_dst = 443
        v6.setobjopt(NFCT_SOPT_SETUP_REPLY)
        v6.tcp_state = TCP_CONNTRACK_LISTEN
        v6.timeout = 333
        v6.create()

def test_cleanup():
    # Remove all conntrack entries where IPv6 source is TESTNET1, TESTNET2 or TESTNET3
    # NOTE if we created a lot of entries with a short timeout, some may expire between dumping the table and removing the table entries
    destroyed = 0
    conntrack = Conntrack()
    (table, count) = conntrack.dump_table(AF_INET6)
    for entry in table:
        if entry.orig_ipv6_src in (TESTNET1, TESTNET2, TESTNET3):
            entry.destroy()
            destroyed += 1
    assert destroyed > 0

def test_delayed_cleanup():
    # Remove all conntrack entries where IPv6 source is TESTNET1, TESTNET2 or TESTNET3
    # now with a delay between dumping the table and removing entries
    # ...so we expect a RuntimeError
    found = 0
    destroyed = 0
    v6 = prepare_v6()
    v6.timeout = 2
    v6.create()
    conntrack = Conntrack()
    (table, count) = conntrack.dump_table(AF_INET6)
    sleep(3)
    for entry in table:
        if entry.orig_ipv6_src in (TESTNET1, TESTNET2, TESTNET3):
            found += 1
            with pytest.raises(ConntrackEntryNotFoundError):
                entry.destroy()
                destroyed += 1
    # We expect 1 entry to be found, but none (successfully) destroyed
    assert found == 1
    assert destroyed == 0
