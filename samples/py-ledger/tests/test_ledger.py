"""The project's existing suite. Green before any patch, and must stay green after."""

from ledger import db


def setup_conn():
    return db.bootstrap(db.connect())


def test_find_account_returns_the_match():
    conn = setup_conn()
    rows = db.find_account_by_name(conn, "Acme Clearing")
    assert len(rows) == 1 and rows[0]["balance"] == 100


def test_find_trades_returns_the_match():
    conn = setup_conn()
    rows = db.find_trades_by_account(conn, "Acme Clearing")
    assert len(rows) == 1 and rows[0]["symbol"] == "AAPL"


def test_sorted_listing_orders_by_the_named_column():
    conn = setup_conn()
    rows = db.list_accounts_sorted(conn, "balance")
    assert [r["balance"] for r in rows] == [0, 100, 250]


def test_unknown_account_returns_nothing():
    conn = setup_conn()
    assert db.find_account_by_name(conn, "Nobody Ltd") == []
