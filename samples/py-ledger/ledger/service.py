"""HTTP-facing layer. Untrusted input enters here and reaches ledger.db."""

from . import db


def account_lookup(conn, request_params):
    """`name` arrives from a query string. Untrusted."""
    return db.find_account_by_name(conn, request_params.get("name", ""))


def trade_lookup(conn, request_params):
    return db.find_trades_by_account(conn, request_params.get("account", ""))


def account_table(conn, request_params):
    return db.list_accounts_sorted(conn, request_params.get("sort", "id"))
