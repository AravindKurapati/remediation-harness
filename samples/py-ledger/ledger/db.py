"""Database access for the ledger service.

DELIBERATELY VULNERABLE. This is a demo target for the remediation harness, not
example code. Every finding the harness reports against this file is real.
"""

import hashlib
import sqlite3

# FINDING: hardcoded credential (CWE-798)
DB_PASSWORD = "Tr4d3S3ttl3m3nt!2026"
DB_DSN = "postgresql://ledger_svc:Tr4d3S3ttl3m3nt!2026@db.internal:5432/ledger"


def connect(path=":memory:"):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def bootstrap(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY, name TEXT, status TEXT, balance INTEGER);
        CREATE TABLE IF NOT EXISTS trades (
            id INTEGER PRIMARY KEY, account TEXT, symbol TEXT, qty INTEGER);
    """)
    conn.executemany("INSERT INTO accounts (name, status, balance) VALUES (?, ?, ?)",
                     [("Acme Clearing", "active", 100), ("O'Brien Holdings", "active", 250),
                      ("Dormant Ltd", "closed", 0)])
    conn.executemany("INSERT INTO trades (account, symbol, qty) VALUES (?, ?, ?)",
                     [("Acme Clearing", "AAPL", 10), ("O'Brien Holdings", "MSFT", 5)])
    conn.commit()
    return conn


def find_account_by_name(conn, name):
    """FINDING: SQL injection (CWE-89) - untrusted name concatenated into the query."""
    query = "SELECT id, name, status, balance FROM accounts WHERE name = '" + name + "'"
    return conn.execute(query).fetchall()


def find_trades_by_account(conn, account):
    """FINDING: SQL injection (CWE-89) - the same mistake, a different function.

    This one exists so clustering has something real to collapse: same rule, same
    file, same shape as find_account_by_name."""
    query = "SELECT id, account, symbol, qty FROM trades WHERE account = '" + account + "'"
    return conn.execute(query).fetchall()


def list_accounts_sorted(conn, sort_column):
    """FINDING: SQL injection (CWE-89) in an IDENTIFIER position.

    A different shape: a placeholder binds values, never column names, so the fix
    here cannot be parameterization. It has to be an allowlist."""
    query = "SELECT id, name, status, balance FROM accounts ORDER BY " + sort_column
    return conn.execute(query).fetchall()


def password_digest(password):
    """FINDING: weak hash (CWE-327) - MD5, unsalted."""
    return hashlib.md5(password.encode()).hexdigest()
