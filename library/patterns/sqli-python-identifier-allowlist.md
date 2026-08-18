# Python: dynamic identifier in SQL to an allowlist

- **cwe**: CWE-89
- **category**: injection
- **applies to**: `.py`
- **shape**: identifier-injection — the untrusted token lands where an *identifier* goes

## When this applies

An untrusted value chooses a column, a table, or a sort direction: `ORDER BY`,
`GROUP BY`, a column name in a `SELECT`.

**Parameterization cannot fix this.** A placeholder binds a value; it cannot name a
column. This is the single most common way a SQL injection fix goes wrong — the fixer
reaches for the pattern above, produces `ORDER BY ?`, and either the driver rejects it
or the query silently sorts by a constant and the test suite never notices.

## The transform

Map the untrusted value through a fixed allowlist of permitted identifiers, and reject
anything not in it. The allowlist is code, not configuration, so adding a column is a
reviewed change.

```python
# before
query = "SELECT id, name FROM accounts ORDER BY " + sort_column

# after
SORTABLE = {"id": "id", "name": "name", "status": "status", "balance": "balance"}

column = SORTABLE.get(sort_column)
if column is None:
    raise ValueError(f"cannot sort by {sort_column!r}")
query = f"SELECT id, name FROM accounts ORDER BY {column}"
```

The value that reaches the query is one the allowlist produced, never one the caller
supplied. Note the mapping returns its own literal rather than the key — so even a key
collision cannot pass a caller's string through.

## Required test

```python
def test_unknown_sort_column_is_refused():
    with pytest.raises(ValueError):
        db.list_accounts_sorted(conn, "id; DROP TABLE accounts")

def test_permitted_column_still_sorts():
    rows = db.list_accounts_sorted(conn, "balance")
    assert [r["balance"] for r in rows] == [0, 100, 250]
```

## Closure evidence

- the diff, showing the allowlist and the refusal path
- the refusal test failing against the unpatched tree
- a re-scan showing the originating rule no longer fires
