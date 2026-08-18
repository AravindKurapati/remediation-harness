# Python: string-concatenated SQL to a parameterized statement

- **cwe**: CWE-89
- **category**: injection
- **applies to**: `.py`
- **shape**: value-injection — the untrusted token lands where a *value* goes

## When this applies

An untrusted value is concatenated or interpolated into a SQL string, and it lands in
a **data position**: a comparison, an `INSERT` value, a `SET`, a `LIMIT`.

It does **not** apply when the value lands in an identifier position — a column name,
`ORDER BY`, a table name. Placeholders bind values and never identifiers, so applying
this pattern there produces `ORDER BY ?`, which drivers either reject or satisfy by
sorting on a constant. Use `sqli-python-identifier-allowlist` for that.

## The transform

Replace the concatenation with a placeholder and pass the value as a parameter. The
driver then sends the statement and the data separately, so no input can change the
statement's structure.

```python
# before
query = "SELECT id, name FROM accounts WHERE name = '" + name + "'"
return conn.execute(query).fetchall()

# after
query = "SELECT id, name FROM accounts WHERE name = ?"
return conn.execute(query, (name,)).fetchall()
```

Do not escape or strip quotes instead. Escaping is a filter that has to be right about
every encoding the database accepts; parameterization removes the question.

## Required test

A test that passes a value containing a SQL metacharacter and asserts it is treated as
**data**, plus one asserting a legitimate value containing a quote still works.

```python
def test_quote_in_name_is_data_not_syntax():
    conn = db.bootstrap(db.connect())
    rows = db.find_account_by_name(conn, "' OR '1'='1")
    assert rows == []          # against the unpatched code this returns every row

def test_legitimate_quote_still_matches():
    conn = db.bootstrap(db.connect())
    rows = db.find_account_by_name(conn, "O'Brien Holdings")
    assert len(rows) == 1      # against the unpatched code this raises a syntax error
```

The second test matters as much as the first: it is what catches a "fix" that strips
quotes and quietly breaks every customer whose name contains one.

## Closure evidence

- the diff, showing concatenation replaced by a placeholder and a parameter tuple
- both tests failing against the unpatched tree, for the two different reasons above
- a re-scan showing the originating rule no longer fires at that location
