"""Defense in depth: the executor refuses writes even when the guard is bypassed."""
import pytest

from guardagent.paths import DB_PATH
from guardagent.report import db_fingerprint
from guardagent.tools import DbError, SqlExecutor


@pytest.fixture(scope="module")
def ex():
    return SqlExecutor(DB_PATH)


@pytest.mark.parametrize("sql", [
    "DELETE FROM orders",
    "DROP TABLE customers",
    "UPDATE products SET unit_price = 0",
    "INSERT INTO customers (id, name, city, country, tier, joined_on) VALUES (999, 'x', 'y', 'US', 'Gold', '2026-01-01')",
    "CREATE TABLE x (a)",
    "ATTACH DATABASE ':memory:' AS m",
    "PRAGMA query_only = OFF",
    "SELECT load_extension('nothing')",
    "SELECT randomblob(10)",
])
def test_writes_refused_without_guard(ex, sql):
    before = db_fingerprint()
    with pytest.raises(DbError) as e:
        ex.run(sql)
    assert e.value.rule in ("db.write_refused", "db.error")
    assert db_fingerprint() == before


def test_runaway_query_is_stopped(ex):
    sql = "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT count(*) FROM c"
    with pytest.raises(DbError) as e:
        ex.run(sql)
    assert e.value.rule == "db.too_slow"


def test_row_cap(ex):
    r = ex.run("SELECT * FROM order_items")
    assert r["row_count"] == 50 and r["truncated"] is True


def test_read_works(ex):
    assert ex.run("SELECT count(*) FROM orders")["rows"] == [[200]]
