import pytest

from guardagent.sqlguard import MAX_ROWS, check_sql


def rule(sql):
    return check_sql(sql).rule


@pytest.mark.parametrize("sql", [
    "SELECT count(*) FROM orders",
    "select name, stock from products order by stock limit 3",
    "WITH g AS (SELECT id FROM customers WHERE tier = 'Gold') SELECT count(*) FROM orders WHERE customer_id IN (SELECT id FROM g)",
    "SELECT name FROM products WHERE name = 'drop table; delete from orders --'",  # keywords inside a literal
    "SELECT \"delete\" FROM (SELECT 1 AS \"delete\")",  # quoted identifier, not a keyword
    "SELECT replace(name, 'Tent', 'Shelter') FROM products",
    "SELECT name FROM customers WHERE name LIKE 'Ar%';",  # one trailing semicolon is fine
    "SELECT 1;;  ",
    "SELECT 'café'",  # non-ASCII inside a string literal is fine
    "SELECT 1 UNION SELECT 2",
])
def test_allowed(sql):
    v = check_sql(sql)
    assert v.allowed, v


def test_limit_added_and_rewritten():
    v = check_sql("SELECT * FROM order_items;")
    assert v.allowed and v.rule == "sql.limit_added"
    assert v.sql == f"SELECT * FROM order_items LIMIT {MAX_ROWS}"


@pytest.mark.parametrize("sql,expected", [
    ("SELECT * FROM orders LIMIT 10", "sql.ok"),
    ("SELECT * FROM orders LIMIT 10 OFFSET 400", "sql.ok"),
    ("SELECT * FROM orders LIMIT 400, 10", "sql.ok"),
    (f"SELECT * FROM orders LIMIT {MAX_ROWS + 1}", "sql.limit_too_large"),
    ("SELECT * FROM orders LIMIT 10, 1000", "sql.limit_too_large"),
    ("SELECT * FROM orders LIMIT -1", "sql.limit_not_literal"),           # -1 means unlimited in SQLite
    ("SELECT * FROM orders LIMIT (SELECT 1000)", "sql.limit_not_literal"),
    ("SELECT * FROM orders LIMIT 1e9", "sql.limit_not_literal"),
    ("SELECT * FROM (SELECT * FROM orders LIMIT 5)", "sql.limit_added"),  # inner LIMIT does not count
])
def test_limits(sql, expected):
    assert rule(sql) == expected


@pytest.mark.parametrize("sql,expected", [
    # destructive statements, any case
    ("DROP TABLE orders", "sql.forbidden_keyword"),
    ("dRoP tAbLe orders", "sql.forbidden_keyword"),
    ("DELETE FROM orders", "sql.forbidden_keyword"),
    ("UPDATE products SET unit_price = 0", "sql.forbidden_keyword"),
    ("INSERT INTO orders VALUES (1, 1, '2026-01-01', 'shipped')", "sql.forbidden_keyword"),
    ("ALTER TABLE orders ADD COLUMN x", "sql.forbidden_keyword"),
    ("ATTACH DATABASE 'evil.db' AS evil", "sql.forbidden_keyword"),
    ("PRAGMA writable_schema = 1", "sql.forbidden_keyword"),
    ("CREATE TABLE t (x)", "sql.forbidden_keyword"),
    ("VACUUM", "sql.forbidden_keyword"),
    ("BEGIN; SELECT 1", "sql.multiple_statements"),
    # a CTE in front of a write is valid SQLite
    ("WITH x AS (SELECT 1) DELETE FROM orders", "sql.forbidden_keyword"),
    ("SELECT * FROM orders WHERE id IN (SELECT id FROM orders) AND 1 = (DELETE FROM orders)", "sql.forbidden_keyword"),
    # not a SELECT
    ("VALUES (1)", "sql.not_select"),
    ("EXPLAIN SELECT 1", "sql.not_select"),
    ("REPLACE INTO products (id) VALUES (1)", "sql.not_select"),
    ("ANALYZE", "sql.not_select"),
    ("(SELECT 1)", "sql.not_select"),
    # stacked statements
    ("SELECT 1; DROP TABLE customers", "sql.multiple_statements"),
    ("SELECT count(*) FROM orders; DROP TABLE customers;", "sql.multiple_statements"),
    ("SELECT ';'; SELECT 2", "sql.multiple_statements"),
    # comments that hide text
    ("SELECT 1 -- ; DROP TABLE orders", "sql.comment"),
    ("SELECT id FROM orders --\n; DELETE FROM orders", "sql.comment"),
    ("SELECT /* harmless */ 1", "sql.comment"),
    ("SELECT 1 /* unterminated", "sql.comment"),
    ("SEL/**/ECT 1", "sql.comment"),
    # invisible and non-ASCII characters
    ("SELECT 1​; DROP TABLE orders", "sql.hidden_chars"),
    ("SELECT name FROM customers WHERE tier = 'Gold'​; DROP TABLE orders", "sql.hidden_chars"),
    ("SELECT 1 ‮", "sql.hidden_chars"),
    ("﻿SELECT 1", "sql.hidden_chars"),
    ("SELECT 1\x00; DROP TABLE x", "sql.hidden_chars"),
    ("SELECT 'a⁠b'", "sql.hidden_chars"),
    ("ＤＲＯＰ TABLE orders", "sql.non_ascii"),  # fullwidth DROP
    ("SELECT 1", "sql.non_ascii"),                             # no-break space
    # literals and odd characters
    ("SELECT 'unterminated", "sql.unterminated_literal"),
    ("SELECT \"x", "sql.unterminated_literal"),
    ("SELECT [x", "sql.unterminated_literal"),
    ("SELECT * FROM orders WHERE id = ?", "sql.parameter"),
    ("SELECT :name", "sql.parameter"),
    ("SELECT 1 # comment", "sql.bad_char"),
    ("SELECT {1}", "sql.bad_char"),
    # dangerous functions
    ("SELECT load_extension('/tmp/x.so')", "sql.forbidden_function"),
    ("SELECT LOAD_EXTENSION ('/tmp/x.so')", "sql.forbidden_function"),
    ("SELECT randomblob(1000000000)", "sql.forbidden_function"),
    ("SELECT length(zeroblob(1000000000))", "sql.forbidden_function"),
    ("SELECT readfile('/etc/passwd')", "sql.forbidden_function"),
    # internal objects
    ("SELECT name FROM sqlite_master", "sql.system_table"),
    ("SELECT name FROM SQLITE_SCHEMA", "sql.system_table"),
    ("SELECT name FROM \"sqlite_master\"", "sql.system_table"),
    ("SELECT name FROM [sqlite_master]", "sql.system_table"),
    ("SELECT name FROM `sqlite_master`", "sql.system_table"),
    ("SELECT name FROM 'sqlite_master'", "sql.system_table"),
    ("SELECT name FROM main.sqlite_master", "sql.system_table"),
    ("SELECT * FROM pragma_table_info('orders')", "sql.system_table"),
    # empty
    ("   ", "sql.empty"),
    (";", "sql.empty"),
    ("x" * 2001, "sql.too_long"),
])
def test_blocked(sql, expected):
    v = check_sql(sql)
    assert not v.allowed
    assert v.rule == expected, v
