"""`core.sql_split` 的纯单元测试（不依赖数据库）。

重点：008 的镜像触发器体是 `BEGIN ... END` 复合语句，内含分号，
朴素的 `sql.split(";")` 会把它切碎，必须靠 DELIMITER 指令 + 词法扫描正确处理。
"""
from __future__ import annotations

from pathlib import Path

import pytest

from core.sql_split import DEFAULT_DELIMITER, SqlSplitError, split_sql_statements

ROOT = Path(__file__).resolve().parent.parent
MIGRATIONS = ROOT / "migrations"


def test_plain_statements_without_delimiter():
    assert split_sql_statements("SELECT 1; SELECT 2;") == ["SELECT 1", "SELECT 2"]
    assert split_sql_statements("SELECT 1") == ["SELECT 1"]
    assert split_sql_statements("   \n  ") == []


def test_semicolon_inside_string_is_not_a_separator():
    statements = split_sql_statements("INSERT INTO t VALUES ('a;b'); SELECT 2;")
    assert statements == ["INSERT INTO t VALUES ('a;b')", "SELECT 2"]


def test_escaped_quote_keeps_string_open():
    statements = split_sql_statements(r"SELECT 'it''s; here', 'a\';b';")
    assert len(statements) == 1
    assert "it''s; here" in statements[0]


def test_line_and_block_comments_are_dropped():
    sql = "-- SELECT 0;\n# SELECT 00;\nSELECT 1; /* SELECT 2; */ SELECT 3;"
    assert split_sql_statements(sql) == ["SELECT 1", "SELECT 3"]


def test_delimiter_directive_supports_compound_bodies():
    sql = """
    DROP TRIGGER IF EXISTS trg;
    DELIMITER $$
    CREATE TRIGGER trg AFTER UPDATE ON t FOR EACH ROW
    BEGIN
        IF NEW.x < 0 THEN
            SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'x';
        END IF;
        UPDATE u SET y = 1 WHERE id = NEW.id;
    END$$
    DELIMITER ;
    SELECT 1;
    """
    statements = split_sql_statements(sql)
    assert len(statements) == 3
    assert statements[0].startswith("DROP TRIGGER")
    assert statements[1].startswith("CREATE TRIGGER")
    assert statements[1].rstrip().endswith("END")
    # 复合体内部的分号必须原样保留
    assert statements[1].count(";") == 3
    assert statements[2] == "SELECT 1"


def test_braces_required_by_delimiter_directive():
    with pytest.raises(SqlSplitError):
        split_sql_statements("DELIMITER\nSELECT 1;")


def test_unclosed_quote_raises():
    with pytest.raises(SqlSplitError):
        split_sql_statements("SELECT 'oops;")


def test_existing_migrations_keep_statement_count():
    """切分器对历史迁移不得吞掉或多切出语句（回归保护）。"""
    for path in sorted(MIGRATIONS.glob("*.sql")):
        sql = path.read_text(encoding="utf-8")
        if "DELIMITER" in sql:
            continue
        naive = [stmt for stmt in sql.split(";") if stmt.strip()]
        split = split_sql_statements(sql)
        # 朴素切分会把「只有注释的尾巴」也算一条语句，这里逐块再切一次对齐口径
        expected = sum(len(split_sql_statements(chunk)) for chunk in naive)
        assert len(split) == expected, f"{path.name}: {len(split)} != {expected}"
        # 注释不应残留在语句开头
        assert all(not stmt.lstrip().startswith(("--", "#")) for stmt in split), path.name


def test_bridge_migration_splits_into_five_statements():
    statements = split_sql_statements((MIGRATIONS / "008_legacy_assets_bridge.sql").read_text(encoding="utf-8"))
    assert len(statements) == 5
    lowered = [stmt.split()[0].upper() for stmt in statements]
    assert lowered == ["DROP", "CREATE", "DROP", "CREATE", "CREATE"]
    # 两个触发器都必须带负数守卫
    assert sum("SIGNAL SQLSTATE '45000'" in stmt for stmt in statements) == 2
    assert all("GREATEST" not in stmt for stmt in statements), "不得再用夹 0 的方式容忍负值"
    assert DEFAULT_DELIMITER == ";"
