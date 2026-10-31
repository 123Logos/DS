"""把 `.sql` 迁移文件切成可逐条执行的语句。

为什么不能用 `sql.split(";")`
------------------------------
`migrations/008_legacy_assets_bridge.sql` 的镜像触发器需要在旧账本被扣成负数时
`SIGNAL SQLSTATE '45000'` 主动报错，触发器体因此是 `BEGIN ... IF ... END IF; ... END`
复合语句，**内部含分号**。朴素的 `split(";")` 会把它切成若干碎片，`cur.execute`
必然语法错误。

本模块实现一个最小但严格的 SQL 词法扫描：

* 识别 `'...'`、`"..."`、`` `...` `` 三种引用，处理 `\\` 转义与引号双写转义；
* 跳过 `-- `（MySQL 要求后跟空白）、`#` 行注释与 `/* ... */` 块注释，
  注释不进入语句文本（避免注释里的分号、百分号干扰），但用空格占位，防止把
  相邻 token 粘连成新 token；
* 支持 mysql CLI 的 `DELIMITER xx` 指令（只在语句起始位置生效），
  `DELIMITER ;` 恢复默认，因此同一份文件既能被 `mysql < file.sql` 执行，
  也能被 `scripts/migrate.py` 逐条执行；
* 只在引用与注释之外按当前分隔符切分，切出的语句不含结尾分隔符。

对不含 `DELIMITER` 的普通迁移文件，结果与 `split(";")` 的语句条数一致。
"""
from __future__ import annotations

#: 默认语句分隔符
DEFAULT_DELIMITER = ";"

#: `DELIMITER` 指令关键字
_DELIMITER_KEYWORD = "DELIMITER"

#: 引号集合（字符串与标识符）
_QUOTES = ("'", '"', "`")


class SqlSplitError(ValueError):
    """迁移文件无法切分（引号/注释未闭合、DELIMITER 指令非法）。"""


def split_sql_statements(sql: str) -> list[str]:
    """按当前分隔符把 SQL 文本切成语句列表（去掉注释与结尾分隔符）。"""
    statements: list[str] = []
    buffer: list[str] = []
    delimiter = DEFAULT_DELIMITER
    index = 0
    length = len(sql)
    # 去掉 UTF-8 BOM，否则第一条语句会带上 \ufeff
    if sql.startswith("\ufeff"):
        index = 1

    def _buffer_blank() -> bool:
        return "".join(buffer).strip() == ""

    def _keep_space() -> None:
        """注释被丢弃后补一个空格，避免前后 token 粘连。"""
        if buffer and not buffer[-1].endswith((" ", "\t", "\n")):
            buffer.append(" ")
        elif not buffer:
            buffer.append(" ")

    while index < length:
        char = sql[index]

        # 行注释：`# ...` 或 `-- ` 到行尾
        if char == "#" or (char == "-" and sql.startswith("--", index) and (
            index + 2 >= length or sql[index + 2].isspace()
        )):
            newline = sql.find("\n", index)
            index = length if newline < 0 else newline
            _keep_space()
            continue

        # 块注释
        if char == "/" and sql.startswith("/*", index):
            end = sql.find("*/", index + 2)
            if end < 0:
                raise SqlSplitError("块注释未闭合: /* ...")
            index = end + 2
            _keep_space()
            continue

        # 字符串 / 反引号标识符
        if char in _QUOTES:
            quote = char
            cursor = index + 1
            while cursor < length:
                if sql[cursor] == "\\":
                    cursor += 2
                    continue
                if sql[cursor] == quote:
                    # 双写转义（'' 或 "" 或 ``）继续留在字符串内
                    if cursor + 1 < length and sql[cursor + 1] == quote:
                        cursor += 2
                        continue
                    cursor += 1
                    break
                cursor += 1
            else:
                raise SqlSplitError(f"引号未闭合: {quote}")
            buffer.append(sql[index:cursor])
            index = cursor
            continue

        # DELIMITER 指令：只允许出现在语句起始处（缓冲区为空）
        if (
            _buffer_blank()
            and sql[index:index + len(_DELIMITER_KEYWORD)].upper() == _DELIMITER_KEYWORD
            and (index + len(_DELIMITER_KEYWORD) >= length
                 or sql[index + len(_DELIMITER_KEYWORD)].isspace())
        ):
            newline = sql.find("\n", index)
            line_end = length if newline < 0 else newline
            parts = sql[index:line_end].strip().split(None, 1)
            if len(parts) != 2 or not parts[1].strip():
                raise SqlSplitError(f"DELIMITER 指令缺少分隔符: {sql[index:line_end]!r}")
            delimiter = parts[1].strip()
            index = line_end
            continue

        if sql.startswith(delimiter, index):
            statement = "".join(buffer).strip()
            buffer = []
            index += len(delimiter)
            if statement:
                statements.append(statement)
            continue

        buffer.append(char)
        index += 1

    trailing = "".join(buffer).strip()
    if trailing:
        statements.append(trailing)
    return statements


__all__ = ["DEFAULT_DELIMITER", "SqlSplitError", "split_sql_statements"]
