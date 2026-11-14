"""通用辅助函数。"""
from __future__ import annotations

import os
from typing import Optional

from .models import Evidence


def read_snapshot_file(abs_path: str) -> list[str]:
    """按文本读取快照文件,返回保留换行符的行列表。

    快照属于不可信数据,这里只用 utf-8 + replace 容错,
    不执行其中任何内容。
    """
    with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.readlines()


def strip_newline(line: str) -> str:
    if line.endswith("\n"):
        line = line[:-1]
    if line.endswith("\r"):
        line = line[:-1]
    return line


def make_evidence(rel_path: str, lineno: int, raw_line: str) -> Evidence:
    return Evidence(path=rel_path, line=lineno, text=strip_newline(raw_line))


def logical_join(physical_lines: list[tuple[int, str]]) -> list[tuple[int, str, list[int]]]:
    """处理反斜杠续行。

    输入 [(物理行号, 去掉换行符的文本), ...],
    输出 [(起始行号, 拼接后的逻辑行, [参与拼接的全部物理行号]), ...]。

    规则(与 sudoers/pam 一致):
    - 以 ``\\`` 结尾的行与下一行拼接,拼接处替换为单个空格;
    - 续行行的行首空白折叠;
    - 注释行/空行不参与续行。
    """
    result: list[tuple[int, str, list[int]]] = []
    buf: Optional[str] = None
    start_line = 0
    members: list[int] = []

    for lineno, text in physical_lines:
        stripped = text.strip()
        is_comment = stripped.startswith("#")
        is_blank = stripped == ""
        if is_comment or is_blank:
            if buf is not None:
                # 前一个续行块未正常结束,先落盘
                result.append((start_line, buf, members))
                buf, start_line, members = None, 0, []
            continue

        if buf is None:
            buf = text.rstrip()
            start_line = lineno
            members = [lineno]
        else:
            buf = buf[:-1].rstrip() + " " + text.strip()
            members.append(lineno)

        if not buf.endswith("\\"):
            result.append((start_line, buf, members))
            buf, start_line, members = None, 0, []

    if buf is not None:  # 文件以续行符结尾
        result.append((start_line, buf, members))
    return result


def split_tokens(text: str) -> list[str]:
    """按空白分词,支持单/双引号(引号内空白保留)与 PAM 方括号组。

    用于 sudoers、pam 这类以空格分隔的配置。
    引号会被去除;反斜杠可转义下一个字符;
    ``[success=1 default=bad]`` 这类 PAM 控制字段整体作为一个 token。
    """
    tokens: list[str] = []
    cur: list[str] = []
    quote: Optional[str] = None
    bracket_depth = 0
    escaped = False
    for ch in text:
        if escaped:
            cur.append(ch)
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if quote:
            if ch == quote:
                quote = None
            else:
                cur.append(ch)
            continue
        if ch in ("'", '"'):
            quote = ch
            continue
        if ch == "[":
            bracket_depth += 1
            cur.append(ch)
            continue
        if ch == "]":
            bracket_depth = max(0, bracket_depth - 1)
            cur.append(ch)
            continue
        if ch.isspace() and bracket_depth == 0:
            if cur:
                tokens.append("".join(cur))
                cur = []
            continue
        cur.append(ch)
    if cur:
        tokens.append("".join(cur))
    return tokens


def fnmatch_any(name: str, patterns: list[str]) -> bool:
    import fnmatch

    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


def norm_rel(path: str) -> str:
    """快照内相对路径统一用正斜杠。"""
    return path.replace(os.sep, "/").lstrip("/")
