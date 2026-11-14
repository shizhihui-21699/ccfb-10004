"""零依赖的 YAML 子集解析器。

等保核查环境通常离线,不能假设目标机装有 PyYAML,因此规则加载只依赖
标准库。本解析器支持规则文件实际用到的语法:

- 块式 map(``key: value``)与序列(``- item``),缩进表示层级;
- 单引号、双引号标量,裸标量;
- 行内注释(``#``,前面需是行首或空白);
- 布尔 true/false、null/~、整数、字符串自动识别;
- 列表项内联键值(``- id: x``)及后续同缩进续行键;
- 顶层 include 列表等简单序列。

不支持锚点、流式 ``[..]``/``{..}``、多文档分隔符——规则文件不需要。
解析失败时抛出 ``YamlError`` 并带行号,避免静默吞错。
"""
from __future__ import annotations

from typing import Any, Optional


class YamlError(ValueError):
    def __init__(self, message: str, line: int) -> None:
        super().__init__(f"YAML 解析错误(第 {line} 行): {message}")
        self.line = line


def _strip_comment(text: str) -> str:
    """去掉行内注释,尊重引号。"""
    quote: Optional[str] = None
    escaped = False
    for i, ch in enumerate(text):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and quote == '"':
            escaped = True
            continue
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            continue
        if ch == "#" and (i == 0 or text[i - 1].isspace()):
            return text[:i]
    return text


def _unquote_scalar(token: str) -> str:
    token = token.strip()
    if len(token) >= 2 and token[0] == token[-1] and token[0] in ("'", '"'):
        body = token[1:-1]
        if token[0] == '"':
            out: list[str] = []
            esc = False
            for ch in body:
                if esc:
                    mapping = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"'}
                    out.append(mapping.get(ch, ch))
                    esc = False
                elif ch == "\\":
                    esc = True
                else:
                    out.append(ch)
            return "".join(out)
        return body
    return token


def _split_flow_items(body: str) -> list[str]:
    """切分 flow 容器内部的逗号项,尊重引号与嵌套。"""
    items: list[str] = []
    depth = 0
    quote: Optional[str] = None
    cur: list[str] = []
    for ch in body:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            cur.append(ch)
            continue
        if ch in "[{":
            depth += 1
            cur.append(ch)
            continue
        if ch in "]}":
            depth -= 1
            cur.append(ch)
            continue
        if ch == "," and depth == 0:
            items.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    if "".join(cur).strip():
        items.append("".join(cur).strip())
    return items


def _parse_flow(token: str) -> Any:
    """解析单行 flow 标量:[a, b] / {key: value}。"""
    t = token.strip()
    if t.startswith("[") and t.endswith("]"):
        body = t[1:-1].strip()
        if not body:
            return []
        return [_parse_flow(x) if x.strip()[0] in "[{" else _coerce(x)
                for x in _split_flow_items(body)]
    if t.startswith("{") and t.endswith("}"):
        body = t[1:-1].strip()
        if not body:
            return {}
        out: dict[str, Any] = {}
        for item in _split_flow_items(body):
            k, _, v = item.partition(":")
            out[_unquote_scalar(k.strip())] = _parse_flow(v.strip()) \
                if v.strip()[:1] in "[{" else _coerce(v.strip())
        return out
    return _coerce(t)


def _coerce(token: str) -> Any:
    t = token.strip()
    if t == "":
        return None
    if len(t) >= 2 and t[0] == t[-1] and t[0] in ("'", '"'):
        return _unquote_scalar(t)
    if (t.startswith("[") and t.endswith("]")) or (t.startswith("{") and t.endswith("}")):
        return _parse_flow(t)
    low = t.lower()
    # 注意:刻意不把 yes/no/on/off 当作布尔——在 sshd/sudoers 等配置里
    # 它们是字符串取值,强制转布尔会让规则比对静默失效。
    if low == "true":
        return True
    if low == "false":
        return False
    if low in ("null", "~"):
        return None
    try:
        return int(t)
    except ValueError:
        pass
    try:
        return float(t)
    except ValueError:
        pass
    return t


class _Line:
    __slots__ = ("indent", "text", "lineno", "dash_col", "block_style")

    def __init__(self, indent: int, text: str, lineno: int, dash_col: int,
                 block_style: str = "") -> None:
        self.indent = indent
        self.text = text
        self.lineno = lineno
        # "-" 所在列;非序列项为 -1
        self.dash_col = dash_col
        # 块标量指示符: "|" 保留换行, ">" 折叠换行
        self.block_style = block_style

    @property
    def is_dash(self) -> bool:
        return self.dash_col >= 0


def _tokenize(src: str) -> list[_Line]:
    raw_lines = src.splitlines()
    out: list[_Line] = []
    i = 0
    while i < len(raw_lines):
        idx = i + 1
        content = _strip_comment(raw_lines[i].rstrip("\r\n"))
        if content.strip() == "":
            i += 1
            continue
        indent = len(content) - len(content.lstrip(" "))
        if "\t" in content[:indent]:
            raise YamlError("缩进不允许使用 Tab", idx)
        body = content.strip()
        style = ""
        if body == "|" or body == ">" or body.startswith("| ") or body.startswith("> "):
            style = body[0]
            body = ""
        # 处理 "key: |" / "key: >" 这类行尾块指示符:保留 key 行,
        # 仅记录需要块模式,后续行在下面统一吞掉。
        trailing_block = ""
        if not style and ":" in body:
            tail = body.rsplit(":", 1)[1].strip()
            if tail in ("|", ">"):
                trailing_block = tail
        if body == "-" or body.startswith("- "):
            dash_col = indent
            after = body[1:].lstrip()
            line = _Line(indent, after, idx, dash_col, trailing_block)
        else:
            line = _Line(indent, body, idx, -1, trailing_block)
        out.append(line)

        # 块标量:吞掉所有比父缩进更深的物理行(含空行),按风格拼接
        block_marker = style or trailing_block
        if block_marker:
            block_lines: list[tuple[int, str]] = []
            j = i + 1
            while j < len(raw_lines):
                raw = raw_lines[j]
                if raw.strip() == "":
                    block_lines.append((-1, ""))
                    j += 1
                    continue
                block_indent = len(raw) - len(raw.lstrip(" "))
                if block_indent <= indent:
                    break
                block_lines.append((block_indent, raw.rstrip("\r\n")))
                j += 1
            # 去尾部空行
            while block_lines and block_lines[-1][1] == "":
                block_lines.pop()
            min_indent = min((b for b, _ in block_lines if b >= 0), default=indent + 1)
            text_parts = [(t if b < 0 else t[min_indent:]) for b, t in block_lines]
            joined = "\n".join(text_parts) if block_marker == "|" else " ".join(
                t for t in text_parts if t)
            # 合成行放在比父键更深的缩进,保持 map 层级;靠 __block__ 标记识别
            out.append(_Line(indent + 1, joined, idx, -1, "__block__"))
            i = j
            continue

        # 裸标量续行:更深缩进、非序列项、非键值行 -> 折行拼接到上一逻辑行
        # (规则文件里 rationale 等长文本可能手工折行)
        while i + 1 < len(raw_lines):
            nxt_raw = raw_lines[i + 1]
            if nxt_raw.strip() == "":
                break
            nxt_indent = len(nxt_raw) - len(nxt_raw.lstrip(" "))
            nxt_body = nxt_raw.strip()
            if nxt_indent <= indent:
                break
            if nxt_body.startswith("- ") or nxt_body == "-":
                break
            if _is_kv(nxt_body) or nxt_body in ("|", ">"):
                break
            line.text = line.text + " " + nxt_body
            i += 1
        i += 1
    return out


def _split_key_value(text: str, lineno: int) -> tuple[str, str]:
    quote: Optional[str] = None
    escaped = False
    for i, ch in enumerate(text):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and quote == '"':
            escaped = True
            continue
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            continue
        if ch == ":" and (i == len(text) - 1 or text[i + 1].isspace()):
            val = text[i + 1 :].strip()
            if val in ("|", ">"):
                val = ""  # 块标量,值由后续缩进行提供
            return _unquote_scalar(text[:i].strip()), val
    raise YamlError(f"无法识别的配置行: {text!r}", lineno)


def _is_kv(text: str) -> bool:
    quote: Optional[str] = None
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            continue
        if ch == ":" and (i == len(text) - 1 or text[i + 1].isspace()):
            return True
    return False


class _Parser:
    def __init__(self, lines: list[_Line]) -> None:
        self.lines = lines
        self.pos = 0

    def parse(self) -> Any:
        if not self.lines:
            return None
        return self._parse_node(self.lines[0].indent)

    def _peek(self) -> Optional[_Line]:
        return self.lines[self.pos] if self.pos < len(self.lines) else None

    def _parse_node(self, indent: int) -> Any:
        line = self._peek()
        if line is None or line.indent < indent:
            return None
        if line.is_dash:
            return self._parse_seq(line.dash_col)
        return self._parse_map(line.indent)

    def _parse_seq(self, dash_col: int) -> list[Any]:
        items: list[Any] = []
        while True:
            line = self._peek()
            if line is None or not line.is_dash or line.dash_col != dash_col:
                break
            self.pos += 1
            if line.text == "":
                # "-" 独占一行,子结构在更深缩进
                nxt = self._peek()
                items.append(self._parse_node(nxt.indent)
                             if nxt is not None and nxt.indent > dash_col else None)
                continue
            if _is_kv(line.text):
                items.append(self._parse_inline_map(line, dash_col))
            else:
                items.append(_coerce(line.text))
        return items

    def _parse_inline_map(self, first_line: _Line, dash_col: int) -> dict[str, Any]:
        # 内联键实际列 = dash 列 + 2;但常见写法把续行键缩进到更深
        # (如 "- id: x" 在 2 列,后续 "  title: y" 在 4 列),
        # 因此 map 键列取"第一个后续非 dash 行"的缩进。
        inline_col = dash_col + 2
        nxt = self._peek()
        key_col = nxt.indent if (nxt is not None and not nxt.is_dash
                                 and nxt.indent > dash_col) else inline_col
        mapping: dict[str, Any] = {}
        key, val = _split_key_value(first_line.text, first_line.lineno)
        self._fill(mapping, key, val, inline_col, first_line.lineno,
                   key_col, first_line.block_style)
        while True:
            nxt = self._peek()
            if nxt is None:
                break
            if nxt.is_dash:
                if nxt.dash_col <= dash_col:
                    break
            elif nxt.indent < key_col:
                break
            if not nxt.is_dash and nxt.indent == key_col:
                if nxt.block_style == "__block__":
                    # 块标量合成行不应出现在键位置,防御性跳过
                    self.pos += 1
                    continue
                self.pos += 1
                k, v = _split_key_value(nxt.text, nxt.lineno)
                self._fill(mapping, k, v, key_col, nxt.lineno,
                           key_col, nxt.block_style)
            elif not nxt.is_dash and nxt.block_style == "__block__":
                # 属于上一个键的块标量,正常应已被 _fill 消费;兜底跳过
                self.pos += 1
            else:
                break
        return mapping

    def _parse_map(self, indent: int) -> dict[str, Any]:
        mapping: dict[str, Any] = {}
        while True:
            line = self._peek()
            if line is None or line.is_dash or line.indent != indent:
                break
            self.pos += 1
            key, val = _split_key_value(line.text, line.lineno)
            self._fill(mapping, key, val, indent, line.lineno,
                       indent, line.block_style)
        return mapping

    def _fill(self, mapping: dict[str, Any], key: str, val: str,
              parent_indent: int, lineno: int, key_col: Optional[int] = None,
              block_style: str = "") -> None:
        if val != "":
            mapping[key] = _coerce(val)
            return
        nxt = self._peek()
        if block_style or (nxt is not None and nxt.block_style == "__block__"):
            # 块标量已在 tokenize 阶段拼接为单行文本
            if nxt is not None and nxt.block_style == "__block__":
                self.pos += 1
                mapping[key] = nxt.text
            else:
                mapping[key] = ""
            return
        # 嵌套块只需要比 map 键列更深;parent_indent 用于无续行键的退化情形
        floor = key_col if key_col is not None else parent_indent
        if nxt is None or nxt.indent <= floor:
            mapping[key] = None
            return
        mapping[key] = self._parse_node(nxt.indent)


def loads(src: str) -> Any:
    """解析 YAML 文本。"""
    return _Parser(_tokenize(src)).parse()


def load_file(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return loads(fh.read())
