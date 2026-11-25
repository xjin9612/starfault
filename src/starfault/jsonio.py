"""JSON 檔的讀寫。寫入的格式固定，內容不變時檔案也不變，git diff 以行為單位。"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

# 這一層以下的陣列與物件寫在同一行。
_COMPACT_DEPTH = 2


def dumps(obj: Any, depth: int = 0) -> str:
    """鍵依字母排序；第 _COMPACT_DEPTH 層以下壓成一行，以上每個項目一行。"""
    if depth >= _COMPACT_DEPTH or not isinstance(obj, dict | list) or not obj:
        return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    pad = "  " * (depth + 1)
    if isinstance(obj, dict):
        items = [
            f"{pad}{json.dumps(k, ensure_ascii=False)}: {dumps(obj[k], depth + 1)}"
            for k in sorted(obj)
        ]
        return "{\n" + ",\n".join(items) + "\n" + "  " * depth + "}"
    items = [f"{pad}{dumps(v, depth + 1)}" for v in obj]
    return "[\n" + ",\n".join(items) + "\n" + "  " * depth + "]"


def write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8", newline="\n")
    os.replace(tmp, path)


def write_json(path: Path, obj: Any) -> None:
    write_text_atomic(path, dumps(obj) + "\n")


def write_compact(path: Path, obj: Any) -> None:
    """網站資料用：整份寫成一行。"""
    text = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    write_text_atomic(path, text + "\n")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))
