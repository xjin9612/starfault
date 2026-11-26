"""狀態檔的 JSON 格式。格式一變，state/ 每個檔案都會出現 diff。"""

from __future__ import annotations

from pathlib import Path

from starfault.jsonio import dumps, write_json


def test_two_levels_one_item_per_line_deeper_levels_compact() -> None:
    data = {
        "b": [["CVE-2026-1", 9.8, "critical", {"0.1": "2026-11-25"}], []],
        "a": {"z": {"y": 1, "x": "測試"}, "empty": {}},
        "n": None,
    }
    assert dumps(data) == (
        "{\n"
        '  "a": {\n'
        '    "empty": {},\n'
        '    "z": {"x":"測試","y":1}\n'
        "  },\n"
        '  "b": [\n'
        '    ["CVE-2026-1",9.8,"critical",{"0.1":"2026-11-25"}],\n'
        "    []\n"
        "  ],\n"
        '  "n": null\n'
        "}"
    )


def test_write_json_ends_with_newline_and_is_stable(tmp_path: Path) -> None:
    path = tmp_path / "x" / "state.json"
    write_json(path, {"b": 1, "a": [1, 2]})
    first = path.read_bytes()
    write_json(path, {"a": [1, 2], "b": 1})
    assert path.read_bytes() == first
    assert first.endswith(b"}\n") and b"\r" not in first
