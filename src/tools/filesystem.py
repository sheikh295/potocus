"""Filesystem tools — complete file create/read/write/update/edit/delete support."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

MAX_READ_CHARS = 20000


def _resolve(path, base_dir=None):
    if path is None or str(path).strip() == "":
        raise ValueError("path must be a non-empty string")
    p = Path(path).expanduser()
    if not p.is_absolute():
        root = Path(base_dir) if base_dir is not None else Path.cwd()
        p = root / p
    return p.resolve(strict=False)


def _clip(text, limit):
    if len(text) <= limit:
        return text
    return text[:limit] + "\n... [truncated]"
def read_file(path, base_dir=None, start_line=None, end_line=None, number_lines=False, max_chars=MAX_READ_CHARS):
    p = _resolve(path, base_dir)
    if not p.exists():
        return f"read_file: not found: {p}"
    if not p.is_file():
        return f"read_file: not a file: {p}"
    try:
        content = p.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"read_file: error reading {p}: {exc}"
    lines = content.splitlines(keepends=False)
    total = len(lines)
    if start_line is not None or end_line is not None:
        s = 1 if start_line is None else max(1, int(start_line))
        e = total if end_line is None else min(total, int(end_line))
        if s > e:
            return f"read_file: invalid range {s}-{e} (file has {total} lines)"
        body_lines = lines[s - 1:e]
        offset = s
    else:
        body_lines = lines
        offset = 1
    if number_lines:
        rendered = "\n".join(f"{i + offset - 1:6d}\t{ln}" for i, ln in enumerate(body_lines))
    else:
        rendered = "\n".join(body_lines)
    if content.endswith("\n") and not (start_line or end_line):
        rendered = rendered + ("\n" if rendered else "")
    header = f"read_file: {p} ({total} lines)"
    if start_line is not None or end_line is not None:
        header += f" [lines {offset}-{offset + len(body_lines) - 1}]"
    return _clip(f"{header}\n{rendered}", max_chars)


def write_file(path, content="", base_dir=None, append=False, create_dirs=True):
    p = _resolve(path, base_dir)
    try:
        if create_dirs:
            p.parent.mkdir(parents=True, exist_ok=True)
        mode = "a" if append else "w"
        with p.open(mode, encoding="utf-8") as handle:
            handle.write(content if content is not None else "")
        size = p.stat().st_size
        return f"write_file: wrote {len(content or '')} chars to {p} (size={size} bytes, append={append})"
    except OSError as exc:
        return f"write_file: error writing {p}: {exc}"
def edit_file(path, old_text, new_text, base_dir=None, replace_all=False):
    p = _resolve(path, base_dir)
    if not p.is_file():
        return f"edit_file: not a file: {p}"
    try:
        content = p.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"edit_file: error reading {p}: {exc}"
    if old_text == "":
        return "edit_file: old_text must be non-empty"
    count = content.count(old_text)
    if count == 0:
        return f"edit_file: old_text not found in {p}"
    if count > 1 and not replace_all:
        return (f"edit_file: old_text occurs {count} times in {p}; "
                "pass replace_all=True or provide more context")
    if replace_all:
        new_content = content.replace(old_text, new_text)
    else:
        new_content = content.replace(old_text, new_text, 1)
    try:
        p.write_text(new_content, encoding="utf-8")
    except OSError as exc:
        return f"edit_file: error writing {p}: {exc}"
    return f"edit_file: replaced {count if replace_all else 1} occurrence(s) in {p}"


def edit_file_lines(path, start_line, end_line, new_content, base_dir=None):
    p = _resolve(path, base_dir)
    if not p.is_file():
        return f"edit_file_lines: not a file: {p}"
    try:
        content = p.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"edit_file_lines: error reading {p}: {exc}"
    raw_lines = content.split("\n")
    if content.endswith("\n"):
        raw_lines = raw_lines[:-1]
    total = len(raw_lines)
    s = max(1, int(start_line))
    if total == 0:
        s = 1
        e = 0
    else:
        e = min(total, int(end_line)) if end_line is not None else min(total, int(start_line))
    if total > 0 and s > total + 1:
        return f"edit_file_lines: start_line {start_line} out of range (file has {total} lines)"
    new_lines = (new_content or "").split("\n")
    if (new_content or "").endswith("\n"):
        new_lines = new_lines[:-1]
    result_lines = raw_lines[:s - 1] + new_lines + raw_lines[e:]
    new_text = "\n".join(result_lines)
    if content.endswith("\n") or (new_content or "").endswith("\n"):
        new_text += "\n"
    try:
        p.write_text(new_text, encoding="utf-8")
    except OSError as exc:
        return f"edit_file_lines: error writing {p}: {exc}"
    replaced = (e - s + 1) if (total > 0 and e >= s) else 0
    return f"edit_file_lines: replaced lines {s}-{max(s, e if total > 0 else s)} in {p} ({replaced} -> {len(new_lines)} lines)"



def create_file(path, content="", base_dir=None, create_dirs=True):
    p = _resolve(path, base_dir)
    if p.exists():
        return f"create_file: already exists: {p}"
    return write_file(path, content, base_dir=base_dir, append=False, create_dirs=create_dirs)

def apply_patch(patch, base_dir=None):
    if not patch or not str(patch).strip():
        return "apply_patch: empty patch"
    root = Path(base_dir) if base_dir is not None else Path.cwd()
    root.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix="potocus-patch-", suffix=".diff")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(patch)
        last_output = ""
        for strip in (1, 0):
            try:
                proc = subprocess.run(
                    ["patch", f"-p{strip}", "--batch", "--no-backup-if-mismatch", "-i", tmp_path],
                    cwd=str(root),
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
            except FileNotFoundError:
                return "apply_patch: `patch` binary not found on host"
            except subprocess.TimeoutExpired:
                return "apply_patch: timed out"
            last_output = (proc.stdout or "") + (proc.stderr or "")
            if proc.returncode == 0:
                return f"apply_patch: applied successfully (strip={strip})\n{last_output.strip()}"
        return f"apply_patch: failed\n{last_output.strip()}"
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


def delete_file(path, base_dir=None, recursive=False):
    p = _resolve(path, base_dir)
    if not p.exists() and not p.is_symlink():
        return f"delete_file: not found: {p}"
    try:
        if p.is_dir() and not p.is_symlink():
            if not recursive:
                return f"delete_file: {p} is a directory; pass recursive=True"
            shutil.rmtree(p)
        else:
            p.unlink()
        return f"delete_file: deleted {p}"
    except OSError as exc:
        return f"delete_file: error deleting {p}: {exc}"


def list_directory(path=".", base_dir=None, recursive=False, max_entries=200):
    p = _resolve(path, base_dir)
    if not p.exists():
        return f"list_directory: not found: {p}"
    if not p.is_dir():
        return f"list_directory: not a directory: {p}"
    entries = []
    try:
        if recursive:
            for root, dirs, files in os.walk(p):
                rel_root = Path(root).relative_to(p)
                for name in sorted(dirs + files):
                    full = Path(root) / name
                    kind = "d" if full.is_dir() else "f"
                    rel = (rel_root / name) if str(rel_root) != "." else Path(name)
                    entries.append(f"{kind} {rel}")
                    if len(entries) >= max_entries:
                        break
                if len(entries) >= max_entries:
                    break
        else:
            for child in sorted(p.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
                kind = "d" if child.is_dir() else "f"
                entries.append(f"{kind} {child.name}")
                if len(entries) >= max_entries:
                    break
    except OSError as exc:
        return f"list_directory: error: {exc}"
    header = f"list_directory: {p} ({len(entries)} shown)"
    if not entries:
        return header + "\n(empty)"
    return _clip(header + "\n" + "\n".join(entries), MAX_READ_CHARS)


def make_directory(path, base_dir=None):
    p = _resolve(path, base_dir)
    try:
        p.mkdir(parents=True, exist_ok=True)
        return f"make_directory: ensured {p}"
    except OSError as exc:
        return f"make_directory: error: {exc}"


def move_file(src, dst, base_dir=None, overwrite=False):
    s = _resolve(src, base_dir)
    d = _resolve(dst, base_dir)
    if not s.exists():
        return f"move_file: source not found: {s}"
    if d.exists() and not overwrite:
        return f"move_file: destination exists: {d} (pass overwrite=True)"
    try:
        d.parent.mkdir(parents=True, exist_ok=True)
        if d.exists() and overwrite:
            if d.is_dir():
                shutil.rmtree(d)
            else:
                d.unlink()
        shutil.move(str(s), str(d))
        return f"move_file: moved {s} -> {d}"
    except OSError as exc:
        return f"move_file: error: {exc}"


def search_files(pattern, path=".", base_dir=None, glob="*", max_results=50, case_sensitive=False, regex=False):
    root = _resolve(path, base_dir)
    if not root.exists():
        return f"search_files: not found: {root}"
    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        compiled = re.compile(pattern if regex else re.escape(pattern), flags)
    except re.error as exc:
        return f"search_files: invalid pattern: {exc}"
    results = []
    if root.is_file():
        files = [root]
    else:
        files = root.rglob(glob)
    for fpath in files:
        if not fpath.is_file():
            continue
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if compiled.search(line):
                rel = fpath.relative_to(root) if root.is_dir() else fpath.name
                results.append(f"{rel}:{i}: {line.strip()}")
                if len(results) >= max_results:
                    break
        if len(results) >= max_results:
            break
    header = f"search_files: pattern={pattern!r} root={root} matches={len(results)}"
    if not results:
        return header + "\n(no matches)"
    return _clip(header + "\n" + "\n".join(results), MAX_READ_CHARS)


def file_info(path, base_dir=None):
    p = _resolve(path, base_dir)
    if not p.exists() and not p.is_symlink():
        return f"file_info: not found: {p}"
    try:
        st = p.stat()
    except OSError as exc:
        return f"file_info: error: {exc}"
    import datetime as _dt
    mtime = _dt.datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds")
    kind = "directory" if p.is_dir() else "file"
    size = st.st_size if p.is_file() else "-"
    return f"file_info: {p}\nkind={kind} size={size} modified={mtime}"
def copy_file(src, dst, base_dir=None, overwrite=False):
    s = _resolve(src, base_dir)
    d = _resolve(dst, base_dir)
    if not s.exists():
        return f"copy_file: source not found: {s}"
    if d.exists() and not overwrite:
        return f"copy_file: destination exists: {d} (pass overwrite=True)"
    try:
        d.parent.mkdir(parents=True, exist_ok=True)
        if s.is_dir():
            if d.exists():
                shutil.rmtree(d)
            shutil.copytree(s, d)
        else:
            shutil.copy2(s, d)
        return f"copy_file: copied {s} -> {d}"
    except OSError as exc:
        return f"copy_file: error: {exc}"
def build_filesystem_tools(runtime):
    from langchain_core.tools import tool as lc_tool

    base = runtime.workspace.root

    @lc_tool("read_file")
    def read_file_tool(path, start_line=None, end_line=None):
        """Read a file from the filesystem.

        Args:
            path: File path (relative to workspace root or absolute).
            start_line: Optional 1-based first line to read.
            end_line: Optional 1-based last line to read (inclusive).
        """
        return read_file(path, base_dir=base, start_line=start_line, end_line=end_line, number_lines=True)

    @lc_tool("write_file")
    def write_file_tool(path, content, append=False):
        """Write content to a file (creates parent dirs). Overwrites unless append=True.

        Args:
            path: File path.
            content: Full text content to write.
            append: If true, append instead of overwriting.
        """
        return write_file(path, content, base_dir=base, append=bool(append))

    @lc_tool("create_file")
    def create_file_tool(path, content=""):
        """Create a new file (fails if it already exists).

        Args:
            path: File path.
            content: Initial content.
        """
        return create_file(path, content, base_dir=base)

    @lc_tool("edit_file")
    def edit_file_tool(path, old_text, new_text, replace_all=False):
        """Replace exact text in a file (search/replace). Prefer over rewriting.

        Args:
            path: File path.
            old_text: Exact text to find.
            new_text: Replacement text.
            replace_all: Replace every occurrence.
        """
        return edit_file(path, old_text, new_text, base_dir=base, replace_all=bool(replace_all))

    @lc_tool("edit_file_lines")
    def edit_file_lines_tool(path, start_line, end_line, new_content):
        """Replace an inclusive 1-based line range with new_content.

        Args:
            path: File path.
            start_line: First line to replace (1-based).
            end_line: Last line to replace (1-based, inclusive).
            new_content: Replacement text (may be multiple lines).
        """
        return edit_file_lines(path, start_line, end_line, new_content, base_dir=base)

    @lc_tool("apply_patch")
    def apply_patch_tool(patch):
        """Apply a unified diff (patch) to files in the workspace.

        Args:
            patch: Unified diff text.
        """
        return apply_patch(patch, base_dir=base)

    @lc_tool("delete_file")
    def delete_file_tool(path, recursive=False):
        """Delete a file or directory.

        Args:
            path: Path to delete.
            recursive: Required to delete non-empty directories.
        """
        return delete_file(path, base_dir=base, recursive=bool(recursive))

    @lc_tool("list_directory")
    def list_directory_tool(path=".", recursive=False):
        """List directory contents.

        Args:
            path: Directory path.
            recursive: Recurse into subdirectories.
        """
        return list_directory(path, base_dir=base, recursive=bool(recursive))

    @lc_tool("make_directory")
    def make_directory_tool(path):
        """Create a directory (and parents).

        Args:
            path: Directory path.
        """
        return make_directory(path, base_dir=base)

    @lc_tool("move_file")
    def move_file_tool(src, dst, overwrite=False):
        """Move or rename a file/directory.

        Args:
            src: Source path.
            dst: Destination path.
            overwrite: Overwrite destination if exists.
        """
        return move_file(src, dst, base_dir=base, overwrite=bool(overwrite))

    @lc_tool("copy_file")
    def copy_file_tool(src, dst, overwrite=False):
        """Copy a file or directory.

        Args:
            src: Source path.
            dst: Destination path.
            overwrite: Overwrite destination if exists.
        """
        return copy_file(src, dst, base_dir=base, overwrite=bool(overwrite))

    @lc_tool("search_files")
    def search_files_tool(pattern, path=".", glob="*", regex=False):
        """Search file contents for a pattern (like grep).

        Args:
            pattern: Text or regex pattern.
            path: Root path to search.
            glob: Filename glob filter.
            regex: Treat pattern as regex.
        """
        return search_files(pattern, path=path, base_dir=base, glob=glob, regex=bool(regex))

    @lc_tool("file_info")
    def file_info_tool(path):
        """Get metadata about a path.

        Args:
            path: Path to inspect.
        """
        return file_info(path, base_dir=base)

    return [
        read_file_tool, write_file_tool, create_file_tool, edit_file_tool,
        edit_file_lines_tool, apply_patch_tool, delete_file_tool,
        list_directory_tool, make_directory_tool, move_file_tool, copy_file_tool,
        search_files_tool, file_info_tool,
    ]

