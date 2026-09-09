"""Tests for utils/wordlists.py and the list_wordlists tool.

Covers:
- preflight_wordlists ok/missing/empty tree cases.
- discover_wordlists walks, skips .git, derives categories.
- list_wordlists tool: catalog shape, category filter, limit cap, warnings
  surfaced, and next_hints pointing at run_ffuf/run_hydra.
"""

import os
from pathlib import Path

import pytest

from utils.wordlists import (
    WORDLISTS_ROOT,
    COMMON_WORDLISTS,
    discover_wordlists,
    preflight_wordlists,
)
from payloads.wordlists import list_wordlists


# --- fixtures ---------------------------------------------------------------

@pytest.fixture
def fake_tree(tmp_path):
    """Build a minimal SecLists-like wordlist tree under tmp_path."""
    root = tmp_path / "wlroot"
    (root / "SecLists" / "Passwords" / "Leaked-Databases").mkdir(parents=True)
    (root / "SecLists" / "Discovery" / "Web-Content").mkdir(parents=True)
    (root / "SecLists" / "Usernames").mkdir(parents=True)
    (root / "SecLists" / ".git").mkdir(parents=True)

    (root / "SecLists" / "Passwords" / "Leaked-Databases" / "rockyou.txt").write_text(
        "123456\npassword\nletmein\n"
    )
    (root / "SecLists" / "Discovery" / "Web-Content" / "common.txt").write_text(
        "admin\nbackup\nlogin\n"
    )
    (root / "SecLists" / "Usernames" / "top-usernames-shortlist.txt").write_text(
        "root\nadmin\nuser\n"
    )
    # junk under .git must NOT surface as a wordlist
    (root / "SecLists" / ".git" / "config.txt").write_text("ignore me")
    return root


# --- preflight ---------------------------------------------------------------

def test_preflight_ok(fake_tree):
    rep = preflight_wordlists(root=fake_tree)
    assert rep["ok"] is True
    assert rep["txt_count"] == 3
    assert rep["root"] == str(fake_tree)
    assert "rockyou.txt" in rep["common_present"]
    assert rep["warnings"] == []


def test_preflight_missing_root(tmp_path):
    rep = preflight_wordlists(root=tmp_path / "nope")
    assert rep["ok"] is False
    assert rep["txt_count"] == 0
    assert rep["warnings"]
    assert "does not exist" in rep["warnings"][0]


def test_preflight_empty_root(tmp_path):
    (tmp_path / "empty").mkdir()
    rep = preflight_wordlists(root=tmp_path / "empty")
    assert rep["ok"] is False
    assert rep["txt_count"] == 0
    assert rep["warnings"]
    assert "No .txt wordlists" in rep["warnings"][0]


def test_preflight_rockyou_gz_hint(tmp_path):
    root = tmp_path / "wl"
    gz_dir = root / "SecLists" / "Passwords" / "Leaked-Databases"
    gz_dir.mkdir(parents=True)
    (gz_dir / "rockyou.txt.gz").write_text("compressed")
    # need at least one .txt so the tree isn't flagged empty
    (root / "SecLists" / "Discovery" / "Web-Content").mkdir(parents=True)
    (root / "SecLists" / "Discovery" / "Web-Content" / "common.txt").write_text("a\n")
    rep = preflight_wordlists(root=root)
    assert rep["ok"] is True
    assert "rockyou.txt" in rep["common_absent"]
    assert any("gunzip" in w for w in rep["warnings"])


# --- discover ----------------------------------------------------------------

def test_discover_walks_and_skips_git(fake_tree):
    paths = [e["path"] for e in discover_wordlists(root=fake_tree)]
    assert len(paths) == 3
    assert not any(".git" in p for p in paths)
    names = {Path(p).name for p in paths}
    assert names == {"rockyou.txt", "common.txt", "top-usernames-shortlist.txt"}


def test_discover_entries_have_metadata(fake_tree):
    entries = list(discover_wordlists(root=fake_tree))
    rock = [e for e in entries if e["path"].endswith("rockyou.txt")][0]
    assert rock["size"] > 0
    assert rock["category"] == "Passwords"
    common = [e for e in entries if e["path"].endswith("common.txt")][0]
    assert common["category"] == "Discovery"


def test_discover_missing_root_yields_nothing(tmp_path):
    assert list(discover_wordlists(root=tmp_path / "nope")) == []


# --- list_wordlists tool -----------------------------------------------------

def test_list_wordlists_catalog(fake_tree, monkeypatch):
    monkeypatch.setattr("payloads.wordlists.WORDLISTS_ROOT", fake_tree)
    monkeypatch.setattr("utils.wordlists.WORDLISTS_ROOT", fake_tree)
    r = list_wordlists()
    assert r["ok"] is True
    assert r["total"] == 3
    assert r["returned"] == 3
    assert "Passwords" in r["by_category"]
    assert "Discovery" in r["by_category"]
    assert "Usernames" in r["by_category"]
    assert "rockyou.txt" in r["common_present"]


def test_list_wordlists_category_filter(fake_tree, monkeypatch):
    monkeypatch.setattr("payloads.wordlists.WORDLISTS_ROOT", fake_tree)
    monkeypatch.setattr("utils.wordlists.WORDLISTS_ROOT", fake_tree)
    r = list_wordlists(category="passwords")  # case-insensitive
    assert r["total"] == 1
    assert r["wordlists"][0]["path"].endswith("rockyou.txt")


def test_list_wordlists_limit_cap(fake_tree, monkeypatch):
    monkeypatch.setattr("payloads.wordlists.WORDLISTS_ROOT", fake_tree)
    monkeypatch.setattr("utils.wordlists.WORDLISTS_ROOT", fake_tree)
    r = list_wordlists(limit=2)
    assert r["total"] == 3
    assert r["returned"] == 2
    assert r["limit_applied"] is True
    # by_category is complete regardless of limit
    assert sum(r["by_category"].values()) == 3


def test_list_wordlists_missing_root_warnings(tmp_path, monkeypatch):
    monkeypatch.setattr("payloads.wordlists.WORDLISTS_ROOT", tmp_path / "nope")
    monkeypatch.setattr("utils.wordlists.WORDLISTS_ROOT", tmp_path / "nope")
    r = list_wordlists()
    assert r["ok"] is False
    assert r["total"] == 0
    assert r["warnings"]
    assert r["wordlists"] == []


def test_list_wordlists_next_hints_target_both_launchers():
    """The manifest's next_hints must guide discovery -> ffuf AND hydra."""
    from payloads.wordlists import list_wordlists as _lw
    hints = set(getattr(_lw, "_next_hints", ()))
    assert "run_ffuf" in hints
    assert "run_hydra" in hints


def test_list_wordlists_is_framework_tool():
    from payloads.wordlists import list_wordlists as _lw
    assert getattr(_lw, "_is_framework_tool", False) is True


# --- default wordlist resolution --------------------------------------------

def test_resolve_default_wordlists_present():
    """The three framework defaults resolve to existing absolute paths."""
    from utils.wordlists import resolve_default_wordlist
    assert resolve_default_wordlist("ffuf") and Path(resolve_default_wordlist("ffuf")).is_file()
    assert resolve_default_wordlist("hydra_logins") and Path(resolve_default_wordlist("hydra_logins")).is_file()
    assert resolve_default_wordlist("hydra_passwords") and Path(resolve_default_wordlist("hydra_passwords")).is_file()


def test_resolve_default_wordlist_absent(tmp_path, monkeypatch):
    monkeypatch.setattr("utils.wordlists.WORDLISTS_ROOT", tmp_path)
    from utils.wordlists import resolve_default_wordlist
    # Reload the module's resolve path picks up the monkeypatched root since it
    # references the module-level WORDLISTS_ROOT at call time.
    assert resolve_default_wordlist("ffuf", root=tmp_path) is None


def test_resolve_wordlist_absolute_existing(tmp_path):
    from utils.wordlists import resolve_wordlist
    p = tmp_path / "x.txt"; p.write_text("a\n")
    assert resolve_wordlist(str(p)) == str(p)


def test_resolve_wordlist_missing_returns_none(tmp_path):
    from utils.wordlists import resolve_wordlist
    assert resolve_wordlist("nope/missing.txt", root=tmp_path) is None


def test_list_wordlists_includes_defaults(fake_tree, monkeypatch):
    monkeypatch.setattr("payloads.wordlists.WORDLISTS_ROOT", fake_tree)
    monkeypatch.setattr("utils.wordlists.WORDLISTS_ROOT", fake_tree)
    r = list_wordlists()
    assert set(r["defaults"].keys()) == {"ffuf", "hydra_logins", "hydra_passwords"}
    # fake_tree contains common.txt and top-usernames-shortlist.txt but NOT
    # top-passwords-shortlist.txt, so the field must surface both presence
    # and absence accurately.
    assert r["defaults"]["ffuf"] is not None
    assert r["defaults"]["ffuf"].endswith("common.txt")
    assert r["defaults"]["hydra_logins"] is not None
    assert r["defaults"]["hydra_logins"].endswith("top-usernames-shortlist.txt")
    assert r["defaults"]["hydra_passwords"] is None
