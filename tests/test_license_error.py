"""Tests for license exit-code -> message surfacing (license_error_message)."""

import json

import pytest

from cloakbrowser import CloakBrowserLicenseError
from cloakbrowser.license import (
    license_error_for_code,
    license_error_message,
    mint_denial_file,
    read_denial_file,
)


def _launch_text(code: int) -> str:
    return (
        "BrowserType.launch: Target page, context or browser has been closed\n"
        f"Browser logs:\n- [pid=123] <process did exit: exitCode={code}, signal=null>"
    )


@pytest.mark.parametrize(
    "code,fragment",
    [
        (76, "session limit"),
        (77, "invalid, expired, or missing"),
        (78, "couldn't verify"),
        (79, "not writable"),
    ],
)
def test_known_license_codes_map_to_message(code, fragment):
    msg = license_error_message(_launch_text(code))
    assert msg is not None
    assert msg.startswith("CloakBrowser Pro:")
    assert fragment in msg


def test_non_license_exit_code_returns_none():
    # A normal/crash exit code is not ours -> passthrough (None).
    assert license_error_message(_launch_text(1)) is None
    assert license_error_message(_launch_text(139)) is None
    # A large SEH-style code (e.g. Windows access violation 0xC0000005) must not
    # crash or false-match -- this is the case that overflows a 32-bit int parse.
    assert license_error_message(_launch_text(3221225477)) is None


def test_no_exit_code_in_text_returns_none():
    # A bare TargetClosedError (post-ready death) carries no code -> None.
    assert license_error_message("Target page, context or browser has been closed") is None
    assert license_error_message("") is None


def test_error_type_is_runtimeerror_subclass():
    assert issubclass(CloakBrowserLicenseError, RuntimeError)
    assert str(CloakBrowserLicenseError("x")) == "x"


# ── license_error_for_code (int -> error, the post-handshake file path) ──


@pytest.mark.parametrize("code,fragment", [
    (76, "session limit"),
    (77, "invalid, expired, or missing"),
    (78, "couldn't verify"),
    (79, "not writable"),
])
def test_license_error_for_code_known(code, fragment):
    err = license_error_for_code(code)
    assert isinstance(err, CloakBrowserLicenseError)
    assert fragment in str(err)


def test_license_error_for_code_unknown_returns_none():
    assert license_error_for_code(1) is None
    assert license_error_for_code(0) is None


# ── read_denial_file (destructive read of the binary's denial marker) ──


def test_read_denial_file_returns_code_and_consumes(tmp_path):
    f = tmp_path / "d.json"
    f.write_text(json.dumps(76))
    assert read_denial_file(str(f)) == 76
    assert not f.exists()  # consumed so a later launch can't see a stale code


def test_read_denial_file_missing_returns_none(tmp_path):
    assert read_denial_file(str(tmp_path / "nope.json")) is None


def test_read_denial_file_second_read_still_returns_code_after_consumed(tmp_path):
    """The read is destructive, but a concurrent/second guarded call for the same
    launch must still see the denial (cached in-process)."""
    f = tmp_path / "d.json"
    f.write_text(json.dumps(76))
    assert read_denial_file(str(f)) == 76
    assert not f.exists()                      # consumed
    assert read_denial_file(str(f)) == 76      # file gone, still surfaced from cache


def test_read_denial_file_garbage_returns_none(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("not-json")
    assert read_denial_file(str(f)) is None
    assert not f.exists()  # garbage is still cleaned up


def test_read_denial_file_empty_returns_none(tmp_path):
    f = tmp_path / "empty.json"
    f.write_text("")
    assert read_denial_file(str(f)) is None


# ── mint_denial_file ──


def test_mint_denial_file_path_in_denials_dir(tmp_path, monkeypatch):
    monkeypatch.setattr("cloakbrowser.license.Path.home", lambda: tmp_path)
    path = mint_denial_file()
    assert path is not None
    assert path.endswith(".json")
    assert "denials" in path
    assert (tmp_path / ".cloakbrowser" / "denials").is_dir()


def test_mint_denial_file_unwritable_returns_none(monkeypatch):
    def boom(*a, **k):
        raise OSError("not writable")
    monkeypatch.setattr("cloakbrowser.license.Path.mkdir", boom)
    assert mint_denial_file() is None  # never breaks a launch


def test_mint_sweeps_stale_denial_files_keeps_fresh(tmp_path, monkeypatch):
    """A denial the binary wrote but nobody consumed would leak forever; mint
    sweeps files older than the TTL and leaves fresh (concurrent) ones alone."""
    import os as _os
    import time as _time
    from cloakbrowser.license import _DENIAL_FILE_TTL_SECONDS
    monkeypatch.setattr("cloakbrowser.license.Path.home", lambda: tmp_path)
    denials = tmp_path / ".cloakbrowser" / "denials"
    denials.mkdir(parents=True)
    stale = denials / "stale.json"
    stale.write_text("76")
    old = _time.time() - (_DENIAL_FILE_TTL_SECONDS + 60)
    _os.utime(stale, (old, old))
    fresh = denials / "fresh.json"       # e.g. a concurrent launch's live denial
    fresh.write_text("76")

    mint_denial_file()

    assert not stale.exists()  # orphan swept
    assert fresh.exists()      # in-flight denial untouched


# ── _install_license_guard (surfacing on the user's next call) ──


class _StubBrowser:
    """Minimal stand-in: new_page raises like a dead browser would."""
    def __init__(self, exc):
        self._exc = exc

    def new_page(self, *a, **k):
        raise self._exc

    def new_context(self, *a, **k):
        raise self._exc


def _target_closed():
    return RuntimeError("Target page, context or browser has been closed")


def test_guard_raises_license_error_when_denial_file_present(tmp_path):
    from cloakbrowser.browser import _install_license_guard
    denial = tmp_path / "d.json"
    denial.write_text(json.dumps(76))
    b = _StubBrowser(_target_closed())
    _install_license_guard(b, str(denial), ("new_page", "new_context"))
    with pytest.raises(CloakBrowserLicenseError) as ei:
        b.new_page()
    assert "session limit" in str(ei.value)


def test_guard_passthrough_when_no_file(tmp_path):
    from cloakbrowser.browser import _install_license_guard
    original = _target_closed()
    b = _StubBrowser(original)
    _install_license_guard(b, str(tmp_path / "absent.json"), ("new_page",))
    with pytest.raises(RuntimeError) as ei:
        b.new_page()
    assert ei.value is original  # a genuine failure is never relabelled


def test_guard_passthrough_when_file_garbage(tmp_path):
    from cloakbrowser.browser import _install_license_guard
    denial = tmp_path / "bad.json"
    denial.write_text("garbage")
    original = _target_closed()
    b = _StubBrowser(original)
    _install_license_guard(b, str(denial), ("new_page",))
    with pytest.raises(RuntimeError) as ei:
        b.new_page()
    assert ei.value is original


@pytest.mark.asyncio
async def test_guard_async_raises_license_error(tmp_path):
    from cloakbrowser.browser import _install_license_guard_async
    denial = tmp_path / "d.json"
    denial.write_text(json.dumps(77))

    class _AsyncStub:
        async def new_page(self, *a, **k):
            raise _target_closed()

    b = _AsyncStub()
    _install_license_guard_async(b, str(denial), ("new_page",))
    with pytest.raises(CloakBrowserLicenseError) as ei:
        await b.new_page()
    assert "invalid, expired, or missing" in str(ei.value)


# ── persistent context: the pre-open page's navigation must be guarded too ──
# A persistent context is handed back with pages[0] already open, so the user
# navigates that page directly and never calls new_page. Every navigation entry
# point in _PERSISTENT_PAGE_NAV_METHODS must surface the denial.


def test_persistent_nav_methods_are_a_realistic_set():
    from cloakbrowser.browser import _PERSISTENT_PAGE_NAV_METHODS
    assert "goto" in _PERSISTENT_PAGE_NAV_METHODS
    # navigation + waits, the realistic first calls on a fresh pages[0]
    assert set(_PERSISTENT_PAGE_NAV_METHODS) == {
        "goto", "reload", "wait_for_load_state", "wait_for_url", "wait_for_selector",
    }


@pytest.mark.parametrize("method", [
    "goto", "reload", "wait_for_load_state", "wait_for_url", "wait_for_selector",
])
def test_guard_surfaces_denial_on_each_pre_open_page_nav_method(tmp_path, method):
    """The bug: pages[0].goto() on a denied persistent context threw a bare
    TargetClosedError. With the page's nav methods guarded, each one surfaces
    CloakBrowserLicenseError instead."""
    from cloakbrowser.browser import _install_license_guard, _PERSISTENT_PAGE_NAV_METHODS

    class _StubPage:
        # every guarded nav method raises like a dead browser would
        def goto(self, *a, **k): raise _target_closed()
        def reload(self, *a, **k): raise _target_closed()
        def wait_for_load_state(self, *a, **k): raise _target_closed()
        def wait_for_url(self, *a, **k): raise _target_closed()
        def wait_for_selector(self, *a, **k): raise _target_closed()

    denial = tmp_path / "d.json"
    denial.write_text(json.dumps(76))
    page = _StubPage()
    _install_license_guard(page, str(denial), _PERSISTENT_PAGE_NAV_METHODS)
    with pytest.raises(CloakBrowserLicenseError) as ei:
        getattr(page, method)("https://example.com")
    assert "session limit" in str(ei.value)


def test_guard_passthrough_on_pre_open_page_without_denial(tmp_path):
    """No denial file -> a genuine navigation failure is never relabelled."""
    from cloakbrowser.browser import _install_license_guard, _PERSISTENT_PAGE_NAV_METHODS

    original = _target_closed()

    class _StubPage:
        def goto(self, *a, **k): raise original
        def reload(self, *a, **k): raise original
        def wait_for_load_state(self, *a, **k): raise original
        def wait_for_url(self, *a, **k): raise original
        def wait_for_selector(self, *a, **k): raise original

    page = _StubPage()
    _install_license_guard(page, str(tmp_path / "absent.json"), _PERSISTENT_PAGE_NAV_METHODS)
    with pytest.raises(RuntimeError) as ei:
        page.goto("https://example.com")
    assert ei.value is original
