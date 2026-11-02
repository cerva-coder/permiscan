import pytest

from permiscan import menu


@pytest.fixture
def feed(monkeypatch):
    def drive(seq):
        it = iter(seq)
        monkeypatch.setattr("builtins.input", lambda _p="": next(it))
    return drive


def test_ask_level_parses_and_loops(feed):
    feed(["3"])
    assert menu._ask_level() == 3
    feed(["x", "0", "2"])  # invalid until a valid one
    assert menu._ask_level() == 2


def test_ask_level_default_is_medium(feed):
    feed([""])
    assert menu._ask_level() == 2


def test_menu_exits_on_zero(feed):
    feed(["0"])
    assert menu.run_menu() == 0


def test_invalid_option_then_exit(feed):
    feed(["9", "0"])
    assert menu.run_menu() == 0


def test_individual_with_empty_url_does_not_call_recon(feed, monkeypatch):
    called = []
    monkeypatch.setattr(menu, "Recon", lambda *a, **k: called.append(a) or (_ for _ in ()).throw(AssertionError))
    # mode 1, level 2, empty URL -> returns without calling Recon; then exits
    feed(["1", "2", "", "n"])
    assert menu.run_menu() == 0
    assert called == []


def test_individual_runs_recon_with_chosen_level(feed, monkeypatch):
    seen = {}

    class FakeRecon:
        def __init__(self, url, level=2):
            seen["url"], seen["level"] = url, level

        def run(self):
            from permiscan.discovery import ReconResult
            return ReconResult(seen["url"])

    monkeypatch.setattr(menu, "Recon", FakeRecon)
    # mode 1, level 3, URL, then don't repeat
    feed(["1", "3", "https://target.test", "n"])
    assert menu.run_menu() == 0
    assert seen == {"url": "https://target.test", "level": 3}
