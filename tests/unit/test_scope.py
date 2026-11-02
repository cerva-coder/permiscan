import pytest

from permiscan.cli import EXIT_SCOPE, main
from permiscan.scope import ScopeEntry, ScopeError, authorize, load_scope, parse_dsn


def test_parse_uri_and_keyword_dsn():
    t = parse_dsn("postgresql://u:s3cret@DB.Example.com:6543/app")
    assert (t.host, t.port, t.database, t.user) == ("db.example.com", 6543, "app", "u")
    assert parse_dsn("host=localhost dbname=app").port == 5432


@pytest.mark.parametrize("dsn", [
    "postgresql:///app",                                    # no host: PGHOST would decide the target
    "host=localhost",                                       # no dbname
    "host=allowed.example dbname=app hostaddr=10.0.0.9",    # hostaddr bypasses the declared host
    "service=prod",
    "host=a,b dbname=app",
    "not a dsn",
])
def test_parse_rejects_ambiguous_targets(dsn):
    with pytest.raises(ScopeError):
        parse_dsn(dsn)


def test_connect_kwargs_pin_the_validated_target():
    kw = parse_dsn("postgresql://u:p@h:5433/db?sslmode=require").connect_kwargs()
    assert (kw["host"], kw["port"], kw["dbname"], kw["sslmode"]) == ("h", 5433, "db", "require")


def test_redact_and_repr_never_leak_password():
    t = parse_dsn("postgresql://u:s3cret@h/db")
    assert "s3cret" not in repr(t)
    assert t.redact("auth failed for s3cret") == "auth failed for ***"


def test_authorize():
    t = parse_dsn("postgresql://postgres.abc:p@pooler.example:5432/postgres")
    authorize(t, [ScopeEntry("pooler.example", 5432, "postgres")])
    authorize(t, [ScopeEntry("pooler.example", 5432, "postgres", user="postgres.abc")])
    for entry in (
        ScopeEntry("pooler.example", 5432, "postgres", user="postgres.other"),  # outro tenant no mesmo pooler
        ScopeEntry("pooler.example", 6543, "postgres"),
        ScopeEntry("other.example", 5432, "postgres"),
    ):
        with pytest.raises(ScopeError):
            authorize(t, [entry])


def test_load_scope(tmp_path):
    path = tmp_path / "scope.toml"
    path.write_text('[[targets]]\nhost = "LocalHost"\ndatabase = "lab"\n', encoding="utf-8")
    assert load_scope(path) == [ScopeEntry("localhost", 5432, "lab")]

    path.write_text("targets = []\n", encoding="utf-8")
    with pytest.raises(ScopeError):
        load_scope(path)
    with pytest.raises(ScopeError):
        load_scope(tmp_path / "missing.toml")


def test_cli_refuses_out_of_scope_target_before_connecting(tmp_path, monkeypatch, capsys):
    scope = tmp_path / "scope.toml"
    scope.write_text('[[targets]]\nhost = "localhost"\nport = 55432\ndatabase = "lab"\n', encoding="utf-8")
    # port 1 never responds: if the CLI tried to connect, the error would be a connection
    # error, not a scope error
    monkeypatch.setenv("PERMISCAN_DSN", "postgresql://u:s3cret@localhost:1/lab")
    assert main(["scan", "--provider", "supabase", "--scope", str(scope)]) == EXIT_SCOPE
    err = capsys.readouterr().err
    assert "outside the authorized scope" in err and "s3cret" not in err
