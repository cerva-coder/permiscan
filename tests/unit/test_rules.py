from permiscan.adapters.postgres.catalog import Function, Policy, Relation, Role, Snapshot
from permiscan.adapters.postgres.rules import analyze
from permiscan.findings import Confidence, Severity

ALL = frozenset({"SELECT", "INSERT", "UPDATE", "DELETE"})
READ = frozenset({"SELECT"})


def snap(relations=(), policies=(), functions=(), roles=()):
    return Snapshot(("public",), tuple(roles), tuple(relations), tuple(policies), tuple(functions))


def rel(name="t", kind="table", rls=False, forced=False, invoker=False, privileges=None, owned_by=()):
    return Relation("public", name, kind, "postgres", rls, forced, invoker, privileges or {}, frozenset(owned_by))


def policy(cmd="SELECT", qual=None, with_check=None, roles=("public",), permissive=True, name="p"):
    return Policy("public", "t", name, permissive, tuple(roles), cmd, qual, with_check)


def fn(executable_by=("anon",), search_path_set=False):
    return Function("public", "f", "", "postgres", search_path_set, frozenset(executable_by))


def scan(**kw):
    return analyze(snap(**kw), "supabase")


def only(findings):
    assert len(findings) == 1, [f.rule_id for f in findings]
    return findings[0]


def test_rls_disabled_without_effective_privileges_is_not_a_finding():
    assert scan(relations=[rel(privileges={"anon": frozenset()})]) == []


def test_rls_disabled_severity_follows_effective_privileges():
    read = only(scan(relations=[rel(privileges={"anon": READ})]))
    assert (read.rule_id, read.severity) == ("pg-rls-disabled", Severity.HIGH)

    write = only(scan(relations=[rel(privileges={"anon": READ, "authenticated": ALL})]))
    assert write.severity == Severity.CRITICAL
    assert write.evidence["privileges"]["authenticated"] == ["DELETE", "INSERT", "SELECT", "UPDATE"]


def test_rls_disabled_reports_ignored_policies():
    f = only(scan(relations=[rel(privileges={"anon": READ})], policies=[policy(qual="owner = auth.uid()")]))
    assert f.evidence["ignored_policies"] == ["p"]
    assert "ignored" in f.title


def test_unrestricted_select_is_possible_and_unrestricted_write_is_likely():
    r = rel(rls=True, privileges={"anon": ALL})
    read = only(scan(relations=[r], policies=[policy(qual="true")]))
    assert (read.rule_id, read.severity, read.confidence) == ("pg-policy-unrestricted", Severity.MEDIUM, Confidence.POSSIBLE)

    write = only(scan(relations=[r], policies=[policy(cmd="UPDATE", qual="(true)")]))
    assert (write.severity, write.confidence) == (Severity.HIGH, Confidence.LIKELY)


def test_policy_is_moot_without_matching_privilege_or_role():
    r = rel(rls=True, privileges={"anon": READ})
    assert scan(relations=[r], policies=[policy(cmd="DELETE", qual="true")]) == []
    assert scan(relations=[r], policies=[policy(qual="true", roles=("authenticated",))]) == []


def test_restrictive_policy_downgrades_confidence():
    r = rel(rls=True, privileges={"authenticated": ALL})
    found = scan(relations=[r], policies=[
        policy(cmd="UPDATE", qual="true"),
        policy(cmd="ALL", qual="org_id = auth.uid()", permissive=False, name="tenant_guard"),
    ])
    f = only(found)
    assert f.confidence == Confidence.POSSIBLE
    assert f.evidence["restrictive_policies"] == ["tenant_guard"]


def test_insert_policy_is_judged_by_with_check():
    r = rel(rls=True, privileges={"authenticated": ALL})
    assert only(scan(relations=[r], policies=[policy(cmd="INSERT", with_check="true")])).rule_id == "pg-policy-unrestricted"
    assert scan(relations=[r], policies=[policy(cmd="INSERT", with_check="owner_id = auth.uid()")]) == []


def test_write_policy_without_identity_reference():
    r = rel(rls=True, privileges={"authenticated": ALL})
    f = only(scan(relations=[r], policies=[policy(cmd="ALL", qual="org_id IS NOT NULL")]))
    assert (f.rule_id, f.cwe) == ("pg-policy-no-ownership", "CWE-639")
    assert scan(relations=[r], policies=[policy(cmd="ALL", qual="(owner = ( SELECT auth.uid() AS uid))")]) == []


def test_policy_without_expression_grants_nothing():
    r = rel(rls=True, privileges={"anon": ALL})
    assert scan(relations=[r], policies=[policy(cmd="INSERT")]) == []


def test_owner_bypasses_rls_unless_forced():
    owned = rel(rls=True, privileges={"app": ALL}, owned_by={"app"})
    assert only(scan(relations=[owned])).rule_id == "pg-rls-owner-bypass"
    assert scan(relations=[rel(rls=True, forced=True, privileges={"app": ALL}, owned_by={"app"})]) == []


def test_audited_role_with_bypassrls():
    f = only(scan(roles=[Role("anon", False, True), Role("authenticated", False, False)]))
    assert (f.rule_id, f.severity, f.resource) == ("pg-role-bypass-rls", Severity.CRITICAL, "role:anon")


def test_views():
    assert only(scan(relations=[rel(kind="view", privileges={"anon": READ})])).rule_id == "pg-view-definer"
    assert scan(relations=[rel(kind="view", invoker=True, privileges={"anon": READ})]) == []
    assert only(scan(relations=[rel(kind="materialized_view", privileges={"anon": READ})])).rule_id == "pg-matview-exposed"
    assert scan(relations=[rel(kind="view", privileges={"anon": frozenset()})]) == []


def test_security_definer_functions():
    assert {f.rule_id for f in scan(functions=[fn()])} == {"pg-func-secdef-exposed", "pg-func-search-path"}
    assert only(scan(functions=[fn(search_path_set=True)])).rule_id == "pg-func-secdef-exposed"
    assert scan(functions=[fn(executable_by=())]) == []


def test_findings_are_sorted_by_severity_and_deduplicated():
    found = scan(
        relations=[rel("a", privileges={"anon": ALL}), rel("b", kind="view", privileges={"anon": READ})],
        functions=[fn()],
    )
    assert [f.severity for f in found] == sorted((f.severity for f in found), key=lambda s: s.rank)
    assert len({f.fingerprint for f in found}) == len(found)
