// Workload identity (CI/CD pipelines, scanners) can publish to explicitly trusted subjects.
//
// Two-gate model following the Sigstore/Fulcio pattern (analogous to cosign +
// Sigstore Policy Controller): the identity layer validates the issuer
// (principal.publisher, set by IssuerRegistry dispatch in registry.go) and the
// policy layer validates the trust registration (resource.publisher_trusted, from
// the trust store). Neither gate alone is sufficient.
//
// Gate 1 — principal.publisher: issuer class (set by application, not token claims)
// Gate 2 — resource.publisher_trusted: per-subject trust registration (trust store)
permit (
  principal,
  action == Action::"publish:artifact",
  resource
)
when {
  principal.publisher == true &&
  resource.publisher_trusted == true
};

// SAFETY FLOOR: deny publish regardless of other permits when subject is not trusted.
// Cedar deny-default provides the same guarantee; this floor is explicit for readability.
forbid (
  principal,
  action == Action::"publish:artifact",
  resource
)
unless {
  resource.publisher_trusted == true
};

// Admin scope OR admin group gates gateway admin operations
permit (
  principal,
  action == Action::"admin:request-registration",
  resource
)
when {
  principal.scopes.contains("complytime:admin") ||
  principal.groups.contains("complytime-admin")
};

permit (
  principal,
  action == Action::"admin:request-trust-modification",
  resource
)
when {
  principal.scopes.contains("complytime:admin") ||
  principal.groups.contains("complytime-admin")
};

// Audit scope/group (or admin scope/group) gates evidence queries
permit (
  principal,
  action == Action::"query:evidence",
  resource
)
when {
  principal.scopes.contains("complytime:audit") ||
  principal.scopes.contains("complytime:admin") ||
  principal.groups.contains("complytime-auditor") ||
  principal.groups.contains("complytime-admin")
};

// Audit or admin (scope or group) allows reading raw evidence from locker.
// Used by the graph loader (service account with complytime:audit scope)
// and by direct locker reads from auditors or admins.
permit (
  principal,
  action == Action::"read:evidence",
  resource
)
when {
  principal.scopes.contains("complytime:audit") ||
  principal.scopes.contains("complytime:admin") ||
  principal.groups.contains("complytime-auditor") ||
  principal.groups.contains("complytime-admin")
};
