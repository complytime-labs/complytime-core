// Permit trusted publishers to publish artifacts for their trusted subjects
permit (
  principal,
  action == Action::"publish:artifact",
  resource
)
when {
  resource.publisher_trusted == true
};

// Permit admin publishers to register subjects
permit (
  principal,
  action == Action::"admin:register-subject",
  resource
)
when {
  principal.admin == true
};

// Permit admin publishers to modify trust
permit (
  principal,
  action == Action::"admin:modify-trust",
  resource
)
when {
  principal.admin == true
};

// Permit all authenticated publishers to read evidence
permit (
  principal,
  action == Action::"read:evidence",
  resource
);

// Permit service identities to seal evidence
permit (
  principal,
  action == Action::"seal:evidence",
  resource
)
when {
  principal.service == true
};

// Permit service identities to verify evidence
permit (
  principal,
  action == Action::"verify:evidence",
  resource
)
when {
  principal.service == true
};

// Permit admin service identities to manage ledgers
permit (
  principal,
  action == Action::"manage:ledger",
  resource
)
when {
  principal.service == true && principal.admin == true
};

// SAFETY FLOOR: Forbid untrusted publishers from publishing artifacts
// This cannot be overridden by any permit
forbid (
  principal,
  action == Action::"publish:artifact",
  resource
)
unless {
  resource.publisher_trusted == true
};
