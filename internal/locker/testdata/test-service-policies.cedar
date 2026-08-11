// Test service identity for locker handler tests
// These permits allow test service identities to perform locker operations

permit (
  principal,
  action == Action::"manage:ledger",
  resource
)
when {
  principal.issuer like "http://127.0.0.1:*" && principal.sub like "*"
};

permit (
  principal,
  action == Action::"seal:evidence",
  resource
)
when {
  principal.issuer like "http://127.0.0.1:*" && principal.sub like "*"
};

permit (
  principal,
  action == Action::"read:evidence",
  resource
)
when {
  principal.issuer like "http://127.0.0.1:*" && principal.sub like "*"
};

permit (
  principal,
  action == Action::"verify:evidence",
  resource
)
when {
  principal.issuer like "http://127.0.0.1:*" && principal.sub like "*"
};
