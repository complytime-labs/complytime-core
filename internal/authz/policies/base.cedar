permit(
  principal,
  action == Action::"read:status",
  resource
);

permit(
  principal,
  action == Action::"read:checkpoint",
  resource
);

permit(
  principal,
  action == Action::"register",
  resource
);

permit(
  principal,
  action == Action::"read:entries",
  resource
) when {
  principal has groups && principal.groups.contains("auditors")
};
