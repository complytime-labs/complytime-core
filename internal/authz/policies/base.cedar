// Read actions — any authenticated identity
permit(principal, action == Action::"read:status", resource);
permit(principal, action == Action::"read:checkpoint", resource);

// Read entries — auditors group required (safety floor: forbid prevents override)
permit(principal, action == Action::"read:entries", resource)
when { principal has groups && principal.groups.contains("auditors") };

forbid(principal, action == Action::"read:entries", resource)
unless { principal has groups && principal.groups.contains("auditors") };

// Publish — publishers group required (safety floor: forbid prevents override)
permit(principal, action == Action::"publish", resource)
when { principal has groups && principal.groups.contains("publishers") };

forbid(principal, action == Action::"publish", resource)
unless { principal has groups && principal.groups.contains("publishers") };

// Publish sub-actions — evaluated at handler level
permit(principal, action == Action::"publish:registration", resource);
permit(principal, action == Action::"publish:policy", resource);

permit(principal, action == Action::"publish:artifact", resource)
when { resource has publisher_trusted && resource.publisher_trusted };

forbid(principal, action == Action::"publish:artifact", resource)
unless { resource has publisher_trusted && resource.publisher_trusted };
