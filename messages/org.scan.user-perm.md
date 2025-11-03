# summary

Performs a quick scan to check permission sets and profiles for user permissions.

# description

The quick scan does not need an audit config and does not create reports. The target org is scanned "in memory" and simply outputs information, where the searched user permissions

# flags.name.summary

One or more permissions to be scanned.

# flags.name.description

More information about a flag. Don't repeat the summary.

# flags.target-org.summary

The target org to scan.

# examples

- <%= config.bin %> <%= command.id %>

# success.profiles-count

Scanned %s profiles.

# success.permissionsets-count

Scanned %s permission sets.
