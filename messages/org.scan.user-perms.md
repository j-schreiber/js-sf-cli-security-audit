# summary

Performs a quick scan to check permission sets and profiles for user permissions.

# description

The quick scan does not need an audit config and does not create reports. The target org is scanned "in memory" and simply outputs information, where the searched user permissions

# flags.name.summary

One or more permissions to be scanned.

# flags.name.description

You can specify any valid user permission on your org, such as "AuthorApex", "CustomizeApplication" or "ViewSetup". If you are unsure what permissions are available on your org, initialise a new audit config and check the created userPermissions.yml.

# flags.target-org.summary

The target org to scan.

# examples

- <%= config.bin %> <%= command.id %>

# success.scanned-entities-count

Scanned %s profiles and %s permission sets.
