# summary

Performs a quick scan for specific user permissions.

# description

The target org is scanned "in memory" and searches Profiles and Permission Sets for the named user permissions. This command does not need an audit config and does not create a report file.

# flags.name.summary

One or more permissions to be searched for.

# flags.name.description

You can specify any valid user permission on your org, such as "AuthorApex", "CustomizeApplication", or "ViewSetup". If you are unsure what permissions are available on your org, initialise a new audit config and check the created userPermissions.yml.

# flags.target-org.summary

The target org to scan.

# flags.deep-scan.summary

Include all user permission assignments.

# flags.deep-scan.description

Searches the profile and all assigned permission sets for active users on the target org. A user can be listed multiple times if they receive a permission from different sources (e.g. a profile and a permission set).

# flags.include-inactive.summary

Include inactive users.

# flags.include-inactive.description

Include all inactive users on the org when you perform a deep scan.

# examples

- Search for multiple permissions on MyTargetOrg

  <%= config.bin %> <%= command.id %> -o MyTargetOrg -n AuthorApex -n ModifyMetadata

# success.scanned-entities-count

Scanned %s profiles and %s permission sets.

# PermissionNotFound

Permission "%s" does not exist on the target org. Maybe you mistyped it?

# PermissionNameNormalized

Permission "%s" normalized to %s.
