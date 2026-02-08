# summary

Performs a quick scan for specific user permissions.

# description

The target org is scanned "in memory" and searches Profiles and Permission Sets for the named user permissions. This command does not need an audit config and does not create a report file.

# flags.name.summary

One or more permissions to be searched for.

# flags.name.description

You can specify any valid user permission on your org, such as "AuthorApex", "CustomizeApplication" or "ViewSetup". If you are unsure what permissions are available on your org, initialise a new audit config and check the created userPermissions.yml. Currently, the names are not validated: If you have a typo (such as "AutorApex", the scan will retun 0 results).

# flags.target-org.summary

The target org to scan.

# flags.deep-scan.summary

Include all user permission assignments.

# flags.deep-scan.description

Searches the profile and all assigned permission sets for every active user on the org.

# examples

- Search for multiple permissions on MyTargetOrg

  <%= config.bin %> <%= command.id %> -o MyTargetOrg -n AuthorApex -n ModifyMetadata

# success.scanned-entities-count

Scanned %s profiles and %s permission sets.
