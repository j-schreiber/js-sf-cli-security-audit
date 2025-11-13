# summary

Audit your org with an existing config.

# description

Loads an existing audit config from the source directory and audits the target org. The audit run always creates a comprehensive report in JSON format.

# flags.target-org.summary

The org that is audited.

# flags.source-dir.summary

Source directory of the audit config to run.

# flags.source-dir.description

Loads all classifications and policies from the directory and uses them to audit the org. Only policies that are enabled and that exist in the directory are executed.

# examples

- Audit the org MyTargetOrg with the config in configs/prod

  <%= config.bin %> <%= command.id %> -o MyTargetOrg -d configs/prod

# success.all-policies-compliant

All policies are compliant.

# summary-non-compliant

At least one policy is not compliant. Review details below.

# info.report-file-location

Full report was written to: %s.

# NoAuditConfigFound

The target directory %s is empty or no valid audit config was found. A valid audit config must contain at least one policy.

# UserPermClassificationRequiredForProfiles

The "Profiles" policy requires at least userPermissions to be initialised, but none were found at the target directory.

# UserPermClassificationRequiredForPermSets

The "Permission Sets" policy requires at least userPermissions to be initialised, but none were found at the target directory.

# error.InvalidConfigFileSchema

Failed to parse %s: %s.

# error.InvalidConfigFileSchema.actions

Verify that your config matches the expected schema.
