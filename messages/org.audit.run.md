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

# flags.verbose.summary

Don't truncate rule violation tables.

# flags.verbose.description

The default behavior truncates result tables of rule violations in terminal output, when they exceed a certain length. The default maximum length is 30 rows and can be configured in the environment variable `SAE_MAX_RESULT_VIOLATION_ROWS`. If this flag is present, the full violations table is printed. The JSON report is never truncated.

# examples

- Audit the org MyTargetOrg with the config in configs/prod

  <%= config.bin %> <%= command.id %> -o MyTargetOrg -d configs/prod

# success.all-policies-compliant

All policies are compliant.

# summary-non-compliant

At least one policy is not compliant. Review details below.

# no-accepted-risks-configured

No accepted risks documented. All violations are reported.

# has-documented-accepted-risks

Audit config has %s accepted risks documented. %s violations were muted.

# info.report-file-location

Full report was written to: %s.

# NoAuditConfigFound

The target directory %s is empty or no valid audit config was found. A valid audit config must contain at least one policy.

# UserPermClassificationRequiredForProfiles

The "Profiles" policy requires at least userPermissions to be initialised, but none were found at the target directory.

# UserPermClassificationRequiredForPermSets

The "Permission Sets" policy requires at least userPermissions to be initialised, but none were found at the target directory.

# ProfileClassificationRequiredForProfiles

The "Profiles" policy requires a corresponding classification to be initialised.

# error.InvalidConfigFileSchema

Failed to parse %s: %s.

# error.InvalidConfigFileSchema.actions

Verify that your config matches the expected schema.

# info.RemovedViolationRows

%s out of %s violations shown. See report for full results or use --verbose flag.
