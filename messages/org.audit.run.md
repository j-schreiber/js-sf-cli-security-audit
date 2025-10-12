# summary

Initialises classifications and policies for a security audit.

# description

Exports permissions (standard and custom), permission sets, profiles, users, etc from the target org. All classifications are initialised with sane defaults that you can customize later.

# flags.target-org.summary

Target org to analyse to initialise classifications for permissions

# flags.source-dir.summary

Directory where policies and classifications are created. If empty, the root directory will be used.

# examples

- Initialise audit policies at the root directory

  <%= config.bin %> <%= command.id %> -o MyTargetOrg

# success.summary

Successfully executed %s policies.

# success.all-policies-compliant

All policies are compliant.

# summary-non-compliant

At least one policy is not compliant. Review details below.

# info.report-file-location

Full report was written to: %s.
