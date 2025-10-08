# summary

Initialises classifications and policies for a security audit.

# description

Exports permissions (standard and custom), permission sets, profiles, users, etc from the target org. All classifications are initialised with sane defaults that you can customize later.

# flags.target-org.summary

Target org to analyse to initialise classifications for permissions

# flags.output-dir.summary

Directory where policies and classifications are created. If empty, the root directory will be used.

# examples

- Initialise audit policies at the root directory

  <%= config.bin %> <%= command.id %> -o MyTargetOrg

# success.perm-classification-summary

Initialised %s permissions at %s.

# success.profile-policy-summary

Initialised policy with %s profiles at %s.
