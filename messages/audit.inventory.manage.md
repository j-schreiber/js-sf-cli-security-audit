# summary

Univeral interactive inventory management.

# description

Asks for the inventory type and the operation you want to perform.

# examples

- Scan and analyse inventorized profiles in "my_audit_config"

  <%= config.bin %> <%= command.id %> -d my_audit_config -o MyTargetOrg

# flags.target-org.summary

Target org to export the inventory from.

# flags.source-dir.summary

Directory of the audit config to scan. If not set, the root directory will be used.

# flags.verbose.summary

Show additional details after completing the operation.

# ux.choices.inventory-type.prompt

Which inventory do you want to manage?

# ux.choices.inventory-type.entities-found

Found %s entities in local config.

# ux.choices.inventory-type.no-entities-found

No entities found in local config.

# ux.choices.operation.prompt

What operation to perform?

# ux.choices.refresh.description-existing

Refreshes the local inventory from target org: Adds new entities from the org that are not yet saved in config.

# ux.choices.refresh.description-fresh

Initialises the local inventory from target org: Creates the config file and pulls all entities from the org.

# ux.choices.prune.description

Prunes the local inventory: Removes entities from config that do not exist on the org.

# ux.summary.completion

Added %s missing entities and removed %s obsolete entities from %s.
