# summary

Interactive inventory management for a local audit config.

# description

Asks for the inventory type you want to manage (currently supports profiles, users, and permission sets)
and performs "refresh" or "prune" operations on the selected inventory. Refresh pulls missing entities
from the target org and adds them to your local config. Prune compares your local config with the target
org and removes entities that are not on your org.

It is highly recommended to put the audit config under version control before you use this command.

# examples

- Load the audit config in "my_audit_config" and compare inventory with MyTargetOrg

  <%= config.bin %> <%= command.id %> -d my_audit_config -o MyTargetOrg

- Loads the audit config from root (working directory)

  <%= config.bin %> <%= command.id %> -o MyTargetOrg

# flags.target-org.summary

Target org to export the inventory from.

# flags.source-dir.summary

Directory of the audit config to scan. If not set, the root directory will be used.

# flags.verbose.summary

Lists added/removed entities after completing the operation.

# ux.choices.inventory-type.prompt

Select inventory to manage:

# ux.choices.inventory-type.entities-found

Found %s entities in local config.

# ux.choices.inventory-type.no-entities-found

No entities found in local config.

# ux.choices.operation.prompt

Choose operation(s):

# ux.choices.refresh.description-existing

Refreshes the local inventory from target org: Adds new entities from the org that are not yet saved in config.

# ux.choices.refresh.description-fresh

Initialises the local inventory from target org: Creates the config file and pulls all entities from the org.

# ux.choices.prune.description

Prunes the local inventory: Removes entities from config that do not exist on the org.

# ux.summary.completion

Added %s missing and removed %s obsolete entities from %s.
