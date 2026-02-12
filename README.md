# Security Audit Engine (SAE)

<p align="center">
  <a href="https://www.npmjs.com/package/@j-schreiber/sf-cli-security-audit"><img src="https://img.shields.io/npm/v/@j-schreiber/sf-cli-security-audit.svg?logo=npm" alt="NPM version"/></a>
  <a href="https://github.com/j-schreiber/js-sf-cli-security-audit/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-blue" alt="License"></a>
</p>

A plugin for the sf CLI to automate security audits. Run audits on your CI platform in minutes, instead of manually documenting for hours.

![Audit Run Demo](/images/audit-run-demo.gif)

> [!IMPORTANT]\
> The SAE is still in beta and under active development. Command signatures, results report format, and directory structures can change.

The readme only covers the auto-generated command signatures. To learn about the concepts, design decisions, and a variety of use cases [see the official docs](https://securityauditengine.org/docs).

# Installation

To build from source, follow these steps

```bash
git clone https://github.com/j-schreiber/js-sf-cli-security-audit
mkdir sf-cli-security-audit
yarn && yarn build
sf plugins link .
```

To install the latest version from NPM

```bash
sf plugins install @j-schreiber/sf-cli-security-audit
```

# Contribute

Contributers are welcome! Please reach out on [Linkedin](https://www.linkedin.com/in/jannis-schreiber/) or via [Email](mailto:hello@jannis-schreiber.me).

# Documentation

<!-- commands -->

- [`sf org audit init`](#sf-org-audit-init)
- [`sf org audit run`](#sf-org-audit-run)
- [`sf org scan user-perms`](#sf-org-scan-user-perms)

## `sf org audit init`

Initialise a new audit config.

```
USAGE
  $ sf org audit init -o <value> [--json] [--flags-dir <value>] [-d <value>] [-p strict|loose|none] [--api-version
    <value>]

FLAGS
  -d, --output-dir=<value>   Directory where the audit config is initialised. If not set, the root directory will be
                             used.
  -o, --target-org=<value>   (required) Target org to export permissions, profiles, users, etc.
  -p, --preset=<option>      [default: strict] Preset to initialise defaults for permission risk levels.
                             <options: strict|loose|none>
      --api-version=<value>  Override the api version used for api requests made by this command

GLOBAL FLAGS
  --flags-dir=<value>  Import flag values from a directory.
  --json               Format output as json.

DESCRIPTION
  Initialise a new audit config.

  Uses your org's configuration to set up a new audit config at the target destination. This creates the basic
  classification and policy files that make up an audit config. You can select from presets to initialise risk levels
  with default values. After initialisation, you can customize the files to suit your needs.

EXAMPLES
  Initialise audit policies at the root directory

    $ sf org audit init -o MyTargetOrg

  Initialise audit config at custom directory with preset

    $ sf org audit init -o MyTargetOrg -d my_dir -p loose

FLAG DESCRIPTIONS
  -p, --preset=strict|loose|none  Preset to initialise defaults for permission risk levels.

    The selected preset is applied before any other default mechanisms (such as template configs). This means, values
    from a selected template override the preset. Consult the documentation to learn more about the rationale behind the
    default risk levels. The risk levels interact with the configured preset on profiles and permission sets and
    essentially control, if a permission is allowed in a certain profile / permission set.
```

_See code: [src/commands/org/audit/init.ts](https://github.com/j-schreiber/js-sf-cli-security-audit/blob/v0.18.0/src/commands/org/audit/init.ts)_

## `sf org audit run`

Audit your org with an existing config.

```
USAGE
  $ sf org audit run -o <value> [--json] [--flags-dir <value>] [-d <value>] [--api-version <value>] [--verbose]

FLAGS
  -d, --source-dir=<value>   Source directory of the audit config to run.
  -o, --target-org=<value>   (required) The org that is audited.
      --api-version=<value>  Override the api version used for api requests made by this command
      --verbose              Don't truncate rule violation tables.

GLOBAL FLAGS
  --flags-dir=<value>  Import flag values from a directory.
  --json               Format output as json.

DESCRIPTION
  Audit your org with an existing config.

  Loads an existing audit config from the source directory and audits the target org. The audit run always creates a
  comprehensive report in JSON format.

EXAMPLES
  Audit the org MyTargetOrg with the config in configs/prod

    $ sf org audit run -o MyTargetOrg -d configs/prod

FLAG DESCRIPTIONS
  -d, --source-dir=<value>  Source directory of the audit config to run.

    Loads all classifications and policies from the directory and uses them to audit the org. Only policies that are
    enabled and that exist in the directory are executed.

  --verbose  Don't truncate rule violation tables.

    The default behavior truncates result tables of rule violations in terminal output, when they exceed a certain
    length. The default maximum length is 30 rows and can be configured in the environment variable
    `SAE_MAX_RESULT_VIOLATION_ROWS`. If this flag is present, the full violations table is printed. The JSON report is
    never truncated.
```

_See code: [src/commands/org/audit/run.ts](https://github.com/j-schreiber/js-sf-cli-security-audit/blob/v0.18.0/src/commands/org/audit/run.ts)_

## `sf org scan user-perms`

Performs a quick scan for specific user permissions.

```
USAGE
  $ sf org scan user-perms -n <value>... -o <value> [--json] [--flags-dir <value>] [--api-version <value>] [-i -d]

FLAGS
  -d, --deep-scan            Include all user permission assignments.
  -i, --include-inactive     Include inactive users.
  -n, --name=<value>...      (required) One or more permissions to be searched for.
  -o, --target-org=<value>   (required) The target org to scan.
      --api-version=<value>  Override the api version used for api requests made by this command

GLOBAL FLAGS
  --flags-dir=<value>  Import flag values from a directory.
  --json               Format output as json.

DESCRIPTION
  Performs a quick scan for specific user permissions.

  The target org is scanned "in memory" and searches Profiles and Permission Sets for the named user permissions. This
  command does not need an audit config and does not create a report file.

EXAMPLES
  Search for multiple permissions on MyTargetOrg

    $ sf org scan user-perms -o MyTargetOrg -n AuthorApex -n ModifyMetadata

FLAG DESCRIPTIONS
  -d, --deep-scan  Include all user permission assignments.

    Searches the profile and all assigned permission sets for active users on the target org. A user can be listed
    multiple times if they receive a permission from different sources (e.g. a profile and a permission set).

  -i, --include-inactive  Include inactive users.

    Include all inactive users on the org when you perform a deep scan.

  -n, --name=<value>...  One or more permissions to be searched for.

    You can specify any valid user permission on your org, such as "AuthorApex", "CustomizeApplication", or "ViewSetup".
    If you are unsure what permissions are available on your org, initialise a new audit config and check the created
    userPermissions.yml.
```

_See code: [src/commands/org/scan/user-perms.ts](https://github.com/j-schreiber/js-sf-cli-security-audit/blob/v0.18.0/src/commands/org/scan/user-perms.ts)_

<!-- commandsstop -->

# Development

Make sure the dev plugin is installed

```bash
sf plugins install @salesforce/plugin-dev
```

Generate a new command (initialises messages, tests, etc)

```bash
sf dev generate command -n my:command:name
```

To use the local build, run using the local `./bin/dev` or `./bin/dev.cmd` file.

```bash
./bin/dev.js org audit run -o MyTargetOrg -d test/mocks/data/audit-configs/full-valid
```
