import z from 'zod';
import {
  AcceptedRisksSchema,
  ComposableRolesFileSchema,
  PermissionControlsFileSchema,
} from '../../src/libs/audit-engine/registry/shape/schema.js';
import {
  AuditConfigShapeDefinition,
  ExtractAuditConfigTypes,
  RefineError,
} from '../../src/libs/audit-engine/file-manager/fileManager.types.js';

// V1 Types

const PolicyRuleConfigSchema = z.object({
  enabled: z.boolean().default(false),
  options: z.unknown().optional(),
});

const RuleMapSchema = z.record(z.string(), PolicyRuleConfigSchema);

const PolicyBaseFile = z.object({
  enabled: z.boolean().default(false),
  rules: RuleMapSchema.default({}),
});

const PermissionsClassificationSchema = z.object({
  classification: z.string(),
});

export const validator = (parseResult: ExtractAuditConfigTypes<typeof BaseShapeV2>) => {
  const errors: RefineError[] = [];
  if (parseResult.controls.roles && parseResult.inventory.profiles) {
    for (const [profileName, profile] of Object.entries(parseResult.inventory.profiles)) {
      if (!parseResult.controls.roles[profile.role]) {
        errors.push({ message: `Invalid role ${profile.role} for profile`, path: ['profiles', profileName] });
      }
    }
  }
  if (!parseResult.policies || Object.keys(parseResult.policies).length === 0) {
    errors.push({
      message: 'Config invalid or empty. Needs one policy.',
      path: ['policies'],
    });
  }
  return errors;
};

export const BaseShapeV2 = {
  controls: {
    files: {
      roles: { schema: ComposableRolesFileSchema },
      permissions: { schema: PermissionControlsFileSchema },
    },
  },
  inventory: {
    files: {
      profiles: {
        schema: z.record(
          z.string(),
          z.object({
            role: z.string(),
          })
        ),
        isCountable: true,
      },
    },
  },
  shape: {
    files: {
      userPermissions: {
        schema: z.record(z.string(), PermissionsClassificationSchema),
        isCountable: true,
      },
    },
  },
  policies: {
    files: {
      profiles: {
        schema: PolicyBaseFile,
      },
      permissionSets: {
        schema: PolicyBaseFile,
      },
      connectedApps: {
        schema: PolicyBaseFile,
      },
      users: {
        schema: PolicyBaseFile,
      },
    },
  },
} as const satisfies AuditConfigShapeDefinition;

export const ExtendedShapeV1 = {
  controls: BaseShapeV2.controls,
  shape: BaseShapeV2.shape,
  inventory: BaseShapeV2.inventory,
  policies: BaseShapeV2.policies,
  acceptedRisks: {
    dirs: {
      profiles: {
        files: {
          EnforcePermissionClassifications: {
            schema: AcceptedRisksSchema,
          },
          TestRule: {
            schema: AcceptedRisksSchema,
          },
        },
      },
      users: {
        files: {
          NoStandardProfilesOnActiveUsers: {
            schema: AcceptedRisksSchema,
          },
          NoOtherApexApiLogins: {
            schema: AcceptedRisksSchema,
          },
          EnforcePermissionClassifications: {
            schema: AcceptedRisksSchema,
          },
          NoInactiveUsers: {
            schema: AcceptedRisksSchema,
          },
        },
      },
    },
  },
} satisfies AuditConfigShapeDefinition;
