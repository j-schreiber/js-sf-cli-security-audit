import path from 'node:path';
import z from 'zod';
import { assert, expect } from 'chai';
import FileManager from '../../src/libs/core/file-mgmt/fileManager.js';
import { AuditConfigSchema } from '../../src/libs/core/file-mgmt/fileManager.types.js';
import { MOCK_DATA_BASE_PATH } from '../mocks/data/paths.js';

const PolicyRuleConfigSchema = z.object({
  enabled: z.boolean().default(true),
  options: z.unknown().optional(),
});

const RuleMapSchema = z.record(z.string(), PolicyRuleConfigSchema);

const PolicyBaseFile = z.object({
  enabled: z.boolean().default(true),
  rules: RuleMapSchema.default({}),
});

const PermissionsClassificationSchema = z.object({
  classification: z.string(),
});

const TestAuditConfigShape = {
  classifications: {
    userPermissions: {
      schema: z.object({ permissions: z.record(z.string(), PermissionsClassificationSchema) }),
    },
    profiles: {
      schema: z.object({
        profiles: z.record(
          z.string(),
          z.object({
            role: z.string(),
          })
        ),
      }),
    },
  },
  policies: {
    profiles: {
      schema: PolicyBaseFile,
    },
    permissionSets: {
      schema: PolicyBaseFile,
    },
    connectedApps: {
      schema: PolicyBaseFile,
    },
  },
} satisfies AuditConfigSchema;

function buildPath(dirName: string) {
  return path.join(MOCK_DATA_BASE_PATH, 'audit-configs', dirName);
}

describe('file manager', () => {
  it('parses audit config from directory that matches shape', () => {
    // Act
    const fm = new FileManager(TestAuditConfigShape);
    const conf = fm.parse(buildPath('full-valid'));

    // Assert
    assert.isDefined(conf.classifications);
    assert.isDefined(conf.classifications.userPermissions);
    assert.isDefined(conf.classifications.profiles);
    assert.isDefined(conf.policies);
    assert.isDefined(conf.policies.profiles);
    assert.isDefined(conf.policies.permissionSets);
    assert.isDefined(conf.policies.connectedApps);
  });

  it('parses partial audit config from directory that matches shape', () => {
    // Act
    const fm = new FileManager(TestAuditConfigShape);
    const conf = fm.parse(buildPath('minimal'));

    // Assert
    assert.isDefined(conf.classifications);
    assert.isDefined(conf.classifications.userPermissions);
    assert.isDefined(conf.classifications.profiles);
    assert.isDefined(conf.policies);
    assert.isDefined(conf.policies.profiles);
    expect(conf.policies.connectedApps).to.be.undefined;
    expect(conf.policies.permissionSets).to.be.undefined;
  });
});
