import path from 'node:path';
import z from 'zod';
import { assert, expect } from 'chai';
import { Messages } from '@salesforce/core';
import FileManager from '../../src/libs/core/file-mgmt/fileManager.js';
import { AuditConfigSchema } from '../../src/libs/core/file-mgmt/fileManager.types.js';
import { MOCK_DATA_BASE_PATH } from '../mocks/data/paths.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'org.audit.run');

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

function buildPath(dirName: string) {
  return path.join(MOCK_DATA_BASE_PATH, 'audit-configs', dirName);
}

describe('file manager', () => {
  let TestAuditConfigShape: AuditConfigSchema;

  beforeEach(() => {
    TestAuditConfigShape = {
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
    };
  });

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

  it('throws error if config does not satisfy minimum criteria', () => {
    // Act
    const dirPath = buildPath('empty');
    const fm = new FileManager(TestAuditConfigShape);

    // Assert
    // assert against the message, not the complete error. Otherwise, stack will
    // always be different and assert will fail
    const expectedError = messages.getMessage('NoAuditConfigFound', [dirPath]);
    expect(() => fm.parse(dirPath)).to.throw(expectedError);
  });

  it('throws error is config does not satisfy configured dependencies', () => {
    // Arrange
    TestAuditConfigShape.policies.profiles.dependencies = [
      { path: ['classifications', 'userPermissions'], errorName: 'UserPermClassificationRequiredForProfiles' },
    ];
    const fm = new FileManager(TestAuditConfigShape);

    // Assert
    const expectedError = messages.getMessage('UserPermClassificationRequiredForProfiles');
    expect(() => fm.parse(buildPath('no-classifications'))).to.throw(expectedError);
  });

  it('parses config that satisfies all configured dependencies', () => {
    // Arrange
    TestAuditConfigShape.policies.profiles.dependencies = [
      { path: ['classifications', 'userPermissions'], errorName: 'UserPermClassificationRequiredForProfiles' },
    ];
    const fm = new FileManager(TestAuditConfigShape);

    // Act
    const conf = fm.parse(buildPath('full-valid'));

    // Assert
    assert.isDefined(conf.classifications);
    assert.isDefined(conf.classifications.userPermissions);
  });
});
