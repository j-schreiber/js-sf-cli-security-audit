import fs from 'node:fs';
import path from 'node:path';
import yaml from 'js-yaml';
import { assert, expect } from 'chai';
import { Messages } from '@salesforce/core';
import FileManager from '../../src/libs/audit-engine/file-manager/fileManager.js';
import {
  AuditConfigShapeDefinition,
  ConfigFileDependency,
} from '../../src/libs/audit-engine/file-manager/fileManager.types.js';
import { MOCK_DATA_BASE_PATH } from '../mocks/data/paths.js';
import { BaseShapeV2, ExtendedShapeV1, validator } from '../mocks/fileManager.types.js';
import { PermissionControl } from '../../src/libs/audit-engine/registry/shape/schema.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'org.audit.run');

function buildPath(dirName: string) {
  return path.join(MOCK_DATA_BASE_PATH, 'audit-configs', dirName);
}

describe('file manager', () => {
  describe('parsing', () => {
    it('parses audit config from directory that matches shape', () => {
      // Act
      const fm = new FileManager(BaseShapeV2);
      const conf = fm.parse(buildPath('full-valid'));

      // Assert
      assert.isDefined(conf.shape);
      assert.isDefined(conf.shape.userPermissions);
      assert.isDefined(conf.inventory);
      assert.isDefined(conf.inventory.profiles);
      assert.isDefined(conf.policies);
      assert.isDefined(conf.policies.profiles);
      assert.isDefined(conf.policies.permissionSets);
      assert.isDefined(conf.policies.connectedApps);
    });

    it('parses partial audit config from directory that matches shape', () => {
      // Act
      const fm = new FileManager(BaseShapeV2);
      const conf = fm.parse(buildPath('minimal'));

      // Assert
      assert.isDefined(conf.shape);
      assert.isDefined(conf.shape.userPermissions);
      assert.isDefined(conf.inventory);
      assert.isDefined(conf.inventory.profiles);
      assert.isDefined(conf.policies);
      assert.isDefined(conf.policies.profiles);
      expect(conf.policies.connectedApps).to.be.undefined;
      expect(conf.policies.permissionSets).to.be.undefined;
    });

    it('parses audit config with .yaml files', () => {
      // Act
      // previous behavior only parsed .yml file suffix, now we accept .yml and .yaml
      const fm = new FileManager(BaseShapeV2);
      const conf = fm.parse(buildPath('minimal-yaml'));

      // Assert
      assert.isDefined(conf.shape);
      assert.isDefined(conf.shape.userPermissions);
      assert.isDefined(conf.inventory);
      assert.isDefined(conf.inventory.profiles);
      assert.isDefined(conf.policies);
      assert.isDefined(conf.policies.profiles);
    });

    it('throws error if directory does not exist', () => {
      // Act
      const dirPath = buildPath('does-not-exist');
      const fm = new FileManager(BaseShapeV2);

      // Assert
      // assert against the message, not the complete error. Otherwise, stack will
      // always be different and assert will fail
      const expectedError = messages.getMessage('error.DirectoryDoesNotExistOrIsEmpty', [dirPath]);
      expect(() => fm.parse(dirPath)).to.throw(expectedError);
    });

    it('throws error if config does not satisfy minimum criteria', () => {
      // Act
      const dirPath = buildPath('empty');
      const fm = new FileManager(BaseShapeV2, validator);

      // Assert
      // assert against the message, not the complete error. Otherwise, stack will
      // always be different and assert will fail
      const expectedError = messages.getMessage('error.FailedToValidateAuditConfig', [
        dirPath,
        'Config invalid or empty. Needs one policy.',
        'policies',
      ]);
      expect(() => fm.parse(dirPath)).to.throw(expectedError);
    });

    it('throws error is config does not satisfy configured dependencies', () => {
      // Arrange
      const wrappedBaseShapeV2 = wrapProfileDependencies([
        {
          path: ['shape', 'userPermissions'],
          errorName: 'UserPermClassificationRequiredForProfiles',
        },
      ]);
      const fm = new FileManager(wrappedBaseShapeV2);

      // Assert
      const expectedError = messages.getMessage('UserPermClassificationRequiredForProfiles');
      expect(() => fm.parse(buildPath('no-classifications'))).to.throw(expectedError);
    });

    it('parses config that satisfies all configured dependencies', () => {
      // Arrange
      const wrappedBaseShapeV2 = wrapProfileDependencies([
        { path: ['shape', 'userPermissions'], errorName: 'UserPermClassificationRequiredForProfiles' },
      ]);
      const fm = new FileManager(wrappedBaseShapeV2);

      // Act
      const conf = fm.parse(buildPath('full-valid'));

      // Assert
      assert.isDefined(conf.shape);
      assert.isDefined(conf.shape.userPermissions);
    });

    it('ignores policy-dependencies if policy is not present', () => {
      // Arrange
      const wrappedBaseShapeV2 = wrapProfileDependencies([
        { path: ['shape', 'userPermissions'], errorName: 'UserPermClassificationRequiredForProfiles' },
      ]);
      const fm = new FileManager(wrappedBaseShapeV2);

      // Act
      const conf = fm.parse(buildPath('no-classifications-2'));

      // Assert
      assert.isDefined(conf.shape);
      assert.isDefined(conf.inventory);
      assert.isDefined(conf.policies);
      assert.isDefined(conf.policies.permissionSets);
    });

    it('reads accepted risks for mapped policies', () => {
      // Act
      const fm = new FileManager(ExtendedShapeV1);
      const conf = fm.parse(buildPath('full-valid'));

      // Assert
      assert.isDefined(conf.acceptedRisks);
      assert.isDefined(conf.acceptedRisks.users);
      assert.isDefined(conf.acceptedRisks.users.NoStandardProfilesOnActiveUsers);
      assert.isDefined(conf.acceptedRisks.users.NoOtherApexApiLogins);
      assert.isDefined(conf.acceptedRisks.users.EnforcePermissionClassifications);
      assert.isDefined(conf.acceptedRisks.profiles);
      assert.isDefined(conf.acceptedRisks.profiles.EnforcePermissionClassifications);
      assert.isUndefined(conf.acceptedRisks.profiles.TestRule);
    });

    it('parses accepted risks with deep and flat matchers', () => {
      // Act
      const fm = new FileManager(ExtendedShapeV1);
      const conf = fm.parse(buildPath('edge-case-risks'));

      // Assert
      assert.isDefined(conf.acceptedRisks);
      assert.isDefined(conf.acceptedRisks.users);
      assert.isDefined(conf.acceptedRisks.users.EnforcePermissionClassifications);
      assert.isDefined(conf.acceptedRisks.users.NoInactiveUsers);
    });

    it('parses role definition from config file if it exists', () => {
      // Act
      const fm = new FileManager(BaseShapeV2, validator);
      const conf = fm.parse(buildPath('custom-roles'));

      // Assert
      assert.isDefined(conf.controls.roles);
      expect(Object.keys(conf.controls.roles)).to.deep.equal([
        'DeployEntity',
        'IntegrationUser',
        'Developer',
        'Ops',
        'Standard',
      ]);
      const deployEntity = conf.controls.roles.DeployEntity;
      assert.isDefined(deployEntity.permissions);
      const perms = deployEntity.permissions as PermissionControl;
      expect(perms.userPermissions?.denied).to.deep.equal(['ViewAllData', 'ModifyAllData']);
      assert.isDefined(conf.inventory.profiles);
      expect(conf.inventory.profiles['API Only Deploy'].role).to.equal('DeployEntity');
    });

    it('runs custom validation logic on profiles classification', () => {
      // Arrange
      const fm = new FileManager(BaseShapeV2, validator);

      // Assert
      expect(() => fm.parse(buildPath('custom-roles-invalid'))).to.throw('Invalid role Admin for profile');
    });
  });

  describe('saving', () => {
    const DEFAULT_TEST_OUTPUT_DIR = path.join('tmp', 'test-outputs', 'audit-config');

    afterEach(() => {
      fs.rmSync(DEFAULT_TEST_OUTPUT_DIR, { recursive: true, force: true });
    });

    it('saves audit config that is compatible with shape', () => {
      // Act
      const fm = new FileManager(BaseShapeV2);
      const saveResult = fm.save(DEFAULT_TEST_OUTPUT_DIR, {
        shape: {
          userPermissions: { TestPermission: { classification: 'Unknown' } },
        },
        policies: {
          profiles: { enabled: true, rules: { TestRule: { enabled: true } } },
          permissionSets: { enabled: true, rules: { TestRule: { enabled: true } } },
        },
      });

      // Assert
      const profilesPath = path.join(DEFAULT_TEST_OUTPUT_DIR, 'policies', 'profiles.yml');
      expect(saveResult.policies.profiles.filePath).to.equal(profilesPath);
      const permsetsPath = path.join(DEFAULT_TEST_OUTPUT_DIR, 'policies', 'permissionSets.yml');
      expect(saveResult.policies.permissionSets.filePath).to.equal(permsetsPath);
      const userClassPath = path.join(DEFAULT_TEST_OUTPUT_DIR, 'shape', 'userPermissions.yml');
      expect(saveResult.shape.userPermissions.filePath).to.equal(userClassPath);
      expect(saveResult.shape.userPermissions.totalEntities).to.equal(1);
      expect(fs.existsSync(userClassPath)).to.be.true;
      expect(fs.existsSync(profilesPath)).to.be.true;
      expect(fs.existsSync(permsetsPath)).to.be.true;
    });

    it('ignores elements in audit config that are not present in shape', () => {
      // Act
      const fm = new FileManager(BaseShapeV2);
      const saveResult = fm.save(DEFAULT_TEST_OUTPUT_DIR, {
        policies: {
          someUnknownPolicy: { enabled: true, rules: { TestRule: { enabled: true } } },
          permissionSets: { enabled: true, rules: { TestRule: { enabled: true } } },
        },
      });

      // Assert
      expect(saveResult.policies.profiles).to.be.undefined;
      const permsetsPath = path.join(DEFAULT_TEST_OUTPUT_DIR, 'policies', 'permissionSets.yml');
      expect(saveResult.policies.permissionSets.filePath).to.equal(permsetsPath);
      const potentialInvalidPath = path.join(DEFAULT_TEST_OUTPUT_DIR, 'policies', 'someUnknownPolicy.yml');
      expect(fs.existsSync(potentialInvalidPath)).to.be.false;
    });

    it('saves accepted risks to disk', () => {
      // Arrange
      const testRuleContent = {
        'Profile Name': {
          'Second Ident': {
            reason: 'Testing',
          },
        },
      };

      const noApexLoginsContent = {
        'test@example.com': {
          '*': {
            reason: 'Logins for this dates are okay',
          },
        },
      };

      // Act
      const fm = new FileManager(ExtendedShapeV1);
      const saveResult = fm.save(DEFAULT_TEST_OUTPUT_DIR, {
        acceptedRisks: {
          profiles: {
            TestRule: testRuleContent,
          },
          users: {
            NoOtherApexApiLogins: noApexLoginsContent,
          },
        },
      });

      // Assert
      const apexLoginsPath = saveResult.acceptedRisks.users.NoOtherApexApiLogins.filePath;
      expect(apexLoginsPath).to.equal(
        path.join(DEFAULT_TEST_OUTPUT_DIR, 'acceptedRisks', 'users', 'NoOtherApexApiLogins.yml')
      );
      expect(saveResult.acceptedRisks.users.NoOtherApexApiLogins.content).to.deep.equal(noApexLoginsContent);
      assertFileContentEquals(apexLoginsPath, noApexLoginsContent);

      const testRulePath = saveResult.acceptedRisks.profiles.TestRule.filePath;
      expect(testRulePath).to.equal(path.join(DEFAULT_TEST_OUTPUT_DIR, 'acceptedRisks', 'profiles', 'TestRule.yml'));
      expect(saveResult.acceptedRisks.profiles.TestRule.content).to.deep.equal(testRuleContent);
      assertFileContentEquals(testRulePath, testRuleContent);
    });

    it('saves existing role definitions to disk', () => {
      // Arrange
      const roleDefs = {
        Ops: {
          allowedPermissions: ['ApiEnabled', 'ViewSetup'],
          allowedClassifications: ['Critical'],
        },
        Standard: {
          allowedClassifications: ['Low'],
        },
      };

      // Act
      const fm = new FileManager(BaseShapeV2);
      const saveResult = fm.save(DEFAULT_TEST_OUTPUT_DIR, {
        controls: {
          roles: roleDefs,
        },
      });

      // Assert
      const defsSaveResult = saveResult.controls.roles;
      expect(defsSaveResult.filePath).to.equal(path.join(DEFAULT_TEST_OUTPUT_DIR, 'controls', 'roles.yml'));
      assertFileContentEquals(defsSaveResult.filePath, roleDefs);
    });

    it('wipes existing role definitions on disk if none exist', () => {
      // Arrange
      const rolesPath = arrangeRoleDefinitions(
        { MyRole: { allowedPermissions: ['TestPerm'] } },
        DEFAULT_TEST_OUTPUT_DIR
      );

      // Act
      const fm = new FileManager(BaseShapeV2);
      const saveResult = fm.save(DEFAULT_TEST_OUTPUT_DIR, {
        controls: {
          roles: undefined,
        },
      });

      // Assert
      const defsSaveResult = saveResult.controls.roles;
      assert.isDefined(defsSaveResult);
      expect(defsSaveResult.content).to.be.undefined;
      expect(fs.existsSync(rolesPath)).to.be.false;
    });
  });
});

function wrapProfileDependencies(deps: ConfigFileDependency[]): AuditConfigShapeDefinition {
  return {
    shape: BaseShapeV2.shape,
    inventory: BaseShapeV2.inventory,
    policies: {
      files: {
        profiles: {
          ...BaseShapeV2.policies.files.profiles,
          dependencies: deps,
        },
        permissionSets: {
          ...BaseShapeV2.policies.files.permissionSets,
        },
      },
    },
  } as const;
}

function assertFileContentEquals(filePath: string, expectedContent: unknown) {
  expect(fs.existsSync(filePath)).to.be.true;
  const actualFileContent = fs.readFileSync(filePath, 'utf-8');
  const parsedContent = yaml.load(actualFileContent);
  expect(parsedContent).to.deep.equal(expectedContent);
}

function arrangeRoleDefinitions(roleContent: unknown, auditConfigDir: string): string {
  const rolesPath = path.join(auditConfigDir, 'controls', 'roles.yml');
  fs.mkdirSync(path.join(auditConfigDir, 'controls'), { recursive: true });
  fs.writeFileSync(rolesPath, yaml.dump(roleContent));
  return rolesPath;
}
