/* eslint-disable camelcase */
import { expect, assert } from 'chai';
import { Messages } from '@salesforce/core';
import AuditTestContext from '../../mocks/auditTestContext.js';
import { UsersPolicyFileContent } from '../../../src/libs/core/file-mgmt/schema.js';
import UserPolicy from '../../../src/libs/core/policies/userPolicy.js';
import {
  ACTIVE_USERS_DETAILS_QUERY,
  buildLoginHistoryQuery,
  buildPermsetAssignmentsQuery,
} from '../../../src/libs/core/constants.js';
import { ProfilesRiskPreset } from '../../../src/libs/core/policy-types.js';
import { AuditPolicyResult } from '../../../src/libs/core/result-types.js';
import { differenceInDays } from '../../../src/libs/core/utils.js';
import { PermissionRiskLevel } from '../../../src/libs/core/classification-types.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.users');
const auditRunMessages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'org.audit.run');
const permScanningMessages = Messages.loadMessages(
  '@j-schreiber/sf-cli-security-audit',
  'rules.enforceClassificationPresets'
);

const DEFAULT_CONFIG = {
  enabled: true,
  rules: {},
  options: {
    defaultRoleForMissingUsers: 'Standard User',
  },
  users: {
    'guest-user@example.de': {
      role: 'Standard User',
    },
    'test-user-2@example.de': {
      role: 'Admin',
    },
  },
} as UsersPolicyFileContent;

describe('users policy', () => {
  const $$ = new AuditTestContext();

  async function resolveAndRun(config: UsersPolicyFileContent): Promise<AuditPolicyResult> {
    const pol = new UserPolicy(config, $$.mockAuditConfig);
    await pol.resolve({ targetOrgConnection: $$.targetOrgConnection });
    const result = await pol.run({ targetOrgConnection: $$.targetOrgConnection });
    return result;
  }

  function mockUsersLastLoginDate(numberOfDaysSinceLastLogin: number): number {
    const mockLastLogin = Date.now() - 1000 * 60 * 60 * 24 * numberOfDaysSinceLastLogin;
    $$.mocks.setQueryMock(ACTIVE_USERS_DETAILS_QUERY, 'active-user-details', (record) => ({
      ...record,
      LastLoginDate: new Date(mockLastLogin).toISOString(),
    }));
    return mockLastLogin;
  }

  function mockSingleActiveUser(profileName: string): void {
    $$.mocks.setQueryMock(ACTIVE_USERS_DETAILS_QUERY, 'single-active-user', (record) => ({
      ...record,
      Profile: { Name: profileName },
    }));
    $$.mocks.setQueryMock(buildPermsetAssignmentsQuery(['005000000000000AAA']), 'empty');
  }

  beforeEach(async () => {
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  describe('entity resolve', () => {
    it('resolves all users from config with active users on org', async () => {
      // Act
      const pol = new UserPolicy(DEFAULT_CONFIG, $$.mockAuditConfig);
      const resolveResult = await pol.resolve({ targetOrgConnection: $$.targetOrgConnection });

      // Assert
      expect(resolveResult.ignoredEntities).to.deep.equal([]);
      expect(Object.keys(resolveResult.resolvedEntities)).to.deep.equal([
        'guest-user@example.de',
        'test-user-1@example.de',
        'test-user-2@example.de',
      ]);
      expect(resolveResult.resolvedEntities['guest-user@example.de'].role).to.equal('Standard User');
      expect(resolveResult.resolvedEntities['guest-user@example.de'].profileName).to.equal('Guest User Profile');
      expect(resolveResult.resolvedEntities['test-user-1@example.de'].role).to.equal('Standard User');
      expect(resolveResult.resolvedEntities['test-user-1@example.de'].profileName).to.equal('Standard User');
      expect(resolveResult.resolvedEntities['test-user-2@example.de'].role).to.equal('Admin');
      expect(resolveResult.resolvedEntities['test-user-2@example.de'].profileName).to.equal('System Administrator');
    });

    it('ignores users with UNKNOWN role in resolve', async () => {
      // Arrange
      $$.mocks.setQueryMock(
        buildPermsetAssignmentsQuery(['005Pl000001p3HqIAI', '0054P00000AaGueQAF']),
        'test-user-assignments'
      );
      const config = structuredClone(DEFAULT_CONFIG);
      config.users['guest-user@example.de'].role = ProfilesRiskPreset.UNKNOWN;

      // Act
      const pol = new UserPolicy(config, $$.mockAuditConfig);
      const resolveResult = await pol.resolve({ targetOrgConnection: $$.targetOrgConnection });

      // Assert
      expect(resolveResult.ignoredEntities.length).to.equal(1);
      expect(resolveResult.ignoredEntities[0]).to.deep.contain({ name: 'guest-user@example.de' });
      expect(Object.keys(resolveResult.resolvedEntities)).to.deep.equal([
        'test-user-1@example.de',
        'test-user-2@example.de',
      ]);
    });

    it('reports all users from org as total users', async () => {
      // Act
      const resolveListener = $$.context.SANDBOX.stub();
      const pol = new UserPolicy(DEFAULT_CONFIG, $$.mockAuditConfig);
      pol.addListener('entityresolve', resolveListener);
      await pol.resolve({ targetOrgConnection: $$.targetOrgConnection });

      // Assert
      expect(resolveListener.callCount).to.equal(3);
      expect(resolveListener.args.flat()[0]).to.deep.equal({ total: 2, resolved: 0 });
      expect(resolveListener.args.flat()[1]).to.deep.equal({ total: 3, resolved: 0 });
      expect(resolveListener.args.flat()[2]).to.deep.equal({ total: 3, resolved: 3 });
    });

    it('queries full login history if option is not set', async () => {
      // Arrange
      $$.mocks.setQueryMock(buildLoginHistoryQuery(), 'logins-with-browser-only');

      // Act
      const pol = new UserPolicy(DEFAULT_CONFIG, $$.mockAuditConfig);
      const resolveResult = await pol.resolve({ targetOrgConnection: $$.targetOrgConnection });

      // Assert
      const testUser = resolveResult.resolvedEntities['test-user-2@example.de'];
      expect(testUser.logins).to.deep.equal([
        {
          application: 'Browser',
          loginCount: 123,
          loginType: 'Application',
          lastLogin: Date.parse('2025-11-11T12:00:00.000+0000'),
        },
      ]);
    });

    it('queries only last N days of login history if option is set', async () => {
      // Arrange
      const expectedQuery = buildLoginHistoryQuery(30);
      $$.mocks.setQueryMock(expectedQuery, 'logins-with-browser-only');
      const config = structuredClone(DEFAULT_CONFIG);
      config.options.analyseLastNDaysOfLoginHistory = 30;

      // Act
      const pol = new UserPolicy(config, $$.mockAuditConfig);
      const resolveResult = await pol.resolve({ targetOrgConnection: $$.targetOrgConnection });

      // Assert
      const testUser = resolveResult.resolvedEntities['test-user-2@example.de'];
      expect(testUser.logins).to.deep.equal([
        {
          application: 'Browser',
          loginCount: 123,
          loginType: 'Application',
          lastLogin: Date.parse('2025-11-11T12:00:00.000+0000'),
        },
      ]);
    });
  });

  describe('policy rules', () => {
    describe('NoOtherApexApiLogins', () => {
      let ruleEnabledConfig: UsersPolicyFileContent;

      beforeEach(() => {
        ruleEnabledConfig = structuredClone(DEFAULT_CONFIG);
        ruleEnabledConfig.rules['NoOtherApexApiLogins'] = { enabled: true };
      });

      it('reports violation if user has login with "Other Apex API"', async () => {
        // Arrange
        $$.mocks.setQueryMock(buildLoginHistoryQuery(), 'logins-with-other-apex-api');

        // Act
        const result = await resolveAndRun(ruleEnabledConfig);

        // Assert
        expect(Object.keys(result.executedRules)).deep.equals(['NoOtherApexApiLogins']);
        assert.isDefined(result.executedRules.NoOtherApexApiLogins);
        expect(result.executedRules.NoOtherApexApiLogins.isCompliant).to.be.false;
        expect(result.executedRules.NoOtherApexApiLogins.violations).to.deep.equal([
          {
            identifier: ['test-user-1@example.de'],
            message: messages.getMessage('violations.no-other-apex-api-logins', [10]),
          },
        ]);
      });

      it('reports no violation if user has no logins with "Other Apex API', async () => {
        // Arrange
        $$.mocks.setQueryMock(buildLoginHistoryQuery(), 'logins-with-browser-only');

        // Act
        const result = await resolveAndRun(ruleEnabledConfig);

        // Assert
        expect(Object.keys(result.executedRules)).deep.equals(['NoOtherApexApiLogins']);
        assert.isDefined(result.executedRules.NoOtherApexApiLogins);
        expect(result.executedRules.NoOtherApexApiLogins.isCompliant).to.be.true;
      });
    });

    describe('NoInactiveUsers', () => {
      let ruleEnabledConfig: UsersPolicyFileContent;

      beforeEach(() => {
        ruleEnabledConfig = structuredClone(DEFAULT_CONFIG);
        ruleEnabledConfig.rules = {
          NoInactiveUsers: { enabled: true, options: { daysAfterUserIsInactive: 30 } },
        };
      });

      it('reports violation if users last login is after threshold', async () => {
        // Arrange
        const mockLastLogin = mockUsersLastLoginDate(31);

        // Act
        const result = await resolveAndRun(ruleEnabledConfig);

        // Assert
        expect(Object.keys(result.executedRules)).deep.equals(['NoInactiveUsers']);
        assert.isDefined(result.executedRules.NoInactiveUsers);
        expect(result.executedRules.NoInactiveUsers.isCompliant).to.be.false;
        const violationMsg = messages.getMessage('violations.inactive-since-n-days', [
          31,
          new Date(mockLastLogin).toISOString(),
        ]);
        expect(result.executedRules.NoInactiveUsers.violations).to.deep.equal([
          {
            identifier: ['guest-user@example.de'],
            message: violationMsg,
          },
          {
            identifier: ['test-user-1@example.de'],
            message: violationMsg,
          },
          {
            identifier: ['test-user-2@example.de'],
            message: violationMsg,
          },
        ]);
      });

      it('parses config object to default options when none is supplied', async () => {
        // Arrange
        const configWithoutOptions = structuredClone(DEFAULT_CONFIG);
        configWithoutOptions.rules = {
          NoInactiveUsers: { enabled: true },
        };
        mockUsersLastLoginDate(31);

        // Act
        const result = await resolveAndRun(configWithoutOptions);

        // Assert
        expect(Object.keys(result.executedRules)).deep.equals(['NoInactiveUsers']);
        assert.isDefined(result.executedRules.NoInactiveUsers);
      });

      it('bubbles zod error as sf error when parsing fails', async () => {
        // Arrange
        const config = structuredClone(DEFAULT_CONFIG);
        config.rules = {
          NoInactiveUsers: { enabled: true, options: { smthInvalid: 10 } },
        };

        // Assert
        const expectedErrorMsg = auditRunMessages.getMessage('error.InvalidConfigFileSchema', [
          'users.yml',
          'Unrecognized key: "smthInvalid" in "rules.NoInactiveUsers.options"',
        ]);
        expect(() => new UserPolicy(config, $$.mockAuditConfig)).to.throw(expectedErrorMsg);
      });

      it('reports violation if user has never logged in', async () => {
        // Act
        const result = await resolveAndRun(ruleEnabledConfig);

        // Assert
        expect(Object.keys(result.executedRules)).deep.equals(['NoInactiveUsers']);
        assert.isDefined(result.executedRules.NoInactiveUsers);
        expect(result.executedRules.NoInactiveUsers.isCompliant).to.be.false;
        const daysSinceCreated = differenceInDays('2025-10-09T12:00:00.000Z', Date.now());
        expect(result.executedRules.NoInactiveUsers.violations).to.deep.contain({
          identifier: ['test-user-1@example.de'],
          message: messages.getMessage('violations.has-never-logged-in', [
            '2025-10-09T12:00:00.000Z',
            daysSinceCreated,
          ]),
        });
      });

      it('reports no violation if users last login is within threshold', async () => {
        // Arrange
        $$.mocks.setQueryMock(ACTIVE_USERS_DETAILS_QUERY, 'active-user-details', (record) => ({
          ...record,
          LastLoginDate: new Date().toISOString(),
        }));

        // Act
        const result = await resolveAndRun(ruleEnabledConfig);

        // Assert
        expect(Object.keys(result.executedRules)).deep.equals(['NoInactiveUsers']);
        assert.isDefined(result.executedRules.NoInactiveUsers);
        expect(result.executedRules.NoInactiveUsers.isCompliant).to.be.true;
      });
    });

    describe('EnforcePermissionClassifications', () => {
      let ruleEnabledConfig: UsersPolicyFileContent;
      const testUserIds = ['0054P00000AYPYXQA5', '005Pl000001p3HqIAI', '0054P00000AaGueQAF'];

      beforeEach(() => {
        ruleEnabledConfig = structuredClone(DEFAULT_CONFIG);
        ruleEnabledConfig.rules = {
          EnforcePermissionClassifications: { enabled: true },
        };
        // no assignments for guest user and user 1, only for test-user-2 (admin)
        $$.mocks.setQueryMock(buildPermsetAssignmentsQuery(testUserIds), 'test-user-assignments');
      });

      it('reports compliance if user role allows all assigned permissions', async () => {
        // Arrange
        // mock classification for some of the profile & perm sets that are okay for user
        // profiles and permsets grant >200 perms, but all of them will be ignored because
        // they are not classified. LOW is okay for standard users
        $$.mockAuditConfig.classifications.userPermissions = {
          content: {
            permissions: {
              ViewSetup: {
                classification: PermissionRiskLevel.LOW,
              },
            },
          },
        };

        // Act
        const result = await resolveAndRun(ruleEnabledConfig);

        // Assert
        expect(Object.keys(result.executedRules)).deep.equals(['EnforcePermissionClassifications']);
        assert.isDefined(result.executedRules.EnforcePermissionClassifications);
        const ruleResult = result.executedRules.EnforcePermissionClassifications;
        expect(ruleResult.isCompliant).to.be.true;
        expect(ruleResult.compliantEntities).to.deep.equal([
          'guest-user@example.de',
          'test-user-1@example.de',
          'test-user-2@example.de',
        ]);
      });

      it('reports violation if user has an permission that is not allowed', async () => {
        // Arrange
        $$.mockAuditConfig.classifications.userPermissions = {
          content: {
            permissions: {
              ViewSetup: {
                classification: PermissionRiskLevel.CRITICAL,
              },
            },
          },
        };

        // Act
        const result = await resolveAndRun(ruleEnabledConfig);

        // Assert
        assert.isDefined(result.executedRules.EnforcePermissionClassifications);
        const ruleResult = result.executedRules.EnforcePermissionClassifications;
        expect(ruleResult.isCompliant).to.be.false;
        expect(ruleResult.compliantEntities).to.deep.equal(['guest-user@example.de']);
        expect(ruleResult.violatedEntities).to.deep.equal(['test-user-1@example.de', 'test-user-2@example.de']);
        expect(ruleResult.violations).to.deep.equal([
          {
            identifier: ['test-user-1@example.de', 'Standard User', 'ViewSetup'],
            message: criticalMismatchMsg('Standard User'),
          },
          {
            identifier: ['test-user-2@example.de', 'Test_Admin_Permission_Set_1', 'ViewSetup'],
            message: criticalMismatchMsg('Admin'),
          },
          {
            identifier: ['test-user-2@example.de', 'System Administrator', 'ViewSetup'],
            message: criticalMismatchMsg('Admin'),
          },
        ]);
      });

      it('skips users with a profile that cannot be resolved to metadata', async () => {
        // Arrange
        mockSingleActiveUser('Custom Profile');

        // Act
        const result = await resolveAndRun(ruleEnabledConfig);

        // Assert
        assert.isDefined(result.executedRules.EnforcePermissionClassifications);
        const ruleResult = result.executedRules.EnforcePermissionClassifications;
        expect(ruleResult.isCompliant).to.be.true;
      });
    });

    describe('EnforcePermissionPresets', () => {
      let ruleEnabledConfig: UsersPolicyFileContent;
      const testUserIds = ['0054P00000AYPYXQA5', '005Pl000001p3HqIAI', '0054P00000AaGueQAF'];

      beforeEach(() => {
        ruleEnabledConfig = structuredClone(DEFAULT_CONFIG);
        ruleEnabledConfig.rules = {
          EnforcePermissionPresets: { enabled: true },
        };
        // no assignments for guest user and user 1, only for test-user-2 (admin)
        $$.mocks.setQueryMock(buildPermsetAssignmentsQuery(testUserIds), 'test-user-assignments');
        // default classifications for the permission sets and profiles that are used
        // throughout the tests of this particular rule
        $$.mockAuditConfig.policies.permissionSets = {
          content: {
            enabled: true,
            permissionSets: {
              Test_Admin_Permission_Set_1: {
                preset: ProfilesRiskPreset.ADMIN,
              },
              Test_Power_User_Permission_Set_1: {
                preset: ProfilesRiskPreset.POWER_USER,
              },
            },
            rules: {},
          },
        };
        $$.mockAuditConfig.policies.profiles = {
          content: {
            enabled: true,
            profiles: {
              'System Administrator': {
                preset: ProfilesRiskPreset.ADMIN,
              },
              'Standard User': {
                preset: ProfilesRiskPreset.STANDARD_USER,
              },
              'Guest User Profile': {
                preset: ProfilesRiskPreset.STANDARD_USER,
              },
            },
            rules: {},
          },
        };
      });

      it('reports compliance if user has only permission sets assigned that match their role', async () => {
        // Act
        const result = await resolveAndRun(ruleEnabledConfig);

        // Assert
        expect(Object.keys(result.executedRules)).deep.equals(['EnforcePermissionPresets']);
        assert.isDefined(result.executedRules.EnforcePermissionPresets);
        const ruleResult = result.executedRules.EnforcePermissionPresets;
        expect(ruleResult.isCompliant).to.be.true;
        expect(ruleResult.compliantEntities).to.deep.equal([
          'guest-user@example.de',
          'test-user-1@example.de',
          'test-user-2@example.de',
        ]);
      });

      it('reports violations if user has permissions assigned that are above their role', async () => {
        // Arrange
        ruleEnabledConfig.users['test-user-2@example.de'].role = ProfilesRiskPreset.POWER_USER;

        // Act
        const result = await resolveAndRun(ruleEnabledConfig);

        // Assert
        assert.isDefined(result.executedRules.EnforcePermissionPresets);
        const ruleResult = result.executedRules.EnforcePermissionPresets;
        expect(ruleResult.compliantEntities).to.deep.equal(['guest-user@example.de', 'test-user-1@example.de']);
        expect(ruleResult.violatedEntities).to.deep.equal(['test-user-2@example.de']);
        expect(ruleResult.violations).to.deep.equal([
          {
            message: messages.getMessage('violations.entity-not-allowed-for-user-role', [
              'Power User',
              'profile',
              'Admin',
            ]),
            identifier: ['test-user-2@example.de', 'System Administrator'],
          },
          {
            message: messages.getMessage('violations.entity-not-allowed-for-user-role', [
              'Power User',
              'permission set',
              'Admin',
            ]),
            identifier: ['test-user-2@example.de', 'Test_Admin_Permission_Set_1'],
          },
        ]);
      });

      it('reports violations if users profile is classified as UNKNOWN', async () => {
        // Arrange
        $$.mockAuditConfig.policies.profiles!.content.profiles['System Administrator'].preset =
          ProfilesRiskPreset.UNKNOWN;

        // Act
        const result = await resolveAndRun(ruleEnabledConfig);

        // Assert
        assert.isDefined(result.executedRules.EnforcePermissionPresets);
        const ruleResult = result.executedRules.EnforcePermissionPresets;
        expect(ruleResult.compliantEntities).to.deep.equal(['guest-user@example.de', 'test-user-1@example.de']);
        expect(ruleResult.violatedEntities).to.deep.equal(['test-user-2@example.de']);
        expect(ruleResult.violations).to.deep.equal([
          {
            message: messages.getMessage('violations.entity-unknown-but-used', ['Profile']),
            identifier: ['test-user-2@example.de', 'System Administrator'],
          },
        ]);
      });

      it('reports violations if profile is not classified in policy', async () => {
        // Arrange
        // user has admin, remove it
        $$.mockAuditConfig.policies.profiles!.content.profiles = {
          'Standard User': {
            preset: ProfilesRiskPreset.STANDARD_USER,
          },
          'Guest User Profile': {
            preset: ProfilesRiskPreset.STANDARD_USER,
          },
        };

        // Act
        const result = await resolveAndRun(ruleEnabledConfig);

        // Assert
        assert.isDefined(result.executedRules.EnforcePermissionPresets);
        const ruleResult = result.executedRules.EnforcePermissionPresets;
        expect(ruleResult.violatedEntities).to.deep.equal(['test-user-2@example.de']);
        expect(ruleResult.violations).to.deep.equal([
          {
            message: messages.getMessage('violations.entity-not-classified-but-used', ['Profile', 'profile']),
            identifier: ['test-user-2@example.de', 'System Administrator'],
          },
        ]);
      });
    });
  });
});

function criticalMismatchMsg(presetName: string): string {
  return permScanningMessages.getMessage('violations.classification-preset-mismatch', [
    PermissionRiskLevel.CRITICAL,
    presetName,
  ]);
}
