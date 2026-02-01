/* eslint-disable camelcase */
import { expect, assert } from 'chai';
import { Messages } from '@salesforce/core';
import AuditTestContext from '../../mocks/auditTestContext.js';
import { AuditPolicyResult } from '../../../src/libs/audit-engine/registry/result.types.js';
import { differenceInDays } from '../../../src/utils.js';
import { loadPolicy } from '../../../src/libs/audit-engine/index.js';
import {
  PermissionRiskLevel,
  UserPolicyConfig,
  UserPrivilegeLevel,
} from '../../../src/libs/audit-engine/registry/shape/schema.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.users');
const auditRunMessages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'org.audit.run');
const permScanningMessages = Messages.loadMessages(
  '@j-schreiber/sf-cli-security-audit',
  'rules.enforceClassificationPresets'
);

describe('users policy', () => {
  const $$ = new AuditTestContext();
  let defaultConfig: UserPolicyConfig;

  /**
   * Runs user policy with the mocked audit config. Add policy config
   * classifications to mock context before calling this.
   *
   * @returns Policy result
   */
  async function resolveAndRun(): Promise<AuditPolicyResult> {
    const pol = loadPolicy('users', $$.mockAuditConfig);
    await pol.resolve({ targetOrgConnection: $$.targetOrgConnection });
    const result = await pol.run({ targetOrgConnection: $$.targetOrgConnection });
    return result;
  }

  function mockUsersLastLoginDate(numberOfDaysSinceLastLogin: number): number {
    const mockLastLogin = Date.now() - 1000 * 60 * 60 * 24 * numberOfDaysSinceLastLogin;
    $$.mocks.mockUsers('active-user-details', (record) => ({
      ...record,
      LastLoginDate: new Date(mockLastLogin).toISOString(),
    }));
    return mockLastLogin;
  }

  /**
   * Mocks result for the policy resolve that returns the
   * users to be evaluated and sets the profile for this user.
   *
   * @param profileName
   */
  function mockSingleUser(profileName: string, isActive: boolean = true): void {
    $$.mocks.mockUsers('single-active-user', (record) => ({
      ...record,
      IsActive: isActive,
      Profile: { Name: profileName },
    }));
    $$.mocks.mockPermsetAssignments('empty', ['005000000000000AAA']);
  }

  beforeEach(async () => {
    $$.mockUserClassification('guest-user@example.de', {
      role: UserPrivilegeLevel.STANDARD_USER,
    });
    $$.mockUserClassification('test-user-2@example.de', {
      role: UserPrivilegeLevel.ADMIN,
    });
    defaultConfig = {
      enabled: true,
      rules: {},
      options: {
        defaultRoleForMissingUsers: UserPrivilegeLevel.STANDARD_USER,
      },
    };
    $$.mockAuditConfig.policies.users = defaultConfig;
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  describe('entity resolve', () => {
    it('resolves all users from config with active users on org', async () => {
      // Act
      const pol = loadPolicy('users', $$.mockAuditConfig);
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
      $$.mocks.mockPermsetAssignments('test-user-assignments', ['005Pl000001p3HqIAI', '0054P00000AaGueQAF']);
      $$.mockUserClassification('guest-user@example.de', { role: UserPrivilegeLevel.UNKNOWN });

      // Act
      const pol = loadPolicy('users', $$.mockAuditConfig);
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
      const pol = loadPolicy('users', $$.mockAuditConfig);
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
      $$.mocks.mockLoginHistory('logins-with-browser-only');
      defaultConfig.rules = { NoInactiveUsers: { enabled: true } };

      // Act
      const pol = loadPolicy('users', $$.mockAuditConfig);
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
      $$.mocks.mockLoginHistory('logins-with-browser-only', 30);
      $$.mockAuditConfig.policies.users = {
        enabled: true,
        rules: { NoInactiveUsers: { enabled: true } },
        options: {
          defaultRoleForMissingUsers: UserPrivilegeLevel.STANDARD_USER,
          analyseLastNDaysOfLoginHistory: 30,
        },
      };

      // Act
      const pol = loadPolicy('users', $$.mockAuditConfig);
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
      let ruleEnabledConfig: UserPolicyConfig;

      beforeEach(() => {
        ruleEnabledConfig = {
          enabled: true,
          rules: {
            NoOtherApexApiLogins: { enabled: true },
          },
          options: {
            defaultRoleForMissingUsers: UserPrivilegeLevel.STANDARD_USER,
            analyseLastNDaysOfLoginHistory: 30,
          },
        };
        $$.mockAuditConfig.policies.users = ruleEnabledConfig;
      });

      it('reports violation if user has login with "Other Apex API"', async () => {
        // Arrange
        $$.mocks.mockLoginHistory(
          'logins-with-other-apex-api',
          ruleEnabledConfig.options.analyseLastNDaysOfLoginHistory
        );

        // Act
        const result = await resolveAndRun();

        // Assert
        expect(Object.keys(result.executedRules)).deep.equals(['NoOtherApexApiLogins']);
        assert.isDefined(result.executedRules.NoOtherApexApiLogins);
        expect(result.executedRules.NoOtherApexApiLogins.isCompliant).to.be.false;
        expect(result.executedRules.NoOtherApexApiLogins.violations).to.deep.equal([
          {
            identifier: ['test-user-1@example.de', '2025-08-07T10:01:17.000Z'],
            message: messages.getMessage('violations.no-other-apex-api-logins', [
              10,
              ruleEnabledConfig.options.analyseLastNDaysOfLoginHistory,
            ]),
          },
        ]);
      });

      it('reports no violation if user has no logins with "Other Apex API', async () => {
        // Arrange
        $$.mocks.mockLoginHistory('logins-with-browser-only', ruleEnabledConfig.options.analyseLastNDaysOfLoginHistory);

        // Act
        const result = await resolveAndRun();

        // Assert
        expect(Object.keys(result.executedRules)).deep.equals(['NoOtherApexApiLogins']);
        assert.isDefined(result.executedRules.NoOtherApexApiLogins);
        expect(result.executedRules.NoOtherApexApiLogins.isCompliant).to.be.true;
      });
    });

    describe('NoInactiveUsers', () => {
      beforeEach(() => {
        $$.mockAuditConfig.policies.users = {
          enabled: true,
          rules: {
            NoInactiveUsers: { enabled: true, options: { daysAfterUserIsInactive: 30 } },
          },
          options: {
            defaultRoleForMissingUsers: UserPrivilegeLevel.STANDARD_USER,
          },
        };
      });

      it('reports violation if users last login is after threshold', async () => {
        // Arrange
        const mockLastLogin = mockUsersLastLoginDate(31);

        // Act
        const result = await resolveAndRun();

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
        $$.mockAuditConfig.policies.users!.rules = {
          NoInactiveUsers: { enabled: true },
        };
        mockUsersLastLoginDate(31);

        // Act
        const result = await resolveAndRun();

        // Assert
        expect(Object.keys(result.executedRules)).deep.equals(['NoInactiveUsers']);
        assert.isDefined(result.executedRules.NoInactiveUsers);
      });

      it('bubbles zod error as sf error when parsing fails', async () => {
        // Arrange
        $$.mockAuditConfig.policies.users!.rules = {
          NoInactiveUsers: { enabled: true, options: { smthInvalid: 10 } },
        };

        // Assert
        const expectedErrorMsg = auditRunMessages.getMessage('error.InvalidConfigFileSchema', [
          'users.yml',
          'Unrecognized key: "smthInvalid" in "rules.NoInactiveUsers.options"',
        ]);
        expect(() => loadPolicy('users', $$.mockAuditConfig)).to.throw(expectedErrorMsg);
      });

      it('reports violation if user has never logged in', async () => {
        // Act
        const result = await resolveAndRun();

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
        $$.mocks.mockUsers('active-user-details', (record) => ({
          ...record,
          LastLoginDate: new Date().toISOString(),
        }));

        // Act
        const result = await resolveAndRun();

        // Assert
        expect(Object.keys(result.executedRules)).deep.equals(['NoInactiveUsers']);
        assert.isDefined(result.executedRules.NoInactiveUsers);
        expect(result.executedRules.NoInactiveUsers.isCompliant).to.be.true;
      });
    });

    describe('EnforcePermissionClassifications', () => {
      const testUserIds = ['0054P00000AYPYXQA5', '005Pl000001p3HqIAI', '0054P00000AaGueQAF'];

      beforeEach(() => {
        $$.mockAuditConfig.policies.users = {
          enabled: true,
          rules: {
            EnforcePermissionClassifications: { enabled: true },
          },
          options: {
            defaultRoleForMissingUsers: UserPrivilegeLevel.STANDARD_USER,
          },
        };
        // no assignments for guest user and user 1, only for test-user-2 (admin)
        $$.mocks.mockPermsetAssignments('test-user-assignments', testUserIds);
      });

      it('reports compliance if user role allows all assigned permissions', async () => {
        // Arrange
        // mock classification for some of the profile & perm sets that are okay for user
        // profiles and permsets grant >200 perms, but all of them will be ignored because
        // they are not classified. LOW is okay for standard users
        $$.mockAuditConfig.classifications.userPermissions = {
          permissions: {
            ViewSetup: {
              classification: PermissionRiskLevel.LOW,
            },
          },
        };

        // Act
        const result = await resolveAndRun();

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
          permissions: {
            ViewSetup: {
              classification: PermissionRiskLevel.CRITICAL,
            },
          },
        };

        // Act
        const result = await resolveAndRun();

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
        mockSingleUser('Custom Profile');

        // Act
        const result = await resolveAndRun();

        // Assert
        assert.isDefined(result.executedRules.EnforcePermissionClassifications);
        const ruleResult = result.executedRules.EnforcePermissionClassifications;
        expect(ruleResult.isCompliant).to.be.true;
      });
    });

    describe('EnforcePermissionPresets', () => {
      const testUserIds = ['0054P00000AYPYXQA5', '005Pl000001p3HqIAI', '0054P00000AaGueQAF'];

      beforeEach(() => {
        $$.mockAuditConfig.policies.users = {
          enabled: true,
          rules: {
            EnforcePermissionPresets: { enabled: true },
          },
          options: {
            defaultRoleForMissingUsers: UserPrivilegeLevel.STANDARD_USER,
          },
        };
        // no assignments for guest user and user 1, only for test-user-2 (admin)
        $$.mocks.mockPermsetAssignments('test-user-assignments', testUserIds);
        // default classifications for the permission sets and profiles that are used
        // throughout the tests of this particular rule
        $$.mockPermSetClassifications({
          Test_Admin_Permission_Set_1: {
            role: UserPrivilegeLevel.ADMIN,
          },
          Test_Power_User_Permission_Set_1: {
            role: UserPrivilegeLevel.POWER_USER,
          },
        });
        $$.mockProfileClassifications({
          'System Administrator': {
            role: UserPrivilegeLevel.ADMIN,
          },
          'Standard User': {
            role: UserPrivilegeLevel.STANDARD_USER,
          },
          'Guest User Profile': {
            role: UserPrivilegeLevel.STANDARD_USER,
          },
        });
      });

      it('reports compliance if user has only permission sets assigned that match their role', async () => {
        // Act
        const result = await resolveAndRun();

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
        $$.mockUserClassification('test-user-2@example.de', { role: UserPrivilegeLevel.POWER_USER });

        // Act
        const result = await resolveAndRun();

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
        $$.mockProfileClassification('System Administrator', { role: UserPrivilegeLevel.UNKNOWN });

        // Act
        const result = await resolveAndRun();

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
        $$.mockProfileClassifications({
          'Standard User': {
            role: UserPrivilegeLevel.STANDARD_USER,
          },
          'Guest User Profile': {
            role: UserPrivilegeLevel.STANDARD_USER,
          },
        });

        // Act
        const result = await resolveAndRun();

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

    describe('NoStandardProfilesOnActiveUsers', () => {
      let ruleConfig: UserPolicyConfig;

      beforeEach(() => {
        ruleConfig = {
          enabled: true,
          rules: {
            NoStandardProfilesOnActiveUsers: {
              enabled: true,
            },
          },
          options: {
            defaultRoleForMissingUsers: UserPrivilegeLevel.STANDARD_USER,
          },
        };
        $$.mockAuditConfig.policies.users = ruleConfig;
      });

      it('reports violation for an active user that has a standard profile', async () => {
        // Arrange
        mockSingleUser('System Administrator');

        // Act
        const result = await resolveAndRun();

        // Assert
        const ruleResult = result.executedRules.NoStandardProfilesOnActiveUsers;
        assert.isDefined(ruleResult);
        expect(ruleResult.violations).to.deep.equal([
          {
            identifier: ['test-user-1@example.de', 'System Administrator'],
            message: messages.getMessage('violations.active-user-has-standard-profile'),
          },
        ]);
      });

      it('reports no violation when an active user has a custom profile', async () => {
        // Arrange
        mockSingleUser('Custom Profile');

        // Act
        const result = await resolveAndRun();

        // Assert
        const ruleResult = result.executedRules.NoStandardProfilesOnActiveUsers;
        assert.isDefined(ruleResult);
        expect(ruleResult.violations).to.deep.equal([]);
      });

      it('reports no violation when an inactive user has a standard profile', async () => {
        // Arrange
        // at the moment, the users policy only processes active users
        // to be upwards compatible when this may change in the future,
        // this rule explicitly skips users that are not active
        mockSingleUser('Standard User', false);

        // Act
        const result = await resolveAndRun();

        // Assert
        const ruleResult = result.executedRules.NoStandardProfilesOnActiveUsers;
        assert.isDefined(ruleResult);
        expect(ruleResult.violations).to.deep.equal([]);
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
