/* eslint-disable camelcase */
import { expect, assert } from 'chai';
import { Messages } from '@salesforce/core';
import AuditTestContext from '../../mocks/auditTestContext.js';
import { UsersPolicyFileContent } from '../../../src/libs/core/file-mgmt/schema.js';
import UserPolicy from '../../../src/libs/core/policies/userPolicy.js';
import { buildPermsetAssignmentsQuery, USERS_LOGIN_HISTORY_QUERY } from '../../../src/libs/core/constants.js';
import { ProfilesRiskPreset } from '../../../src/libs/core/policy-types.js';
import { AuditPolicyResult } from '../../../src/libs/core/result-types.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.users');

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
      expect(resolveResult.resolvedEntities['guest-user@example.de'].assignedProfile).to.equal('Guest User Profile');
      expect(resolveResult.resolvedEntities['test-user-1@example.de'].role).to.equal('Standard User');
      expect(resolveResult.resolvedEntities['test-user-1@example.de'].assignedProfile).to.equal(
        'Standard User Profile'
      );
      expect(resolveResult.resolvedEntities['test-user-2@example.de'].role).to.equal('Admin');
      expect(resolveResult.resolvedEntities['test-user-2@example.de'].assignedProfile).to.equal('System Administrator');
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
        $$.mocks.setQueryMock(USERS_LOGIN_HISTORY_QUERY, 'logins-with-other-apex-api');

        // Act
        const result = await resolveAndRun(ruleEnabledConfig);

        // Assert
        expect(Object.keys(result.executedRules)).deep.equals(['NoOtherApexApiLogins']);
        assert.isDefined(result.executedRules.NoOtherApexApiLogins);
        expect(result.executedRules.NoOtherApexApiLogins.isCompliant).to.be.false;
        expect(result.executedRules.NoOtherApexApiLogins.violations).to.deep.equal([
          {
            identifier: ['test-user-1@example.de'],
            message: messages.getMessage('violations.no-other-apex-api-logins'),
          },
        ]);
      });

      it('reports no violation if user has no logins with "Other Apex API', async () => {
        // Arrange
        $$.mocks.setQueryMock(USERS_LOGIN_HISTORY_QUERY, 'logins-with-browser-only');

        // Act
        const result = await resolveAndRun(ruleEnabledConfig);

        // Assert
        expect(Object.keys(result.executedRules)).deep.equals(['NoOtherApexApiLogins']);
        assert.isDefined(result.executedRules.NoOtherApexApiLogins);
        expect(result.executedRules.NoOtherApexApiLogins.isCompliant).to.be.true;
      });
    });
  });
});
