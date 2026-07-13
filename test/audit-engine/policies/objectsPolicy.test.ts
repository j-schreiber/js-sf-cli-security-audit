import { expect, assert } from 'chai';
// import { Messages } from '@salesforce/core';
import AuditTestContext from '../../mocks/auditTestContext.js';
import { resolveAndRun } from '../../mocks/testHelpers.js';
import { PolicyConfig } from '../../../src/libs/audit-engine/registry/shape/schema.js';

// Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
// const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'policies.general');

describe('policy - objects', () => {
  const $$ = new AuditTestContext();
  let defaultConfig: PolicyConfig;

  beforeEach(async () => {
    defaultConfig = {
      enabled: true,
      rules: {
        PrivateExternalAccessForAllObjects: {
          enabled: true,
        },
      },
    };
    $$.mockAuditConfig.policies.objects = defaultConfig;
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  describe('PrivateExternalAccessForAllObjects', () => {
    beforeEach(() => {
      defaultConfig = {
        enabled: true,
        rules: {
          PrivateExternalAccessForAllObjects: {
            enabled: true,
          },
        },
      };
      $$.mockAuditConfig.policies.objects = defaultConfig;
      $$.mocks.mockEntityDefinitions(
        ['Account', 'MyCustomObject1__c', 'MyCustomObject2__c', 'MyCustomObject3__c', 'RecordActnSelItemExtrc'],
        'default-entity-definitions'
      );
    });

    it('throws violations for non-private custom and standard objects', async () => {
      // Act
      const policyResult = await resolveAndRun('objects', $$);

      // Assert
      expect(policyResult.auditedEntities).to.have.members([
        'Account',
        'MyCustomObject1__c',
        'MyCustomObject2__c',
        'MyCustomObject3__c',
        'RecordActnSelItemExtrc',
      ]);
      assert.isDefined(policyResult.executedRules.PrivateExternalAccessForAllObjects);
      const ruleResult = policyResult.executedRules.PrivateExternalAccessForAllObjects;
      expect(ruleResult.isCompliant).to.be.false;
      expect(ruleResult.violatedEntities).to.have.members(['Account', 'MyCustomObject1__c', 'MyCustomObject2__c']);
      expect(ruleResult.compliantEntities).to.have.members(['MyCustomObject3__c', 'RecordActnSelItemExtrc']);
    });
  });
});
