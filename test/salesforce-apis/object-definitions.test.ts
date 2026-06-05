import { expect } from 'chai';
import AuditTestContext from '../mocks/auditTestContext.js';
import { Objects } from '../../src/salesforce/index.js';
import { CUSTOM_OBJECT_BASE_QUERY } from '../../src/salesforce/repositories/object-definitions/object-definitions.types.js';

describe('object definitions resolve', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
    await $$.init();
    $$.mocks.mockEntityDefinitions(
      ['Account', 'MyCustomObject__c', 'MyOtherCustomObject__c', 'RecordActnSelItemExtrc'],
      'default-entity-definitions'
    );
    $$.mocks.setQueryMock(CUSTOM_OBJECT_BASE_QUERY, 'default-custom-objects');
  });

  afterEach(async () => {
    $$.reset();
  });

  it('resolves all objects that are returned by metadata list command', async () => {
    // Act
    const repo = new Objects($$.targetOrgConnection);
    const objects = await repo.resolve();

    // Assert
    expect(objects.size).to.equal(4);
    expect(objects).keys(['Account', 'MyCustomObject__c', 'MyOtherCustomObject__c', 'RecordActnSelItemExtrc']);
  });
});
