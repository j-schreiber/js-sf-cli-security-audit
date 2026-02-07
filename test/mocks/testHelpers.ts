import fs from 'node:fs';
import path from 'node:path';
import { expect } from 'chai';
import { XMLParser } from 'fast-xml-parser';
import { Record as JsForceRecord } from '@jsforce/jsforce-node';
import { PermissionSet, Profile } from '@jsforce/jsforce-node/lib/api/metadata.js';
import { SfError } from '@salesforce/core';
import { Registry } from '../../src/salesforce/mdapi/metadataRegistry.js';
import { PartialPolicyRuleResult } from '../../src/libs/audit-engine/registry/context.types.js';
import {
  AuditPolicyResult,
  PolicyRuleViolation,
  PolicyRuleViolationMute,
  RuleComponentMessage,
} from '../../src/libs/audit-engine/registry/result.types.js';
import AcceptedRisks from '../../src/libs/audit-engine/accepted-risks/acceptedRisks.js';
import { loadPolicy, Policies } from '../../src/libs/audit-engine/index.js';
import { MOCK_DATA_BASE_PATH, RETRIEVES_BASE } from './data/paths.js';
import AuditTestContext from './auditTestContext.js';

/**
 * Runs policy with the mocked audit config. Add policy config
 * classifications to mock context before calling this.
 *
 * @returns Policy result
 */
export async function resolveAndRun(policy: Policies, context: AuditTestContext): Promise<AuditPolicyResult> {
  const pol = loadPolicy(policy, context.mockAuditConfig);
  await pol.resolve({ targetOrgConnection: context.targetOrgConnection });
  const partials = await pol.executeRules({ targetOrgConnection: context.targetOrgConnection });
  return pol.finalise(partials, new AcceptedRisks(context.mockAuditConfig.acceptedRisks));
}

export function newRuleResult(ruleName?: string): PartialPolicyRuleResult {
  return {
    ruleName: ruleName ?? 'Mock_Rule',
    violations: new Array<PolicyRuleViolation>(),
    mutedViolations: new Array<PolicyRuleViolationMute>(),
    warnings: new Array<RuleComponentMessage>(),
    errors: [],
  };
}

export function parsePermSetFromFile(permSetName: string): PermissionSet {
  const permsetPath = path.join(RETRIEVES_BASE, 'full-permsets', `${permSetName}.permissionset-meta.xml`);
  return Registry.namedTypes.PermissionSet.parse(permsetPath)!;
}

export function parseProfileFromFile(fileName: string): Profile {
  const profilePath = path.join(MOCK_DATA_BASE_PATH, 'profiles-metadata', `${fileName}.json`);
  return (JSON.parse(fs.readFileSync(profilePath, 'utf-8')) as JsForceRecord[])[0]['Metadata'] as Profile;
}

export function parseFileAsJson<T>(...filePath: string[]): T {
  const fileContent = fs.readFileSync(path.join(MOCK_DATA_BASE_PATH, ...filePath), 'utf-8');
  return JSON.parse(fileContent) as T;
}

export function parseXmlFile<T>(...filePath: string[]): T {
  const fileContent = fs.readFileSync(path.join(MOCK_DATA_BASE_PATH, ...filePath), 'utf-8');
  return new XMLParser().parse(fileContent) as T;
}

export function assertSfError(err: unknown, expectedName: string, expectedMsg?: string) {
  if (err instanceof SfError) {
    expect(err.name).to.equal(expectedName + 'Error');
    if (expectedMsg) {
      expect(err.message).to.contain(expectedMsg);
    }
  } else {
    expect.fail('Expected SfError, but got: ' + JSON.stringify(err));
  }
}
