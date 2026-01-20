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
  PolicyRuleViolation,
  PolicyRuleViolationMute,
  RuleComponentMessage,
} from '../../src/libs/audit-engine/registry/result.types.js';
import { MOCK_DATA_BASE_PATH, QUERY_RESULTS_BASE, RETRIEVES_BASE } from './data/paths.js';

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
  return Registry.namedTypes.PermissionSet.parse(permsetPath);
}

export function parseProfileFromFile(fileName: string): Profile {
  const profilePath = path.join(QUERY_RESULTS_BASE, `${fileName}.json`);
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
