import fs from 'node:fs';
import path from 'node:path';
import { XMLParser } from 'fast-xml-parser';
import { Record as JsForceRecord } from '@jsforce/jsforce-node';
import { PermissionSet, Profile } from '@jsforce/jsforce-node/lib/api/metadata.js';
import { Registry } from '../../src/salesforce/mdapi/metadataRegistry.js';
import { MOCK_DATA_BASE_PATH, QUERY_RESULTS_BASE, RETRIEVES_BASE } from './data/paths.js';

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
