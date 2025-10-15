import { readFileSync } from 'node:fs';
import { Connection } from '@salesforce/core';
import { ComponentSet, RetrieveSetOptions } from '@salesforce/source-deploy-retrieve';
import { XMLParser } from 'fast-xml-parser';
import { PermissionSet } from '@jsforce/jsforce-node/lib/api/metadata.js';

const parser = new XMLParser({
  isArray: (jpath): boolean =>
    ['userPermissions', 'fieldPermissions', 'customPermissions', 'classAccesses'].includes(jpath),
});

export type PermissionSetMetadata = {
  PermissionSet: PermissionSet;
};

export default class MdapiRetriever {
  public constructor(private connection: Connection) {}

  public async retrievePermissionsets(componentNames: string[]): Promise<Record<string, PermissionSet>> {
    const components = componentNames.map((cname) => ({ type: 'PermissionSet', fullName: cname }));
    if (components.length === 0) {
      return {};
    }
    const compSet = new ComponentSet(components);
    const retrieveOptions: RetrieveSetOptions = {
      usernameOrConnection: this.connection,
      output: '.jsc/retrieves',
    };
    const retrieveRequest = await compSet.retrieve(retrieveOptions);
    const retrieveResult = await retrieveRequest.pollStatus();
    const result: Record<string, PermissionSet> = {};
    retrieveResult.components
      .getSourceComponents()
      .toArray()
      .forEach((sourceComponent) => {
        if (sourceComponent.xml) {
          result[sourceComponent.name] = parseAsPermissionset(sourceComponent.xml);
        }
      });
    return result;
  }
}

export function parseAsPermissionset(filePath: string): PermissionSet {
  const cmpSrcContent = readFileSync(filePath, 'utf-8');
  return (parser.parse(cmpSrcContent) as PermissionSetMetadata).PermissionSet;
}
