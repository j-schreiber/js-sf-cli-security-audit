import { readFileSync } from 'node:fs';
import { Connection } from '@salesforce/core';
import { ComponentLike, ComponentSet, RetrieveResult, RetrieveSetOptions } from '@salesforce/source-deploy-retrieve';
import { XMLParser } from 'fast-xml-parser';
import { ConnectedAppSettings, PermissionSet } from '@jsforce/jsforce-node/lib/api/metadata.js';

const parser = new XMLParser({
  isArray: (jpath): boolean =>
    ['userPermissions', 'fieldPermissions', 'customPermissions', 'classAccesses'].includes(jpath),
});

export type PermissionSetMetadata = {
  PermissionSet: PermissionSet;
};

export type ConnectedAppSettingsFileContent = {
  ConnectedAppSettings: ConnectedAppSettings;
};

export default class MdapiRetriever {
  private readonly retrieveOptions: RetrieveSetOptions;

  public constructor(private connection: Connection) {
    this.retrieveOptions = {
      usernameOrConnection: this.connection,
      output: '.jsc/retrieves',
    };
  }

  public async retrievePermissionsets(componentNames: string[]): Promise<Record<string, PermissionSet>> {
    const components = componentNames.map((cname) => ({ type: 'PermissionSet', fullName: cname }));
    if (components.length === 0) {
      return {};
    }
    const retrieveResult = await this.retrieve(components);
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

  public async retrieveConnectedAppSetting(): Promise<ConnectedAppSettings | undefined> {
    const cmp = { type: 'Settings', fullName: 'ConnectedApp' };
    const retrieveResult = await this.retrieve([cmp]);
    if (retrieveResult.components.getSourceComponents().toArray().length === 1) {
      const filePath = retrieveResult.components.getSourceComponents().toArray()[0].xml;
      if (filePath) {
        return parseAsConnectedAppSetting(filePath);
      }
    }
    return undefined;
  }

  private async retrieve(components: ComponentLike[]): Promise<RetrieveResult> {
    const compSet = new ComponentSet(components);
    const retrieveRequest = await compSet.retrieve(this.retrieveOptions);
    const retrieveResult = await retrieveRequest.pollStatus();
    return retrieveResult;
  }
}

export function parseAsPermissionset(filePath: string): PermissionSet {
  const cmpSrcContent = readFileSync(filePath, 'utf-8');
  return (parser.parse(cmpSrcContent) as PermissionSetMetadata).PermissionSet;
}

export function parseAsConnectedAppSetting(filePath: string): ConnectedAppSettings {
  const cmpSrcContent = readFileSync(filePath, 'utf-8');
  return (parser.parse(cmpSrcContent) as ConnectedAppSettingsFileContent).ConnectedAppSettings;
}
