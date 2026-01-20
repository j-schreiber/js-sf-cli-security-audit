import { XMLParser } from 'fast-xml-parser';
import { Connection } from '@salesforce/core';
import { ComponentSet } from '@salesforce/source-deploy-retrieve';
import { ComponentRetrieveResult, retrieve } from './metadataRegistryEntry.js';

export type SalesforceSetting = {
  [settingsKey: string]: unknown;
};

type ComponentList = ComponentRetrieveResult['retrievedComponents'];

/**
 * A generic loosely-typed retriever for settings metadata
 */
export default class GenericSettingsMetadata {
  private retrieveType;
  private readonly parser = new XMLParser();

  public constructor() {
    this.retrieveType = 'Settings';
  }

  /**
   * Retrieves a list of Salesforce settings by name. Returns a map of
   * the settings, organized by their name and a generic losely typed
   * content
   *
   * @param con
   * @param settingNames
   * @returns
   */
  public async resolve(con: Connection, settingNames: string[]): Promise<Record<string, SalesforceSetting>> {
    const cmpSet = new ComponentSet();
    if (settingNames.length === 0) {
      return {};
    }
    for (const settingName of settingNames) {
      cmpSet.add({ type: this.retrieveType, fullName: settingName });
    }
    const retrieveResult = await retrieve(cmpSet, con);
    const result = this.parseSettingsContent(retrieveResult.retrievedComponents, settingNames);
    return result;
  }

  private parseSettingsContent(settings: ComponentList, settingNames: string[]): Record<string, SalesforceSetting> {
    const result: Record<string, SalesforceSetting> = {};
    for (const setting of settings) {
      if (!settingNames.includes(setting.identifier)) {
        continue;
      }
      const settingsContent = this.extractContent(setting.fileContent, `${setting.identifier}Settings`);
      if (settingsContent) {
        result[setting.identifier] = settingsContent;
      }
    }
    return result;
  }

  private extractContent(content: string, rootNodeName: string): Record<string, unknown> | null | undefined {
    const parsedContent = this.parser.parse(content) as Record<string, unknown>;
    return parsedContent[rootNodeName] as Record<string, unknown>;
  }
}
