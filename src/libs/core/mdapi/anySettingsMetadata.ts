import { readFileSync } from 'node:fs';
import { Connection } from '@salesforce/core';
import { ComponentSet, SourceComponent } from '@salesforce/source-deploy-retrieve';
import { XMLParser } from 'fast-xml-parser';
import { cleanRetrieveDir, retrieve } from './metadataRegistryEntry.js';

type SalesforceSettings = {
  [settingsKey: string]: unknown;
};

/**
 * A generic loosely-typed retriever for settings metadata
 */
export default class AnySettingsMetadata {
  private parser;
  private retrieveType;

  public constructor() {
    this.parser = new XMLParser();
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
  public async resolve(con: Connection, settingNames: string[]): Promise<Map<string, SalesforceSettings>> {
    const cmpSet = new ComponentSet();
    for (const settingName of settingNames) {
      cmpSet.add({ type: this.retrieveType, fullName: settingName });
    }
    const retrieveResult = await retrieve(cmpSet, con);
    const result = this.parseSettingsContent(settingNames, retrieveResult.components);
    cleanRetrieveDir(retrieveResult.getFileResponses());
    return result;
  }

  private parseSettingsContent(settingNames: string[], components: ComponentSet): Map<string, SalesforceSettings> {
    const result = new Map<string, SalesforceSettings>();
    for (const settingName of settingNames) {
      const cmps = components.getSourceComponents({ type: this.retrieveType, fullName: settingName }).toArray();
      const settingsContent = this.parseSourceFile(cmps, `${settingName}Settings`);
      if (settingsContent) {
        result.set(settingName, settingsContent);
      }
    }
    return result;
  }

  private parseSourceFile(cmps: SourceComponent[], rootNodeName: string): Record<string, unknown> | null {
    if (cmps.length > 0 && cmps[0].xml) {
      const fileContent = readFileSync(cmps[0].xml, 'utf-8');
      const rawFileContent = this.parser.parse(fileContent) as Record<string, unknown>;
      return rawFileContent[rootNodeName] as Record<string, unknown>;
    }
    return null;
  }
}
