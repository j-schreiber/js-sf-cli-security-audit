import { EventEmitter } from 'node:events';
import { FileProperties } from '@jsforce/jsforce-node/lib/api/metadata.js';
import SfConnection from '../../connection.js';
import {
  CUSTOM_OBJECT_BASE_QUERY,
  formatEntityDefinitionQuery,
  ObjectDefinition,
  SfCustomObject,
  SfEntityDefinition,
} from './object-definitions.types.js';

export default class ObjectDefinitions extends EventEmitter<{ entityresolve: [{ total: number; resolved: number }] }> {
  public constructor(private readonly con: SfConnection) {
    super();
  }

  public async resolve(): Promise<Map<string, ObjectDefinition>> {
    this.emit('entityresolve', { total: 0, resolved: 0 });
    const results = new Map<string, ObjectDefinition>();
    const customObjects = await this.fetchCustomObjects();
    this.emit('entityresolve', { total: Object.keys(customObjects).length, resolved: 0 });
    const sharingRules = await this.fetchSharingRules();
    const objectNames = Array.from(
      new Set<string>([...Object.keys(customObjects), ...Object.keys(sharingRules)])
    ).sort();
    const entityDefs = await this.fetchEntityDefinitions(objectNames);
    const toolingCustomObjs = await this.fetchToolingCustomObjects();
    for (const objectName of objectNames) {
      results.set(
        objectName,
        buildObjectDefinition(
          objectName,
          Boolean(sharingRules[objectName]),
          toolingCustomObjs[entityDefs[objectName]?.DurableId],
          entityDefs[objectName],
          customObjects[objectName]
        )
      );
    }
    this.emit('entityresolve', {
      total: Object.keys(customObjects).length,
      resolved: Object.keys(customObjects).length,
    });
    return results;
  }

  private async fetchCustomObjects(): Promise<Record<string, FileProperties>> {
    const customObjects = await this.con.listMetadata('CustomObject');
    const r: Record<string, FileProperties> = {};
    for (const obj of customObjects) {
      r[obj.fullName] = obj;
    }
    return r;
  }

  private async fetchSharingRules(): Promise<Record<string, FileProperties>> {
    const sharingRules = await this.con.listMetadata('SharingRules');
    const r: Record<string, FileProperties> = {};
    for (const obj of sharingRules) {
      r[obj.fullName] = obj;
    }
    return r;
  }

  private async fetchEntityDefinitions(objectNames: string[]): Promise<Record<string, SfEntityDefinition>> {
    const queryResult = await this.con.query<SfEntityDefinition>(formatEntityDefinitionQuery(objectNames), true);
    const result: Record<string, SfEntityDefinition> = {};
    for (const entityDef of queryResult.records) {
      result[entityDef.QualifiedApiName] = entityDef;
    }
    return result;
  }

  private async fetchToolingCustomObjects(): Promise<Record<string, SfCustomObject>> {
    const queryResult = await this.con.query<SfCustomObject>(CUSTOM_OBJECT_BASE_QUERY, true);
    const result: Record<string, SfCustomObject> = {};
    for (const def of queryResult.records) {
      // Custom Objects return their Id with case-insensitive 18-char id, but the
      // "DurableId" that we use from entity definition is 15-char case-sensitive.
      // #make-it-make-sense
      result[def.Id.substring(0, 15)] = def;
    }
    return result;
  }
}

function evalObjectType(entityDef?: SfEntityDefinition): ObjectDefinition['type'] {
  if (entityDef) {
    return entityDef.IsCustomSetting
      ? 'CustomSetting'
      : entityDef.QualifiedApiName.endsWith('__mdt')
      ? 'CustomMetadata'
      : entityDef.QualifiedApiName.endsWith('__e')
      ? 'PlatformEvent'
      : entityDef.QualifiedApiName.endsWith('__kav')
      ? 'KnowledgeArticle'
      : 'SObject';
  } else {
    return 'Unknown';
  }
}

function buildObjectDefinition(
  developerName: string,
  isSharingControllable: boolean,
  toolingObj?: SfCustomObject,
  entityDef?: SfEntityDefinition,
  customObjectMetadata?: FileProperties
): ObjectDefinition {
  return {
    customObjectId: toolingObj?.Id,
    developerName,
    isSharingControllable,
    label: entityDef?.MasterLabel,
    externalSharing: entityDef?.ExternalSharingModel ?? 'Unknown',
    internalSharing: entityDef?.InternalSharingModel ?? 'Unknown',
    sharingModel: toolingObj?.SharingModel ?? 'Unknown',
    isCustom: Boolean(toolingObj),
    type: evalObjectType(entityDef),
    hasEntityDefinition: Boolean(entityDef),
    hasCustomObjectMetadata: Boolean(customObjectMetadata),
  };
}
