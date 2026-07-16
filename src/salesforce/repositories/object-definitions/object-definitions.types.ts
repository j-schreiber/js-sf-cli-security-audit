const ENTITY_DEFINITION_BASE_QUERY =
  'SELECT DurableId,MasterLabel,QualifiedApiName,ExternalSharingModel,InternalSharingModel,KeyPrefix,IsRetrieveable,IsCustomizable,IsCustomSetting FROM EntityDefinition';

export function formatEntityDefinitionQuery(objectNames: string[]): string {
  return `${ENTITY_DEFINITION_BASE_QUERY} WHERE QualifiedApiName IN (${formatObjectNames(objectNames)})`;
}

export const CUSTOM_OBJECT_BASE_QUERY = 'SELECT Id,DeveloperName,SharingModel FROM CustomObject';

export type ObjectDefinition = {
  /**
   * Qualified API name of the object, with type suffix (__c, __e, etc)
   */
  developerName: string;
  /**
   * Indicates if the object has a sharing rules table.
   */
  isSharingControllable: boolean;
  /**
   * If its a custom object, the Id in CustomObject table
   */
  customObjectId?: string;
  label: string | undefined;
  externalSharing: GlobalSharingModelEnum;
  internalSharing: GlobalSharingModelEnum;
  /**
   * Set by query on CustomObject (SfCustomObject.SharingModel). The value
   * indicates if the object can have individual sharing, or if it inherits
   * the visibility from its parent.
   */
  sharingModel: CustomObjSharingModelEnum;
  /**
   * Derived type of the object.
   */
  type: 'SObject' | 'CustomSetting' | 'CustomMetadata' | 'PlatformEvent' | 'KnowledgeArticle' | 'Unknown';
  /**
   * Indicates if this is a custom object (i.e. entry in CustomObjects table)
   */
  isCustom: boolean;
  /**
   * Indicates, if the object exists in the EntityDefinition table
   */
  hasEntityDefinition: boolean;
  /**
   * Indicates, if the object exists as a CustomObject metadata (this
   * type has all regular sobjects, not only custom objects).
   */
  hasObjectMetadata: boolean;
};

export type SfEntityDefinition = {
  DurableId: string;
  QualifiedApiName: string;
  MasterLabel: string;
  ExternalSharingModel: GlobalSharingModelEnum;
  InternalSharingModel: GlobalSharingModelEnum;
  IsRetrieveable: boolean;
  IsCustomizeable: boolean;
  IsCustomSetting: boolean;
  KeyPrefix: string;
};

export type SfCustomObject = {
  Id: string;
  DeveloperName: string;
  SharingModel: CustomObjSharingModelEnum;
};

export type GlobalSharingModelEnum =
  | 'Private'
  | 'ControlledByParent'
  | 'ReadWrite'
  | 'Read'
  | 'ReadWriteTransfer'
  | 'ControlledByCampaign'
  | 'ReadSelect'
  | 'FullAccess'
  | 'Unknown';

export type CustomObjSharingModelEnum = 'Unknown' | 'Edit' | 'Read' | 'ControlledByParent' | 'None';

function formatObjectNames(objectNames: string[]): string {
  return `${objectNames.map((objName) => `'${objName}'`).join(',')}`;
}
