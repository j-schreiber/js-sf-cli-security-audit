const ENTITY_DEFINITION_BASE_QUERY =
  'SELECT DurableId,MasterLabel,QualifiedApiName,ExternalSharingModel,InternalSharingModel,KeyPrefix,IsRetrieveable,IsCustomizable FROM EntityDefinition';

export function formatEntityDefinitionQuery(objectNames: string[]): string {
  return `${ENTITY_DEFINITION_BASE_QUERY} WHERE QualifiedApiName IN (${formatObjectNames(objectNames)})`;
}

export const CUSTOM_OBJECT_BASE_QUERY = 'SELECT Id,DeveloperName,SharingModel FROM CustomObject';

export type SfEntityDefinition = {
  DurableId: string;
  QualifiedApiName: string;
  MasterLabel: string;
  ExternalSharingModel: GlobalSharingModelEnum;
  InternalSharingModel: GlobalSharingModelEnum;
  IsRetrieveable: boolean;
  IsCustomizeable: boolean;
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
