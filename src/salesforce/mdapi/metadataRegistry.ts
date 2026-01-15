import { XMLParser } from 'fast-xml-parser';
import {
  ConnectedAppSettings,
  PermissionSet,
  Profile as ProfileMetadata,
} from '@jsforce/jsforce-node/lib/api/metadata.js';
import NamedMetadata from './namedMetadataType.js';
import SingletonMetadata from './singletonMetadataType.js';
import NamedMetadataQueryable from './namedMetadataToolingQueryable.js';
import GenericSettingsMetadata from './genericSettingsMetadata.js';

const NamedTypesRegistry = {
  PermissionSet: new NamedMetadata<PermissionSetXml, 'PermissionSet'>({
    retrieveType: 'PermissionSet',
    rootNodeName: 'PermissionSet',
    parser: new XMLParser({
      isArray: (jpath): boolean =>
        ['userPermissions', 'fieldPermissions', 'customPermissions', 'classAccesses'].includes(jpath),
    }),
    parsePostProcessor: (parseResult): PermissionSet => ({
      ...parseResult,
      userPermissions: parseResult.userPermissions ?? [],
      customPermissions: parseResult.customPermissions ?? [],
      classAccesses: parseResult.classAccesses ?? [],
    }),
  }),
  Profile: new NamedMetadataQueryable<ProfileXml, 'Profile'>({
    objectName: 'Profile',
    nameField: 'Name',
    parsePostProcessor: (parseResult): ProfileMetadata => ({
      ...parseResult,
      userPermissions: parseResult.userPermissions ?? [],
      customPermissions: parseResult.customPermissions ?? [],
      classAccesses: parseResult.classAccesses ?? [],
    }),
  }),
  Settings: new GenericSettingsMetadata(),
};

const SingletonRegistry = {
  ConnectedAppSettings: new SingletonMetadata<ConnectedAppSettingsXml, 'ConnectedAppSettings'>({
    rootNodeName: 'ConnectedAppSettings',
    retrieveName: 'ConnectedApp',
    retrieveType: 'Settings',
  }),
};

type ProfileXml = {
  Profile: ProfileMetadata;
};

type PermissionSetXml = {
  PermissionSet: PermissionSet;
};

type ConnectedAppSettingsXml = {
  ConnectedAppSettings: ConnectedAppSettings;
};

export type MdapiRegistry = typeof Registry;

export const Registry = {
  namedTypes: NamedTypesRegistry,
  singletonTypes: SingletonRegistry,
};
