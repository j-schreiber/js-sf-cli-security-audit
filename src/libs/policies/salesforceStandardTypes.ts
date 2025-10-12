import { Record } from '@jsforce/jsforce-node';
import { Profile as JsForceProfile } from '@jsforce/jsforce-node/lib/api/metadata.js';

export type CustomPermission = Record & {
  Id: string;
  MasterLabel: string;
  DeveloperName: string;
};

export type Profile = Record & {
  Id: string;
  Name: string;
  UserType: string;
  Metadata: JsForceProfile;
};

export type PermissionSet = Record & {
  Id: string;
  IsOwnedByProfile: boolean;
  IsCustom: boolean;
  Name: string;
  Label: string;
  Profile: Omit<Profile, 'Metadata'>;
};
