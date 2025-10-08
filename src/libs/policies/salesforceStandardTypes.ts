import { Record } from '@jsforce/jsforce-node';

export type CustomPermission = Record & {
  Id: string;
  MasterLabel: string;
  DeveloperName: string;
};

export type Profile = Record & {
  Id: string;
  Name: string;
  UserType: string;
};

export type PermissionSet = Record & {
  Id: string;
  IsOwnedByProfile: boolean;
  IsCustom: boolean;
  Name: string;
  Label: string;
  Profile: Profile;
};
