import { Record } from '@jsforce/jsforce-node';
import { Profile as JsForceProfile } from '@jsforce/jsforce-node/lib/api/metadata.js';

export type CustomPermission = Record & {
  Id: string;
  MasterLabel: string;
  DeveloperName: string;
};

export type ConnectedApp = Record & {
  Id: string;
  Name: string;
  OptionsAllowAdminApprovedUsersOnly: boolean;
};

export type OauthToken = Record & {
  Id: string;
  User: Pick<User, 'Username'>;
  AppName: string;
  UseCount: number;
};

export type User = Record & {
  Username: string;
  Profile: ProfileBasic;
};

export type Profile = ProfileBasic & {
  Metadata: JsForceProfile;
};

type ProfileBasic = Record & {
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
  Profile: ProfileBasic;
  NamespacePrefix?: string;
};

export type PermissionSetAssignment = Record & {
  AssigneeId: string;
  PermissionSet: Pick<PermissionSet, 'Name'>;
};

export type UserLoginsAggregate = Record & {
  LoginType: string;
  Application: string;
  UserId: string;
  LoginCount: number;
  LastLogin: string;
};
