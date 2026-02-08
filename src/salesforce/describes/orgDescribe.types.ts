import { Record } from '@jsforce/jsforce-node';

export const CUSTOM_PERMS_QUERY = 'SELECT Id,MasterLabel,DeveloperName FROM CustomPermission';

export type Permission = {
  name: string;
  label?: string;
};

export type SfCustomPermission = Record & {
  Id: string;
  MasterLabel: string;
  DeveloperName: string;
};
