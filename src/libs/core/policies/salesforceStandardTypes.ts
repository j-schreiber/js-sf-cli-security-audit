import { Record } from '@jsforce/jsforce-node';

export type CustomPermission = Record & {
  Id: string;
  MasterLabel: string;
  DeveloperName: string;
};
