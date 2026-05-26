import { DescribeSObjectResult, Record as SfRecord } from '@jsforce/jsforce-node';

export const CUSTOM_PERMS_QUERY = 'SELECT Id,MasterLabel,DeveloperName FROM CustomPermission';

export type Permission = {
  name: string;
  label?: string;
};

export type SfCustomPermission = SfRecord & {
  Id: string;
  MasterLabel: string;
  DeveloperName: string;
};

export type SObjectsDescribeResult = {
  /**
   * Sanitised list of valid sobject names
   */
  successes: string[];
  /**
   * Map of lowercase sobject names and corresponding
   * describe results.
   */
  describes: Record<string, DescribeSObjectResult>;
  /**
   * List of sobject names that do not exist on the target
   * org with a reason of failure.
   */
  errors: Array<{ name: string; reason: string }>;
};
