import { Record } from '@jsforce/jsforce-node';
import z from 'zod';

type ExtlClntAppDistState = 'Local' | 'Packaged';
type ExtlClntAppOauthPermittedUsers = 'AllSelfAuthorized' | 'AdminApprovedPreAuthorized';

export type SfConnectedApp = Record & {
  Id: string;
  Name: string;
  OptionsAllowAdminApprovedUsersOnly: boolean;
};

export type SfExternalClientApp = Record & {
  Id: string;
  MasterLabel: string;
  DeveloperName: string;
  DistributionState: ExtlClntAppDistState;
};

export type SfExternalAppOauthPolicy = Record & {
  ExternalClientApplicationId: string;
  PermittedUsersPolicyType: ExtlClntAppOauthPermittedUsers;
};

export type SfOauthToken = Record & {
  Id: string;
  User: { Username: string };
  AppName: string;
  AppMenuItem?: {
    ApplicationId: string;
  };
  UseCount: number;
};

export type SfMinimalUser = Record & {
  Id: string;
};

export type ConnectedApp = {
  id?: string;
  name: string;
  origin: 'Installed' | 'OauthToken' | 'Owned';
  type: 'ConnectedApp' | 'ExternalClientApp' | 'Unknown';
  onlyAdminApprovedUsersAllowed: boolean;
  overrideByApiSecurityAccess: boolean;
  useCount: number;
  users: string[];
};

export const ResolveAppsOptionsSchema = z.object({
  withTokenUsage: z.boolean().default(false),
  withOrgOwned: z.boolean().default(false),
});

export type ResolveAppsOptions = z.infer<typeof ResolveAppsOptionsSchema>;
