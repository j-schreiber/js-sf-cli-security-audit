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
  LastUsedDate?: string;
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
  users: ConnectedAppUser[];
};

export const ResolveAppsOptionsSchema = z.object({
  withTokenUsage: z.boolean().default(false),
  withOrgOwned: z.boolean().default(false),
});

export type ResolveAppsOptions = z.infer<typeof ResolveAppsOptionsSchema>;

export type ConnectedAppUser = {
  username: string;

  /** Aggregated usage of all tokens from this user */
  useCount: number;

  tokenCount: number;

  /** ISO Code timestamp of last use date from tokens of this user */
  lastUsed?: string;
};

export type OAuthUsageStats = {
  /** ISO Code timestamp of last use date from all tokens for this app */
  lastUsed?: string;

  appId?: string;

  /** Aggregated usage of all tokens from this app */
  useCount: number;

  users: Map<string, ConnectedAppUser>;
};
