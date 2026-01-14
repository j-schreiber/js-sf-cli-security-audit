import { Record } from '@jsforce/jsforce-node';
import z from 'zod';

export type SfConnectedApp = Record & {
  Id: string;
  Name: string;
  OptionsAllowAdminApprovedUsersOnly: boolean;
};

export type SfOauthToken = Record & {
  Id: string;
  User: { Username: string };
  AppName: string;
  UseCount: number;
};

export type ConnectedApp = {
  name: string;
  origin: 'Installed' | 'OauthToken' | 'Owned';
  onlyAdminApprovedUsersAllowed: boolean;
  overrideByApiSecurityAccess: boolean;
  useCount: number;
  users: string[];
};

export const ResolveAppsOptionsSchema = z.object({
  withOAuthToken: z.boolean().default(false),
  withOrgOwned: z.boolean().default(false),
});

export type ResolveAppsOptions = z.infer<typeof ResolveAppsOptionsSchema>;
