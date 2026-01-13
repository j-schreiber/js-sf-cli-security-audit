import z from 'zod';
import { Record } from '@jsforce/jsforce-node';
import { Profile as JsForceProfile } from '@jsforce/jsforce-node/lib/api/metadata.js';

export type Profile = {
  profileId: string;
  name: string;
  userType: string;
  metadata?: JsForceProfile;
};

export type PermissionSet = Record & {
  Id: string;
  IsOwnedByProfile: boolean;
  IsCustom: boolean;
  Name: string;
  Label: string;
  Profile: SfProfile;
  NamespacePrefix?: string;
};

type SfProfile = Record & {
  Id: string;
  Name: string;
  UserType: string;
};

export const ResolveProfilesOptionsSchema = z.object({
  /** Resolves profiles with metadata */
  withMetadata: z.boolean().default(false),
  /** Filters profiles by their name */
  filterNames: z.string().array().optional(),
});

export type ResolveProfilesOptions = z.infer<typeof ResolveProfilesOptionsSchema>;
