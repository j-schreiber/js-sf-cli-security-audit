import { Record } from '@jsforce/jsforce-node';
import { PermissionSet as JsForcePermSet } from '@jsforce/jsforce-node/lib/api/metadata.js';
import z from 'zod';

export type PermissionSet = {
  name: string;
  isCustom: boolean;
  metadata?: JsForcePermSet;
};

type SfParentProfile = Record & {
  Id: string;
  Name: string;
  UserType: string;
};

export type SfPermissionSet = Record & {
  Id: string;
  IsOwnedByProfile: boolean;
  IsCustom: boolean;
  Name: string;
  Label: string;
  Profile: SfParentProfile;
  NamespacePrefix?: string;
};

export const ResolvePermSetOptionsSchema = z.object({
  /** Resolves permission sets with metadata */
  withMetadata: z.boolean().default(false),
  /** Filters permission sets by their name */
  filterNames: z.string().array().optional(),
  /** Only includes custom permission sets */
  isCustomOnly: z.boolean().default(false),
});

export type ResolvePermSetOptions = z.infer<typeof ResolvePermSetOptionsSchema>;
