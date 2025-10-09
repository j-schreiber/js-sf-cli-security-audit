import path from 'node:path';

export const CLASSIFICATION_SUBDIR = 'classification';
export const POLICIES_SUBDIR = 'policies';
export const USER_PERMISSIONS_PATH = path.join(CLASSIFICATION_SUBDIR, 'userPermissions.yml');
export const CUSTOM_PERMISSIONS_PATH = path.join(CLASSIFICATION_SUBDIR, 'customPermissions.yml');
export const PROFILE_POLICY_PATH = path.join(POLICIES_SUBDIR, 'profiles.yml');
export const PERMSET_POLICY_PATH = path.join(POLICIES_SUBDIR, 'permissionSets.yml');
