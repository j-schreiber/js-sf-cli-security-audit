export const CUSTOM_PERMS_QUERY = 'SELECT Id,MasterLabel,DeveloperName FROM CustomPermission';
export const PROFILES_QUERY =
  'SELECT Profile.Name,Profile.UserType,IsCustom FROM PermissionSet WHERE IsOwnedByProfile = TRUE';
export const PERMISSION_SETS_QUERY = 'SELECT Name,Label,IsCustom FROM PermissionSet WHERE IsOwnedByProfile = FALSE';
