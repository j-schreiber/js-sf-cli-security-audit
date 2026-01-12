export const PROFILES_QUERY =
  'SELECT Profile.Name,Profile.UserType,IsCustom FROM PermissionSet WHERE IsOwnedByProfile = TRUE';
