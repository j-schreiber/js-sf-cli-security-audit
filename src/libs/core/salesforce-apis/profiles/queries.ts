export const PROFILES_QUERY =
  'SELECT Profile.Name,Profile.UserType,IsCustom FROM PermissionSet WHERE IsOwnedByProfile = TRUE';

export function buildProfilesQuery(profileNames?: string[]): string {
  return profileNames && profileNames.length > 0
    ? `${PROFILES_QUERY} AND Profile.Name IN (${profileNames.map((name) => `'${name}'`).join(',')})`
    : PROFILES_QUERY;
}
