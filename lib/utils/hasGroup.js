/**
 * Check if the given OIDC user is in the given group.
 */
function hasGroup(groupStr, oidcUser) {
  const groups = oidcUser.memberOf;

  if (typeof groups === "string") {
    groups = [groups];
  }

  if (groups && groups.length > 0) {
    for (let i = 0; i < groups.length; i++) {
      if (groupStr && groupStr === _getGroupName(groups[i])) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Gets the group name from the given AD_LDAP CN string.
 */
function _getGroupName(CNLdapGroupString) {
  const regex1 = /^CN=/i;
  const regex2 = /,.*/i;
  return CNLdapGroupString.replace(regex1, "").replace(regex2, "");
}

module.exports = hasGroup;
