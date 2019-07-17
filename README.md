# Active Directory Python Module

## Description

This module for interaction with AD. It is wrapper over ldap3 module.

## Example usage

```
from pyactivedirectory import ActiveDirectory
ad = ActiveDirectory(ad_user='username', ad_password='password',
                         ad_server="server", default_search_tree='dc=google,dc=com')
```

## Interface

- Add object(who) to group(where)
```add_to_group(self, who, where)```

- Create entity in ad
```create_entity(self, dn, object_class, attributes, controls=None)```

- Create group
```create_group(self, name, path, is_secure_group=False, attributes=None)```

- Create disabled user without password
```create_user(self, login, path, attributes=None)```

- Create enabled user with password
```create_user_with_password(self, login, password, path, attributes=None)```

- Set status enable for user dn
```enable_user_dn(self, dn)```

- Generate password 15 symbols
```generate_password(self)```

- Get all members of group
```get_all_members_of_group(self, group_dn, search_tree=None)```

- Get DN by sAMAccountName
```get_dn(self, sAMAccountName, search_tree=None)```

- Get user dn by email
```get_dn_by_email(self, email, search_tree=None)```

- Get group members of group
```get_group_members_of_group(self, group_dn, search_tree=None)```

- Return last message from ldap3.connection
```get_last_message(self)```

- Return list OUs DN from search_tree
```get_ou(self, search_tree)```

- Search interface for AD
```get_search(self, search_tree, search_filter, attributes=[], types_only=False, get_operational_attributes=True)```

- Return required attibutes. By default return all attributes
```get_user_attribute(self, dn, attributes=None)```

- Get user members of group
```get_user_members_of_group(self, group_dn, search_tree=None)```

- Change common name
```modify_cn(self, dn, new_cn)```

- Set new password
```modify_password(self, dn, password)```

- Change attribute for dn. Attribute must be in dict
```modify_user_dn(self, dn, attributes)```

- Set up attribute change password on next login
```set_user_must_change_pass(self, dn)```
