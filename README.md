# Active Directory Python Module

## Description

This module for interaction with AD. It is wrapper over ldap3 module.

## Interface

- Set status enable for user dn
```enable_user_dn(self, dn)```

- Get DN by sAMAccountName
```get_dn(self, sAMAccountName, search_tree=None)```

- Get user dn by email
```get_dn_by_email(self, email, search_tree=None)```

- pass
```get_group_by_name(self, group_name, search_tree)```

- Return list OUs DN from search_tree
```get_ou(self, search_tree)```

- Search interface for AD
```get_search(self, search_tree, search_filter, attributes=[], types_only=False, get_operational_attributes=True)```

- pass
```modify_password(self, dn, password)```

- Change attribute for dn. Attribute must be in dict
```modify_user_dn(self, dn, attributes)```

- Set up attribute change password on next login
```set_user_must_change_pass(self, dn)```
