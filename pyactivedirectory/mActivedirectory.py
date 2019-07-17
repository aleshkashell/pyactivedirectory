from ldap3 import Server, Connection, SUBTREE, MODIFY_REPLACE, ALL_ATTRIBUTES
from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups
import random  # For generate password
import string  # For generate password
import json
# import sys
import logging
logger = logging.getLogger("AD")


def _entry_to_json(entry):
    return json.loads(entry.entry_to_json())


class ActiveDirectory:
    __conn = ''

    def __init__(self, ad_user, ad_password, ad_server, default_search_tree, use_ssl=True):
        self.__default_search_tree = default_search_tree
        self.__connect_to_ad(ad_user, ad_password, ad_server, use_ssl)

    def __connect_to_ad(self, ad_user, ad_password, ad_server, use_ssl):
        server = Server(ad_server, use_ssl=use_ssl)
        self.__conn = Connection(server, user=ad_user, password=ad_password)
        if not self.__conn.bind():
            logger.info("Could not connect to server")
        else:
            logger.debug('Connection success')
        self.__log('debug')

    def add_to_group(self, who, where):
        """Add object(who) to group(where)"""
        return ad_add_members_to_groups(self.__conn, who, where)

    def create_entity(self, dn, object_class, attributes, controls=None):
        """Create entity in ad"""
        return self.__conn.add(dn=dn, object_class=object_class, attributes=attributes, controls=controls)

    def create_group(self, name, path, is_secure_group=False, attributes=None):
        """Create group"""
        if is_secure_group:
            group_type = '-2147483646'
        else:
            group_type = '2'
        def_attributes = {'sAMAccountName': name, 'groupType': group_type}
        local_attrib = {}
        if attributes:
            local_attrib.update(attributes)
        local_attrib.update(def_attributes)
        dn = 'CN=' + name + ',' + path
        if self.create_entity(dn=dn, object_class='group', attributes=local_attrib):
            return dn
        else:
            return None

    def create_user(self, login, path, attributes=None):
        """Create disabled user without password"""
        localAttrib = {}
        defAttributes = {'objectClass': 'user', 'sAMAccountName': login}
        if attributes:
            localAttrib.update(attributes)
        localAttrib.update(defAttributes)
        user_dn = 'CN=' + login + ',' + path
        if self.create_entity(dn=user_dn, object_class='user', attributes=localAttrib):
            return user_dn
        else:
            return None

    def create_user_with_password(self, login, password, path, attributes=None):
        """Create enabled user with password"""
        localAttrib = {}
        defAttributes = {'objectClass': 'user', 'sAMAccountName': login}
        if attributes:
            localAttrib.update(attributes)
        localAttrib.update(defAttributes)
        user_dn = 'CN=' + login + ',' + path
        if self.create_entity(dn=user_dn, object_class='user', attributes=localAttrib):
            if not self.modify_password(dn=user_dn, password=password):
                self.__log("debug")
            if not self.enable_user_dn(user_dn):
                self.__log("debug")
            return user_dn
        else:
            self.__log("error")
            return None

    def enable_user_dn(self, dn):
        """Set status enable for user dn"""
        # userAccountControl : 66048 = 512 + 65536 is enabled default user
        # 512 NORMAL_ACCOUNT
        # 65536 PASSWORD_NEVER_EXPIRED
        # only activate
        change_UAC_attribute = {"userAccountControl": [MODIFY_REPLACE, 512]}
        return self.__conn.modify(dn=dn, changes=change_UAC_attribute)

    def generate_password(self):
        """Generate password 15 symbols"""
        random.randint(6, 20) - 3
        pwd = []
        for i in range(1, 15):
            gen = random.randint(0, 2)
            if gen == 0:
                pwd.append(random.choice(string.ascii_lowercase))
            if gen == 1:
                pwd.append(random.choice(string.ascii_uppercase))
            if gen == 2:
                pwd.append(str(random.randint(0, 9)))
        # fill out the rest of the characters
        # using whatever algorithm you want
        # for the next "length" characters
        random.shuffle(pwd)
        return ''.join(pwd)

    def get_dn_by_email(self, email, search_tree=None):
        """Get user dn by email"""
        search_filter = ('(&(mail=' + email + '))')
        cur_search_tree = self.__check_search_tree(search_tree)
        entries = self.get_search(search_tree=cur_search_tree, search_filter=search_filter)
        logger.debug(entries)
        try:
            return (_entry_to_json(entries[0])['dn'])
        except(KeyError):
            logger.info('"{email}" not found'.format(email=email))
            return None
        except(IndexError):
            self.__log('error')
            return None

    def get_dn(self, sAMAccountName, search_tree=None):
        """Get DN by sAMAccountName"""
        search_filter = ('(&(sAMAccountName=' + sAMAccountName + '))')
        cur_search_tree = self.__check_search_tree(search_tree)
        entries = self.get_search(search_tree=cur_search_tree, search_filter=search_filter)
        try:
            return (_entry_to_json(entries[0])['dn'])
        except(KeyError):
            logger.info('"{sAMAccountName}" not found'.format(
                        sAMAccountName=sAMAccountName))
            return None
        except(IndexError):
            self.__log('error')
            return None

    def get_ou(self, search_tree):
        """Return list OUs DN from search_tree"""
        response = self.get_search(search_tree=search_tree, search_filter='(&(!(objectClass=person))\
                    (!(distinguishedName=' + search_tree + '))(!(objectClass=group)))')
        return [i['dn'] for i in response]

    def get_last_message(self):
        """Return last message from ldap3.connection"""
        return self.__conn.result

    def get_all_members_of_group(self, group_dn, search_tree=None):
        """Get all members of group"""
        cur_search_tree = self.__check_search_tree(search_tree)
        search_filter = ('(&(objectClass=*)(memberOf={group_dn}))'.format(group_dn=group_dn))
        self.__conn.search(cur_search_tree, search_filter, SUBTREE)
        return [i['dn'] for i in self.__conn.response if i['type'] != 'searchResRef']

    def get_group_members_of_group(self, group_dn, search_tree=None):
        """Get group members of group"""
        cur_search_tree = self.__check_search_tree(search_tree)
        search_filter = ('(&(objectClass=group)(memberOf={group_dn}))'.format(group_dn=group_dn))
        self.__conn.search(cur_search_tree, search_filter, SUBTREE)
        return [i['dn'] for i in self.__conn.response if i['type'] != 'searchResRef']

    def get_search(self, search_tree, search_filter, attributes=[], types_only=False, get_operational_attributes=True):
        """Search interface for AD"""
        cur_search_tree = self.__check_search_tree(search_tree)
        self.__conn.search(cur_search_tree, search_filter, SUBTREE,
                           attributes=attributes,
                           types_only=types_only,
                           get_operational_attributes=True)
        return self.__conn.entries

    def get_user_attribute(self, dn, attributes=None):
        """Return required attibutes. By default return all attributes"""
        if not attributes:
            attributes = ALL_ATTRIBUTES
        response = self.get_search(search_tree=dn, search_filter='(objectClass=*)', attributes=attributes)
        try:
            return response[0]['attributes']
        except KeyError:
            return None

    def get_user_members_of_group(self, group_dn, search_tree=None):
        """Get user members of group"""
        cur_search_tree = self.__check_search_tree(search_tree)
        search_filter = ('(&(objectClass=person)(memberOf={group_dn}))'.format(group_dn=group_dn))
        self.__conn.search(cur_search_tree, search_filter, SUBTREE)
        return [i['dn'] for i in self.__conn.response if i['type'] != 'searchResRef']

    def get_users_json(self, search_tree=None):
        """Get users from search tree"""
        cur_search_tree = self.__check_search_tree(search_tree)
        search_filter = ('(&(cn=*)(objectClass=user))')
        self.__conn.search(cur_search_tree, search_filter, SUBTREE, attributes=ALL_ATTRIBUTES)
        data = [_entry_to_json(i) for i in self.__conn.entries]
        return data


    def modify_cn(self, dn, new_cn):
        """Change common name"""
        return self.__conn.modify_dn(dn, 'cn=' + new_cn)

    def modify_password(self, dn, password):
        """Set new password"""
        return self.__conn.extend.microsoft.modify_password(user=dn, new_password=password)

    def modify_user_dn(self, dn, attributes):
        """Change attribute for dn. Attribute must be in dict"""
        result = self.__conn.modify(dn=dn, changes=self.__prepare_attributes(attributes))
        self.__log('debug')
        return result

    def set_user_must_change_pass(self, dn):
        """Set up attribute change password on next login"""
        # // use 0 instead of -1.
        password_expire = {"pwdLastSet": (MODIFY_REPLACE, [0])}
        self.__conn.modify(dn=dn, changes=password_expire)

    def __log(self, type):
        if type == 'error':
            logger.error('Description: {description}, message: {message}\t'.format(
                        description=self.__conn.result['description'], message=self.__conn.result['message']))
        if type == 'info':
            logger.info('Description: {description}, message: {message}\t'.format(
                        description=self.__conn.result['description'], message=self.__conn.result['message']))
        if type == 'debug':
            logger.debug('Description: {description}, message: {message}\t'.format(
                        description=self.__conn.result['description'], message=self.__conn.result['message']))
        if type == 'warning':
            logger.warning('Description: {description}, message: {message}\t'.format(
                        description=self.__conn.result['description'], message=self.__conn.result['message']))

    def __check_search_tree(self, search_tree):
        if search_tree is None or search_tree == '':
            new_search_tree = self.__default_search_tree
        else:
            new_search_tree = search_tree
        logger.debug('Search_tree: {}'.format(new_search_tree))
        return new_search_tree

    def __prepare_attributes(self, attributes):
        attrib = {}
        for key in attributes.keys():
            attrib[key] = [(MODIFY_REPLACE, [attributes[key]])]
        return attrib
