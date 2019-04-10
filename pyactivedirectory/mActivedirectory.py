from ldap3 import Server, Connection, SUBTREE, MODIFY_REPLACE, ALL_ATTRIBUTES
from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups
# import random, string #For generate password
# import sys
import logging
logger = logging.getLogger("AD")


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

    def enable_user_dn(self, dn):
        """Set status enable for user dn"""
        # userAccountControl : 66048 = 512 + 65536 is enabled default user
        # only activate
        change_UAC_attribute = {"userAccountControl": [MODIFY_REPLACE, 512]}
        return self.__conn.modify(dn=dn, changes=change_UAC_attribute)

    def get_dn_by_email(self, email, search_tree=None):
        """Get user dn by email"""
        search_filter = ('(&(mail=' + email + '))')
        cur_search_tree = self.__check_search_tree(search_tree)
        response = self.get_search(search_tree=cur_search_tree, search_filter=search_filter)
        try:
            return (response[0]['dn'])
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
        response = self.get_search(search_tree=cur_search_tree, search_filter=search_filter)
        try:
            return (response[0]['dn'])
        except(KeyError):
            logger.info('"{sAMAccountName}" not found'.format(
                        sAMAccountName=sAMAccountName))
            return None
        except(IndexError):
            self.__log('error')
            return None

    def get_group_by_name(self, group_name, search_tree):
        pass

    def get_ou(self, search_tree):
        """Return list OUs DN from search_tree"""
        response = self.get_search(search_tree=search_tree, search_filter='(&(!(objectClass=person))\
                    (!(distinguishedName=' + search_tree + '))(!(objectClass=group)))')
        return [i['dn'] for i in response]

    def get_search(self, search_tree, search_filter, attributes=[], types_only=False, get_operational_attributes=True):
        """Search interface for AD"""
        self.__conn.search(search_tree, search_filter, SUBTREE,
                           attributes=attributes,
                           types_only=types_only,
                           get_operational_attributes=True)
        return self.__conn.response

    def get_user_attribute(self, dn, attributes=None):
        """Return required attibutes. By default return all attributes"""
        if not attributes:
            attributes = ALL_ATTRIBUTES
        response = self.get_search(search_tree=dn, search_filter='(objectClass=*)', attributes=attributes)
        try:
            return response[0]['attributes']
        except KeyError:
            return None

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
