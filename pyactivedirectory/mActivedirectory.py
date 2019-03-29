from ldap3 import Server, Connection, SIMPLE, SYNC, ASYNC, SUBTREE, ALL, \
                    MODIFY_REPLACE, ALL_ATTRIBUTES
from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups
# import random, string #For generate password
import sys
import logging
logger = logging.getLogger("AD")


class activedirectory:
    __conn = ''

    def __init__(self, ad_user, ad_password, ad_server, default_search_tree,
                 use_ssl=True):
        self.__default_search_tree = default_search_tree
        self.__connect_to_ad(ad_user, ad_password, ad_server, use_ssl)

    def __connect_to_ad(self, ad_user, ad_password, ad_server, use_ssl):
        """"""
        server = Server(ad_server, use_ssl=use_ssl)
        self.__conn = Connection(server, user=ad_user, password=ad_password)
        if not self.__conn.bind():
            logger.info("Could not connect to server")
        else:
            logger.debug('Connection success')
        self.__log('debug')

    def get_dn_by_email(self, email, search_tree=None):
        search_filter = ('(&(mail=' + email + '))')
        cur_search_tree = self.check_search_tree(search_tree)
        response = self.get_search(search_tree=cur_search_tree,
                                   search_filter=search_filter)
        try:
            return (response[0]['dn'])
        except(KeyError):
            logger.info('"{email}" not found'.format(email=email))
            return None
        except(IndexError):
            self.__log('error')
            return None

    def get_dn(self, sAMAccountName, search_tree=None):
        search_filter = ('(&(sAMAccountName=' + sAMAccountName + '))')
        cur_search_tree = self.check_search_tree(search_tree)
        response = self.get_search(search_tree=cur_search_tree,
                                   search_filter=search_filter)
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

    def get_search(self, search_tree, search_filter, attributes=[],
                   types_only=False, get_operational_attributes=True):
        self.__conn.search(search_tree, search_filter, SUBTREE,
                           attributes=attributes,
                           types_only=types_only,
                           get_operational_attributes=True)
        return self.__conn.response

    def __log(self, type):
        if type == 'error':
            logger.error('Description: {description}, \
                        message: {message}\t'.format(
                        description=self.__conn.result['description'],
                        message=self.__conn.result['message']))
        if type == 'info':
            logger.info('Description: {description}, \
                        message: {message}\t'.format(
                        description=self.__conn.result['description'],
                        message=self.__conn.result['message']))
        if type == 'debug':
            logger.debug('Description: {description}, \
                        message: {message}\t'.format(
                        description=self.__conn.result['description'],
                        message=self.__conn.result['message']))
        if type == 'warning':
            logger.warning('Description: {description}, \
                        message: {message}\t'.format(
                        description=self.__conn.result['description'],
                        message=self.__conn.result['message']))

    def check_search_tree(self, search_tree):
        if search_tree is None or search_tree == '':
            new_search_tree = self.__default_search_tree
        else:
            new_search_tree = search_tree
        logger.debug('Search_tree: {}'.format(new_search_tree))
        return new_search_tree
