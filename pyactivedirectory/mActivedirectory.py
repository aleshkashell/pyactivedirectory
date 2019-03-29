from ldap3 import Server, Connection, SIMPLE, SYNC, ASYNC, SUBTREE, ALL, \
                    MODIFY_REPLACE, ALL_ATTRIBUTES
from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups
# import random, string #For generate password
import sys
import logging
logger = logging.getLogger("AD")


class activedirectory:
    __conn = ''

    def __init__(self, ad_user, ad_password, ad_server, use_ssl=True,
                 default_search_tree=''):
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
        logger.debug(self.__conn.result)

    def get_dn_by_username(self, username, search_tree):
        search_filter = ('(&(sAMAccountName=' + username + '))')
        if not search_tree:
            if not self.__default_search_tree:
                search_tree = self.__default_search_tree
                logger.debug(search_tree)
            else:
                logger.info('Empty search tree {}'.format(search_tree))
                return False
        response = self.get_search(search_tree=search_tree,
                                   search_filter=search_filter)
        try:
            return (response[0]['dn'])
        except(KeyError):
            logger.debug(self.__conn.result)
            return None
        except(IndexError):
            logger.debug(self.__conn.result)
            return None

    def get_search(self, search_tree, search_filter, attributes=[],
                   types_only=False, get_operational_attributes=True):
        self.__conn.search(search_tree, search_filter, SUBTREE,
                           attributes=attributes,
                           types_only=types_only,
                           get_operational_attributes=True)
        return self.__conn.response
