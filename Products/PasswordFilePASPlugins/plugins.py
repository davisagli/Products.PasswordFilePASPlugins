import csv
from AccessControl import ClassSecurityInfo, AuthEncoding
from App.class_init import default__class_init__ as InitializeClass
from OFS.Cache import Cacheable

from Products.PageTemplates.PageTemplateFile import PageTemplateFile

from Products.PluggableAuthService.interfaces.plugins \
    import IAuthenticationPlugin
from Products.PluggableAuthService.interfaces.plugins \
    import IRolesPlugin
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements


manage_addPasswordFileUserRoleManagerForm = PageTemplateFile(
    'www/add', globals(), __name__='manage_addPasswordFileUserRoleManagerForm' )


def addPasswordFileUserRoleManager( dispatcher, id, fname, title=None, REQUEST=None ):
    """ Add a PasswordFileUserRoleManager to a Pluggable Auth Service. """

    um = PasswordFileUserRoleManager(id, fname, title)
    dispatcher._setObject(um.getId(), um)

    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect(
                                '%s/manage_workspace'
                                '?manage_tabs_message='
                                'PasswordFileUserRoleManager+added.'
                            % dispatcher.absolute_url())


class PasswordFileUserRoleManager( BasePlugin, Cacheable ):

    """ PAS plugin for managing users in a password file.
    """

    meta_type = 'Password File User & Role Manager'

    security = ClassSecurityInfo()

    def __init__(self, id, fname, title=None):

        self._id = self.id = id
        self.fname = fname
        self.title = title

    def _userdata(self):
        userdata = getattr(self, '_v_userdata', None)
        if userdata is None:
            userdata = {}
            for row in csv.DictReader(open(self.fname, 'r'), fieldnames=('login', 'password', 'roles'), delimiter=':'):
                userdata[row['login']] = row
        self._v_userdata = userdata
        return userdata

    #
    #   IAuthenticationPlugin implementation
    #
    security.declarePrivate( 'authenticateCredentials' )
    def authenticateCredentials( self, credentials ):

        """ See IAuthenticationPlugin.

        o We expect the credentials to be those returned by
          ILoginPasswordExtractionPlugin.
        """
        login = credentials.get( 'login' )
        password = credentials.get( 'password' )

        if login is None or password is None:
            return None

        userdata = self._userdata()
        reference = userdata[login]['password']

        if not reference:
            return None

        if AuthEncoding.pw_validate( reference, password ):
            return login, login

        return None

    #
    #   IRolesPlugin implementation
    #
    security.declarePrivate( 'getRolesForPrincipal' )
    def getRolesForPrincipal( self, principal, request=None ):
        """ See IRolesPlugin.
        """
        userdata = self._userdata()
        result = tuple(userdata[principal.getId()]['roles'].split(','))
        return result


classImplements( PasswordFileUserRoleManager
               , IAuthenticationPlugin
               , IRolesPlugin
               )

InitializeClass( PasswordFileUserRoleManager )
