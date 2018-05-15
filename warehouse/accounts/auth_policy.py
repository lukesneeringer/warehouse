# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from pymacaroons import Macaroon, Verifier
from pymacaroons.exceptions import MacaroonException

from pyramid.authentication import (
    BasicAuthAuthenticationPolicy as _BasicAuthAuthenticationPolicy,
    CallbackAuthenticationPolicy as _CallbackAuthenticationPolicy,
    SessionAuthenticationPolicy as _SessionAuthenticationPolicy,
)

from sqlalchemy.orm.exc import NoResultFound

import warehouse.accounts
from warehouse.accounts.interfaces import IUserService
from warehouse.accounts.models import Token
from warehouse.cache.http import add_vary_callback


class ApiTokenAuthenticationPolicy(_CallbackAuthenticationPolicy):

    def __init__(self, authenticate):
        self._authenticate = authenticate
        self.callback = self._api_token_auth_callback

    def unauthenticated_userid(self, request):
        api_token = request.params.get('api_token')

        if api_token is None:
            return None

        try:
            macaroon = Macaroon.deserialize(api_token)

            # First, check identifier and location
            if macaroon.identifier != request.registry.settings['token_api.id']:
                return None

            if macaroon.location != 'pypi.org':
                return None

            # Check the macaroon against our configuration
            verifier = Verifier()
            verifier.satisfy_general(self._validate_first_party_caveat)

            verified = verifier.verify(
                macaroon, request.registry.settings['token_api.secret'],
            )

            if verified:
                # Get id from token
                token_id = None

                for each in macaroon.first_party_caveats():
                    caveat = each.to_dict()
                    caveat_parts = caveat['cid'].split(': ')
                    caveat_key = caveat_parts[0]
                    caveat_value = ': '.join(caveat_parts[1:])

                    if caveat_key == 'id':
                        token_id = caveat_value
                        break

                if token_id is not None:
                    # Look up user from token_id
                    token = request.db.query(Token).filter(
                        Token.id == token_id,
                        ).one()

                    username = token.username
                    login_service = request.find_service(
                        IUserService, context=None,
                    )

                    return login_service.find_userid(username)

        except (MacaroonException, NoResultFound) as e:
            return None

    def remember(self, request, userid, **kw):
        """A no-op. Let other authenticators handle this."""
        return []

    def forget(self, request):
        """ A no-op. Let other authenticators handle this."""
        return []


    def _validate_first_party_caveat(self, caveat):
        # Only support 'id' caveat for now
        if caveat.split(': ')[0] not in ['id']:
            return False

        return True

    def _api_token_auth_callback(self, userid, request):
        return self._authenticate(userid, request)


class BasicAuthAuthenticationPolicy(_BasicAuthAuthenticationPolicy):

    def unauthenticated_userid(self, request):
        # If we're calling into this API on a request, then we want to register
        # a callback which will ensure that the response varies based on the
        # Authorization header.
        request.add_response_callback(add_vary_callback("Authorization"))

        # Dispatch to the real basic authentication policy
        username = super().unauthenticated_userid(request)

        # Assuming we got a username from the basic authentication policy, we
        # want to locate the userid from the IUserService.
        if username is not None:
            login_service = request.find_service(IUserService, context=None)
            return str(login_service.find_userid(username))


class SessionAuthenticationPolicy(_SessionAuthenticationPolicy):

    def unauthenticated_userid(self, request):
        # If we're calling into this API on a request, then we want to register
        # a callback which will ensure that the response varies based on the
        # Cookie header.
        request.add_response_callback(add_vary_callback("Cookie"))

        # Dispatch to the real SessionAuthenticationPolicy
        return super().unauthenticated_userid(request)
