import datetime as dt
import io
import os
from calendar import timegm
from unittest import mock

from django.core.exceptions import SuspiciousOperation
from django.test import RequestFactory, SimpleTestCase, override_settings

from authentication.backends.oidc.backends import OIDCAuthCodeBackend
from authentication.backends.oidc.utils import (
    _validate_claims,
    get_openid_allowed_issuers,
    resolve_claim_value,
)
from authentication.management.commands.configure_oidc_from_env import Command


def make_id_token(**overrides):
    now = timegm(dt.datetime.utcnow().utctimetuple())
    token = {
        'iss': 'https://login.microsoftonline.com/tenant-1/v2.0',
        'aud': 'client-id',
        'exp': now + 300,
        'iat': now,
        'nonce': 'nonce-value',
    }
    token.update(overrides)
    return token


class OIDCTests(SimpleTestCase):
    def test_resolve_claim_value_supports_fallbacks(self):
        claims = {
            'sub': 'subject-id',
            'preferred_username': '',
            'email': 'ryu.liu@intelligentagetech.com',
        }
        value = resolve_claim_value(
            claims, ['preferred_username', 'email', 'upn', 'sub'], claims['sub']
        )
        self.assertEqual(value, 'ryu.liu@intelligentagetech.com')

    @override_settings(
        AUTH_OPENID_PROVIDER_TYPE='microsoft_entra_id',
        AUTH_OPENID_ENTRA_TENANT_ID='tenant-1',
        AUTH_OPENID_ALLOWED_ISSUERS=[],
        AUTH_OPENID_PROVIDER_ENDPOINT='https://login.microsoftonline.com/tenant-1/v2.0',
        AUTH_OPENID_CLIENT_ID='client-id',
        AUTH_OPENID_ID_TOKEN_MAX_AGE=600,
        AUTH_OPENID_USE_NONCE=True,
    )
    def test_entra_issuer_is_checked_exactly(self):
        _validate_claims(make_id_token(), nonce='nonce-value')

        token = make_id_token(iss='https://login.microsoftonline.com/other-tenant/v2.0')
        with self.assertRaises(SuspiciousOperation):
            _validate_claims(token, nonce='nonce-value')

    @override_settings(
        AUTH_OPENID_PROVIDER_TYPE='microsoft_entra_id',
        AUTH_OPENID_ENTRA_TENANT_ID='tenant-1',
        AUTH_OPENID_ALLOWED_ISSUERS=[
            'https://login.microsoftonline.com/tenant-1/v2.0',
            'https://sts.windows.net/tenant-1/',
        ],
        AUTH_OPENID_PROVIDER_ENDPOINT='https://login.microsoftonline.com/tenant-1/v2.0',
    )
    def test_allowed_issuers_are_normalized(self):
        self.assertEqual(
            get_openid_allowed_issuers(),
            [
                'https://login.microsoftonline.com/tenant-1/v2.0',
                'https://sts.windows.net/tenant-1',
            ],
        )

    def test_configure_command_extracts_tenant_from_issuer(self):
        self.assertEqual(
            Command.get_tenant_id('https://login.microsoftonline.com/tenant-1/v2.0'),
            'tenant-1',
        )

    @mock.patch('authentication.management.commands.configure_oidc_from_env.Setting.update_or_create')
    @mock.patch('authentication.management.commands.configure_oidc_from_env.requests.get')
    def test_configure_command_uses_discovery_without_printing_secret(
            self, mock_get, mock_update_or_create
    ):
        discovery = {
            'issuer': 'https://login.microsoftonline.com/tenant-1/v2.0',
            'authorization_endpoint': 'https://login.microsoftonline.com/tenant-1/oauth2/v2.0/authorize',
            'token_endpoint': 'https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token',
            'jwks_uri': 'https://login.microsoftonline.com/tenant-1/discovery/v2.0/keys',
            'userinfo_endpoint': 'https://graph.microsoft.com/oidc/userinfo',
            'end_session_endpoint': 'https://login.microsoftonline.com/tenant-1/oauth2/v2.0/logout',
        }
        response = mock.Mock()
        response.json.return_value = discovery
        response.raise_for_status.return_value = None
        mock_get.return_value = response

        stdout = io.StringIO()
        secret = 'super-secret-client-value'
        env = {
            'OIDC_RP_CLIENT_ID': 'client-id',
            'OIDC_RP_CLIENT_SECRET': secret,
            'OIDC_RP_WELLKNOWN_URL': 'https://login.microsoftonline.com/tenant-1/v2.0/.well-known/openid-configuration',
        }
        with mock.patch.dict(os.environ, env):
            Command(stdout=stdout).handle(
                base_site_url='https://js.bitfufu.tech',
                disabled=False,
            )

        mock_update_or_create.assert_any_call(
            name='AUTH_OPENID_CLIENT_SECRET',
            value=secret,
            encrypted=True,
            category='oidc',
        )
        mock_update_or_create.assert_any_call(
            name='AUTH_OPENID_CLIENT_AUTH_METHOD',
            value='client_secret_post',
            encrypted=False,
            category='oidc',
        )
        self.assertNotIn(secret, stdout.getvalue())

    @override_settings(
        BASE_SITE_URL='https://js.bitfufu.tech',
        AUTH_OPENID_USE_NONCE=False,
        AUTH_OPENID_USE_STATE=True,
        AUTH_OPENID_PKCE=False,
        AUTH_OPENID_CLIENT_AUTH_METHOD='client_secret_post',
        AUTH_OPENID_CLIENT_ID='client-id',
        AUTH_OPENID_CLIENT_SECRET='super-secret-client-value',
        AUTH_OPENID_PROVIDER_TOKEN_ENDPOINT='https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token',
        AUTH_OPENID_AUTH_LOGIN_CALLBACK_URL_NAME='authentication:openid:login-callback',
    )
    @mock.patch('authentication.backends.oidc.backends.logger.debug')
    @mock.patch('authentication.backends.oidc.backends.requests.post')
    def test_token_error_log_is_redacted(self, mock_post, mock_debug):
        class ErrorResponse:
            status_code = 401
            content = b'id_token=raw-token&client_secret=super-secret-client-value'

            def raise_for_status(self):
                raise RuntimeError('raw-token super-secret-client-value')

        request = RequestFactory().get('/core/auth/openid/callback/?state=s&code=c')
        request.session = {'oidc_auth_state': 's'}
        mock_post.return_value = ErrorResponse()

        self.assertIsNone(OIDCAuthCodeBackend().authenticate(request))

        log_output = '\n'.join(str(call) for call in mock_debug.call_args_list)
        self.assertIn('status code is: 401', log_output)
        self.assertNotIn('raw-token', log_output)
        self.assertNotIn('super-secret-client-value', log_output)
