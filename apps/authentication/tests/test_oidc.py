import datetime as dt
import io
import os
from calendar import timegm
from urllib.parse import parse_qs, urlparse
from unittest import mock

from django.core.exceptions import SuspiciousOperation
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from authentication.backends.oidc.views import OIDCEndSessionView
from authentication.backends.oidc.backends import OIDCAuthCodeBackend
from authentication.backends.oidc.utils import (
    _validate_claims,
    get_openid_allowed_issuers,
    resolve_claim_value,
)
from authentication.management.commands.configure_oidc_from_env import Command
from authentication.views.login import UserLoginView


ONLY_OPENID_AUTH_SETTINGS = {
    'AUTH_OPENID': True,
    'AUTH_CAS': False,
    'AUTH_SAML2': False,
    'AUTH_OAUTH2': False,
    'AUTH_WECOM': False,
    'AUTH_DINGTALK': False,
    'AUTH_FEISHU': False,
    'AUTH_LARK': False,
    'AUTH_SLACK': False,
    'AUTH_PASSKEY': False,
}


NO_THIRD_PARTY_AUTH_SETTINGS = {
    **ONLY_OPENID_AUTH_SETTINGS,
    'AUTH_OPENID': False,
}

ONLY_OPENID_DEFAULT_LOGIN_SETTINGS = {
    **ONLY_OPENID_AUTH_SETTINGS,
    'LOGIN_REDIRECT_TO_BACKEND': '',
}


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

    def test_login_does_not_auto_redirect_after_oidc_logout(self):
        request = RequestFactory().get('/core/auth/login/?oidc_logged_out=1')
        view = UserLoginView()
        view.request = request
        view.get_support_auth_methods = mock.Mock(return_value=[
            {
                'name': 'OPENID',
                'enabled': True,
                'url': '/core/auth/openid/login/',
                'auto_redirect': True,
            }
        ])

        self.assertIsNone(view.redirect_third_party_auth_if_need(request))

    @override_settings(
        BASE_SITE_URL='https://jumpserver.example.com',
        AUTH_OPENID_PROVIDER_END_SESSION_ENDPOINT='https://login.microsoftonline.com/tenant/oauth2/v2.0/logout',
        AUTH_OPENID_PROVIDER_END_SESSION_REDIRECT_URI_PARAMETER='post_logout_redirect_uri',
        AUTH_OPENID_PROVIDER_END_SESSION_ID_TOKEN_PARAMETER='id_token_hint',
    )
    def test_oidc_logout_returns_to_non_auto_redirect_login_page(self):
        request = RequestFactory().get('/core/auth/openid/logout/')
        request.session = {'oidc_auth_id_token': 'id-token'}

        view = OIDCEndSessionView()
        view.request = request
        logout_url = view.provider_end_session_url

        query = parse_qs(urlparse(logout_url).query)
        self.assertEqual(query['id_token_hint'], ['id-token'])
        self.assertEqual(
            query['post_logout_redirect_uri'],
            ['https://jumpserver.example.com/core/auth/login/?oidc_logged_out=1'],
        )


class LoginTemplateTests(TestCase):
    @override_settings(**ONLY_OPENID_DEFAULT_LOGIN_SETTINGS)
    def test_default_login_page_is_sso_only(self):
        response = self.client.get(reverse('authentication:login'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'OpenID')
        self.assertNotContains(response, 'name="username"')
        self.assertNotContains(response, 'id="password"')

    @override_settings(**ONLY_OPENID_AUTH_SETTINGS)
    def test_oidc_logout_login_page_is_sso_only(self):
        url = reverse('authentication:login') + '?oidc_logged_out=1&next=/ui/'
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'OpenID')
        self.assertContains(response, '/core/auth/openid/login/?next=%2Fui%2F')
        self.assertNotContains(response, 'name="username"')
        self.assertNotContains(response, 'id="password"')
        self.assertNotContains(response, 'forgot_password')
        self.assertNotContains(response, 'oidc_logged_out')

    @override_settings(**ONLY_OPENID_AUTH_SETTINGS)
    def test_admin_login_page_keeps_local_password_form(self):
        response = self.client.get(reverse('authentication:login') + '?admin=1')

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'name="username"')
        self.assertContains(response, 'id="password"')
        self.assertContains(response, 'OpenID')
        self.assertNotContains(response, '/core/auth/openid/login/?admin=1')

    @override_settings(**NO_THIRD_PARTY_AUTH_SETTINGS)
    def test_login_page_falls_back_to_password_form_without_sso(self):
        response = self.client.get(reverse('authentication:login') + '?oidc_logged_out=1')

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'name="username"')
        self.assertContains(response, 'id="password"')
