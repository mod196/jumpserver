import datetime as dt
import io
import os
from calendar import timegm
from urllib.parse import parse_qs, urlparse
from unittest import mock

from django.contrib import auth
from django.contrib.auth import get_user_model
from django.core.exceptions import SuspiciousOperation
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from authentication.backends.oidc.views import OIDCEndSessionView
from authentication.backends.oidc.backends import OIDCAuthCodeBackend
from authentication.backends.oidc.signals import openid_create_or_update_user
from authentication.backends.oidc.utils import (
    _validate_claims,
    get_openid_allowed_issuers,
    resolve_claim_value,
)
from authentication.management.commands.configure_oidc_from_env import Command
from authentication.views.login import UserLoginView
from orgs.models import Organization
from users.models import UserGroup


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

LOCAL_PASSWORD_DISABLED_AUTH_SETTINGS = {
    **NO_THIRD_PARTY_AUTH_SETTINGS,
    'AUTH_LDAP': False,
    'AUTH_LDAP_HA': False,
    'AUTH_RADIUS': False,
    'TERMINAL_PUBLIC_KEY_AUTH': False,
    'DISABLE_LOCAL_PASSWORD_LOGIN': True,
}

LOCAL_PASSWORD_ENABLED_AUTH_SETTINGS = {
    **LOCAL_PASSWORD_DISABLED_AUTH_SETTINGS,
    'DISABLE_LOCAL_PASSWORD_LOGIN': False,
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
        mock_update_or_create.assert_any_call(
            name='AUTH_OPENID_SYNC_GROUPS',
            value=False,
            encrypted=False,
            category='oidc',
        )
        mock_update_or_create.assert_any_call(
            name='AUTH_OPENID_USER_ATTR_MAP',
            value={
                'name': ['name', 'display_name', 'preferred_username', 'email'],
                'username': ['preferred_username', 'email', 'upn', 'sub'],
                'email': ['email', 'preferred_username', 'upn'],
            },
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


class OIDCUserGroupSyncTests(TestCase):
    @override_settings(
        AUTH_OPENID_SYNC_GROUPS=False,
        OPENID_ORG_IDS=[Organization.DEFAULT_ID],
    )
    def test_oidc_groups_claim_is_ignored_by_default(self):
        user = get_user_model().objects.create(username='oidc-user')

        openid_create_or_update_user.send(
            sender=self.__class__, user=user, created=True,
            attrs={
                'username': 'oidc-user',
                'email': 'oidc-user@example.com',
                'groups': ['entra-group-id'],
            },
        )

        user.refresh_from_db()
        self.assertEqual(user.source, user.Source.openid.value)
        self.assertFalse(UserGroup.objects.filter(name='entra-group-id').exists())
        self.assertFalse(user.groups.exists())

    @override_settings(
        AUTH_OPENID_SYNC_GROUPS=False,
        OPENID_ORG_IDS=[Organization.DEFAULT_ID],
    )
    def test_manual_user_groups_are_kept_when_oidc_sync_disabled(self):
        user = get_user_model().objects.create(username='oidc-user', source='openid')
        manual_group = UserGroup.objects.create(
            name='jumpserver-managed-group', org_id=Organization.DEFAULT_ID
        )
        user.groups.add(manual_group)

        openid_create_or_update_user.send(
            sender=self.__class__, user=user, created=False,
            attrs={
                'username': 'oidc-user',
                'email': 'oidc-user@example.com',
                'groups': ['entra-group-id'],
            },
        )

        user.refresh_from_db()
        self.assertEqual(
            list(user.groups.values_list('name', flat=True)),
            ['jumpserver-managed-group']
        )
        self.assertFalse(UserGroup.objects.filter(name='entra-group-id').exists())

    @override_settings(
        AUTH_OPENID_SYNC_GROUPS=True,
        OPENID_ORG_IDS=[Organization.DEFAULT_ID],
    )
    def test_oidc_groups_claim_is_synced_when_enabled(self):
        user = get_user_model().objects.create(username='oidc-user')

        openid_create_or_update_user.send(
            sender=self.__class__, user=user, created=True,
            attrs={
                'username': 'oidc-user',
                'email': 'oidc-user@example.com',
                'groups': ['entra-group-id'],
            },
        )

        user.refresh_from_db()
        self.assertTrue(UserGroup.objects.filter(name='entra-group-id').exists())
        self.assertEqual(list(user.groups.values_list('name', flat=True)), ['entra-group-id'])


class LoginTemplateTests(TestCase):
    @override_settings(**ONLY_OPENID_DEFAULT_LOGIN_SETTINGS)
    def test_default_login_page_is_sso_only(self):
        response = self.client.get(reverse('authentication:login'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'OpenID')
        self.assertContains(response, 'microsoft-logo')
        self.assertNotContains(response, 'login_oidc_logo.png')
        self.assertNotContains(response, 'name="username"')
        self.assertNotContains(response, 'id="password"')

    @override_settings(**ONLY_OPENID_AUTH_SETTINGS)
    def test_oidc_logout_login_page_is_sso_only(self):
        url = reverse('authentication:login') + '?oidc_logged_out=1&next=/ui/'
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'OpenID')
        self.assertContains(response, 'microsoft-logo')
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

    @override_settings(**ONLY_OPENID_DEFAULT_LOGIN_SETTINGS, DISABLE_LOCAL_PASSWORD_LOGIN=True)
    def test_admin_login_page_is_sso_only_when_local_password_disabled(self):
        response = self.client.get(reverse('authentication:login') + '?admin=1')

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'OpenID')
        self.assertContains(response, 'microsoft-logo')
        self.assertNotContains(response, 'name="username"')
        self.assertNotContains(response, 'id="password"')

    @override_settings(**LOCAL_PASSWORD_DISABLED_AUTH_SETTINGS)
    def test_login_page_does_not_fallback_to_password_when_local_password_disabled(self):
        response = self.client.get(reverse('authentication:login'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Local password login is disabled')
        self.assertNotContains(response, 'name="username"')
        self.assertNotContains(response, 'id="password"')

    @override_settings(**LOCAL_PASSWORD_DISABLED_AUTH_SETTINGS)
    def test_local_password_post_is_forbidden_when_disabled(self):
        response = self.client.post(reverse('authentication:login') + '?admin=1', {
            'username': 'admin',
            'password': 'password',
        })

        self.assertEqual(response.status_code, 403)
        self.assertContains(response, 'Local password login is disabled', status_code=403)

    @override_settings(**LOCAL_PASSWORD_DISABLED_AUTH_SETTINGS)
    def test_model_password_backend_is_disabled_when_local_password_disabled(self):
        user_model = get_user_model()
        user_model.objects.create_user(username='local-admin', password='password')

        user = auth.authenticate(username='local-admin', password='password')

        self.assertIsNone(user)

    @override_settings(**LOCAL_PASSWORD_ENABLED_AUTH_SETTINGS)
    def test_model_password_backend_still_works_by_default(self):
        user_model = get_user_model()
        user_model.objects.create_user(username='local-admin', password='password')

        user = auth.authenticate(username='local-admin', password='password')

        self.assertIsNotNone(user)
        self.assertEqual(user.username, 'local-admin')
