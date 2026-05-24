import os
from urllib.parse import urlparse

import requests
from django.core.management.base import BaseCommand, CommandError

from settings.models import Setting


class Command(BaseCommand):
    help = 'Configure Microsoft Entra ID OIDC settings from environment variables.'

    sensitive_envs = (
        'OIDC_RP_CLIENT_SECRET',
    )

    def add_arguments(self, parser):
        parser.add_argument(
            '--base-site-url',
            default=os.environ.get('JUMPSERVER_BASE_SITE_URL', 'https://js.bitfufu.tech'),
            help='Public JumpServer base URL used to build the OIDC callback URL.',
        )
        parser.add_argument(
            '--disabled',
            action='store_true',
            help='Write discovered settings but leave AUTH_OPENID disabled.',
        )

    def handle(self, *args, **options):
        client_id = os.environ.get('OIDC_RP_CLIENT_ID')
        client_secret = os.environ.get('OIDC_RP_CLIENT_SECRET')
        wellknown_url = os.environ.get('OIDC_RP_WELLKNOWN_URL')
        missing = [
            name for name, value in {
                'OIDC_RP_CLIENT_ID': client_id,
                'OIDC_RP_CLIENT_SECRET': client_secret,
                'OIDC_RP_WELLKNOWN_URL': wellknown_url,
            }.items() if not value
        ]
        if missing:
            raise CommandError('Missing required environment variables: {}'.format(', '.join(missing)))

        try:
            response = requests.get(wellknown_url, timeout=15)
            response.raise_for_status()
            discovery = response.json()
        except Exception as error:
            raise CommandError('Failed to load OIDC discovery document: {}'.format(error))

        issuer = discovery.get('issuer')
        required_keys = {
            'issuer': issuer,
            'authorization_endpoint': discovery.get('authorization_endpoint'),
            'token_endpoint': discovery.get('token_endpoint'),
            'jwks_uri': discovery.get('jwks_uri'),
        }
        missing_discovery = [key for key, value in required_keys.items() if not value]
        if missing_discovery:
            raise CommandError(
                'OIDC discovery document is missing required fields: {}'.format(
                    ', '.join(missing_discovery)
                )
            )

        tenant_id = self.get_tenant_id(issuer)
        settings_items = {
            'AUTH_OPENID': not options['disabled'],
            'AUTH_OPENID_PROVIDER_TYPE': 'microsoft_entra_id',
            'AUTH_OPENID_ENTRA_TENANT_ID': tenant_id,
            'AUTH_OPENID_ALLOWED_ISSUERS': [issuer.rstrip('/')],
            'AUTH_OPENID_KEYCLOAK': False,
            'BASE_SITE_URL': options['base_site_url'].rstrip('/'),
            'AUTH_OPENID_CLIENT_ID': client_id,
            'AUTH_OPENID_CLIENT_SECRET': client_secret,
            'AUTH_OPENID_CLIENT_AUTH_METHOD': 'client_secret_post',
            'AUTH_OPENID_PROVIDER_ENDPOINT': issuer.rstrip('/'),
            'AUTH_OPENID_PROVIDER_AUTHORIZATION_ENDPOINT': discovery['authorization_endpoint'],
            'AUTH_OPENID_PROVIDER_TOKEN_ENDPOINT': discovery['token_endpoint'],
            'AUTH_OPENID_PROVIDER_JWKS_ENDPOINT': discovery['jwks_uri'],
            'AUTH_OPENID_PROVIDER_USERINFO_ENDPOINT': discovery.get('userinfo_endpoint', ''),
            'AUTH_OPENID_PROVIDER_END_SESSION_ENDPOINT': discovery.get('end_session_endpoint', ''),
            'AUTH_OPENID_PROVIDER_SIGNATURE_ALG': 'RS256',
            'AUTH_OPENID_PROVIDER_SIGNATURE_KEY': None,
            'AUTH_OPENID_SCOPES': 'openid profile email',
            'AUTH_OPENID_ID_TOKEN_INCLUDE_CLAIMS': True,
            'AUTH_OPENID_USE_STATE': True,
            'AUTH_OPENID_USE_NONCE': True,
            'AUTH_OPENID_ALWAYS_UPDATE_USER': True,
            'AUTH_OPENID_IGNORE_SSL_VERIFICATION': False,
            'AUTH_OPENID_SHARE_SESSION': True,
            'AUTH_OPENID_PKCE': False,
            'AUTH_OPENID_CODE_CHALLENGE_METHOD': 'S256',
            'AUTH_OPENID_USER_ATTR_MAP': {
                'name': ['name', 'display_name', 'preferred_username', 'email'],
                'username': ['preferred_username', 'email', 'upn', 'sub'],
                'email': ['email', 'preferred_username', 'upn'],
                'groups': 'groups',
            },
        }

        encrypted_items = {'AUTH_OPENID_CLIENT_SECRET'}
        for name, value in settings_items.items():
            Setting.update_or_create(
                name=name, value=value, encrypted=name in encrypted_items, category='oidc',
            )

        self.stdout.write(self.style.SUCCESS(
            'Configured Microsoft Entra ID OIDC for issuer {} and base site {}'.format(
                issuer, options['base_site_url'].rstrip('/')
            )
        ))

    @staticmethod
    def get_tenant_id(issuer):
        parsed = urlparse(issuer or '')
        parts = [item for item in parsed.path.split('/') if item]
        return parts[0] if parts else ''
