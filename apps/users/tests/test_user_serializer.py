from django.test import SimpleTestCase, override_settings

from users.models import User
from users.serializers import UserSerializer


class UserSerializerSourceChoicesTest(SimpleTestCase):
    @override_settings(XPACK_ENABLED=False, AUTH_OPENID=True)
    def test_ce_allows_openid_source_when_oidc_is_enabled(self):
        serializer = UserSerializer()
        choices = dict(serializer.fields["source"].choices)

        self.assertIn(User.Source.openid.value, choices)
        self.assertNotIn(User.Source.saml2.value, choices)
        self.assertNotIn(User.Source.oauth2.value, choices)
        self.assertNotIn(User.Source.ldap_ha.value, choices)

    @override_settings(XPACK_ENABLED=False, AUTH_OPENID=False)
    def test_ce_preserves_existing_instance_source(self):
        user = User(username="oidc-user", source=User.Source.openid.value)
        serializer = UserSerializer(instance=user)
        choices = dict(serializer.fields["source"].choices)

        self.assertIn(User.Source.openid.value, choices)
