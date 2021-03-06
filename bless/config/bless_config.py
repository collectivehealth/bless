"""
.. module: bless.config.bless_config
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
import ConfigParser

BLESS_OPTIONS_SECTION = 'Bless Options'
CERTIFICATE_VALIDITY_BEFORE_SEC_OPTION = 'certificate_validity_before_seconds'
CERTIFICATE_VALIDITY_AFTER_SEC_OPTION = 'certificate_validity_after_seconds'
CERTIFICATE_BREAKGLASS_BEFORE_SEC_OPTION = 'certificate_breakglass_validity_before_seconds'
CERTIFICATE_BREAKGLASS_AFTER_SEC_OPTION = 'certificate_breakglass_validity_after_seconds'
CERTIFICATE_VALIDITY_SEC_DEFAULT = 60 * 2
CERTIFICATE_BREAKGLASS_SEC_DEFAULT = 60

BREAKGLASS_USER_OPTION = 'breakglass_user'
BREAKGLASS_USER_DEFAULT = None

ENTROPY_MINIMUM_BITS_OPTION = 'entropy_minimum_bits'
ENTROPY_MINIMUM_BITS_DEFAULT = 2048

RANDOM_SEED_BYTES_OPTION = 'random_seed_bytes'
RANDOM_SEED_BYTES_DEFAULT = 256

LOGGING_LEVEL_OPTION = 'logging_level'
LOGGING_LEVEL_DEFAULT = 'INFO'

TEST_USER_OPTION = 'test_user'
TEST_USER_DEFAULT = None

CERTIFICATE_EXTENSIONS_OPTION = 'certificate_extensions'
# These are the the ssh-keygen default extensions:
CERTIFICATE_EXTENSIONS_DEFAULT = 'permit-X11-forwarding,' \
                                 'permit-agent-forwarding,' \
                                 'permit-port-forwarding,' \
                                 'permit-pty,' \
                                 'permit-user-rc'

BLESS_CA_SECTION = 'Bless CA'
CA_PRIVATE_KEY_FILE_OPTION = 'ca_private_key_file'
KMS_KEY_ID_OPTION = 'kms_key_id'

OKTA_OPTIONS_SECTION = 'Okta Options'

ENCRYPTED_OKTA_API_TOKEN_OPTION = 'encrypted_okta_api_token'
ENCRYPTED_OKTA_API_TOKEN_DEFAULT = None

OKTA_BASE_URL_OPTION = 'okta_base_url'
OKTA_BASE_URL_DEFAULT = None

OKTA_ALLOWED_GROUPS_OPTION = 'okta_allowed_groups'
OKTA_ALLOWED_GROUPS_DEFAULT = None

REGION_PASSWORD_OPTION_SUFFIX = '_password'

KMSAUTH_SECTION = 'KMS Auth'
KMSAUTH_USEKMSAUTH_OPTION = 'use_kmsauth'
KMSAUTH_USEKMSAUTH_DEFAULT = False

KMSAUTH_KEY_ID_OPTION = 'kmsauth_key_id'
KMSAUTH_KEY_ID_DEFAULT = ''

KMSAUTH_SERVICE_ID_OPTION = 'kmsauth_serviceid'
KMSAUTH_SERVICE_ID_DEFAULT = None


class BlessConfig(ConfigParser.RawConfigParser):
    def __init__(self, aws_region, config_file):
        """
        Parses the BLESS config file, and provides some reasonable default values if they are
        absent from the config file.

        The [Bless Options] section is entirely optional, and has defaults.

        The [Bless CA] section is required.
        :param aws_region: The AWS Region BLESS is deployed to.
        :param config_file: Path to the connfig file.
        """
        self.aws_region = aws_region
        defaults = {CERTIFICATE_VALIDITY_BEFORE_SEC_OPTION: CERTIFICATE_VALIDITY_SEC_DEFAULT,
                    CERTIFICATE_VALIDITY_AFTER_SEC_OPTION: CERTIFICATE_VALIDITY_SEC_DEFAULT,
                    CERTIFICATE_BREAKGLASS_BEFORE_SEC_OPTION: CERTIFICATE_BREAKGLASS_SEC_DEFAULT,
                    CERTIFICATE_BREAKGLASS_AFTER_SEC_OPTION: CERTIFICATE_BREAKGLASS_SEC_DEFAULT,
                    ENTROPY_MINIMUM_BITS_OPTION: ENTROPY_MINIMUM_BITS_DEFAULT,
                    RANDOM_SEED_BYTES_OPTION: RANDOM_SEED_BYTES_DEFAULT,
                    LOGGING_LEVEL_OPTION: LOGGING_LEVEL_DEFAULT,
                    TEST_USER_OPTION: TEST_USER_DEFAULT,
                    KMSAUTH_SERVICE_ID_OPTION: KMSAUTH_SERVICE_ID_DEFAULT,
                    KMSAUTH_KEY_ID_OPTION: KMSAUTH_KEY_ID_DEFAULT,
                    KMSAUTH_USEKMSAUTH_OPTION: KMSAUTH_USEKMSAUTH_DEFAULT,
                    CERTIFICATE_EXTENSIONS_OPTION: CERTIFICATE_EXTENSIONS_DEFAULT,
                    ENCRYPTED_OKTA_API_TOKEN_OPTION: ENCRYPTED_OKTA_API_TOKEN_DEFAULT,
                    OKTA_BASE_URL_OPTION: OKTA_BASE_URL_DEFAULT,
                    OKTA_ALLOWED_GROUPS_OPTION: OKTA_ALLOWED_GROUPS_DEFAULT
                    }
        ConfigParser.RawConfigParser.__init__(self, defaults=defaults)
        self.read(config_file)

        if not self.has_section(BLESS_OPTIONS_SECTION):
            self.add_section(BLESS_OPTIONS_SECTION)

        if not self.has_section(KMSAUTH_SECTION):
            self.add_section(KMSAUTH_SECTION)

        if not self.has_section(OKTA_OPTIONS_SECTION):
            self.add_section(OKTA_OPTIONS_SECTION)

        if not self.has_option(BLESS_CA_SECTION, self.aws_region + REGION_PASSWORD_OPTION_SUFFIX):
            raise ValueError("No Region Specific Password Provided.")

    def getpassword(self):
        """
        Returns the correct encrypted password based off of the aws_region.
        :return: A Base64 encoded KMS CiphertextBlob.
        """
        return self.get(BLESS_CA_SECTION, self.aws_region + REGION_PASSWORD_OPTION_SUFFIX)

    def getkmsauthkeyids(self):
        """
        Returns a list of kmsauth keys used for validation (so a key generated
        in one region can validate in another).
        :return: A list of kmsauth key ids
        """
        return map(str.strip, self.get(KMSAUTH_SECTION, KMSAUTH_KEY_ID_OPTION).split(','))
