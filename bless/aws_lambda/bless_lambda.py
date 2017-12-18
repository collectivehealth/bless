"""
.. module: bless.aws_lambda.bless_lambda
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
import base64
import logging
import os
import time
import boto3
import okta

from botocore.exceptions import ClientError
from kmsauth import KMSTokenValidator, TokenValidationError
from marshmallow.exceptions import ValidationError
from okta.models.user import UserProfile as OktaUserProfile

from bless.config.bless_config import BlessConfig, \
    BLESS_OPTIONS_SECTION, \
    CERTIFICATE_VALIDITY_BEFORE_SEC_OPTION, \
    CERTIFICATE_VALIDITY_AFTER_SEC_OPTION, \
    CERTIFICATE_BREAKGLASS_BEFORE_SEC_OPTION, \
    CERTIFICATE_BREAKGLASS_AFTER_SEC_OPTION, \
    BREAKGLASS_USER_OPTION, \
    ENTROPY_MINIMUM_BITS_OPTION, \
    RANDOM_SEED_BYTES_OPTION, \
    BLESS_CA_SECTION, \
    CA_PRIVATE_KEY_FILE_OPTION, \
    LOGGING_LEVEL_OPTION, \
    KMSAUTH_SECTION, \
    KMSAUTH_USEKMSAUTH_OPTION, \
    KMSAUTH_SERVICE_ID_OPTION, \
    TEST_USER_OPTION, \
    CERTIFICATE_EXTENSIONS_OPTION, \
    ENCRYPTED_OKTA_API_TOKEN_OPTION, \
    OKTA_OPTIONS_SECTION, \
    OKTA_BASE_URL_OPTION, \
    OKTA_ALLOWED_GROUPS_OPTION

from bless.request.bless_request import BlessSchema
from bless.ssh.certificate_authorities.ssh_certificate_authority_factory import \
    get_ssh_certificate_authority
from bless.ssh.certificates.ssh_certificate_builder import SSHCertificateType
from bless.ssh.certificates.ssh_certificate_builder_factory import get_ssh_certificate_builder

VALID_SSH_RSA_PUBLIC_KEY_HEADER = "ssh-rsa AAAAB3NzaC1yc2"


def lambda_handler(event, context=None, ca_private_key_password=None, okta_api_token=None,
                   entropy_check=True,
                   config_file=os.path.join(os.path.dirname(__file__), 'bless_deploy.cfg')):
    """
    This is the function that will be called when the lambda function starts.
    :param event: Dictionary of the json request.
    :param context: AWS LambdaContext Object
    http://docs.aws.amazon.com/lambda/latest/dg/python-context-object.html
    :param ca_private_key_password: For local testing, if the password is provided, skip the KMS
    decrypt.
    :param entropy_check: For local testing, if set to false, it will skip checking entropy and
    won't try to fetch additional random from KMS
    :param config_file: The config file to load the SSH CA private key from, and additional settings
    :return: the SSH Certificate that can be written to id_rsa-cert.pub or similar file.
    """
    # AWS Region determines configs related to KMS
    region = os.environ['AWS_REGION']

    # Load the deployment config values
    config = BlessConfig(region, config_file=config_file)

    logger = logging.getLogger(__name__)

    logging_level = config.get(BLESS_OPTIONS_SECTION, LOGGING_LEVEL_OPTION)
    numeric_level = getattr(logging, logging_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: {}'.format(logging_level))
    logger.setLevel(numeric_level)

    certificate_validity_before_seconds = config.getint(BLESS_OPTIONS_SECTION, CERTIFICATE_VALIDITY_BEFORE_SEC_OPTION)
    certificate_validity_after_seconds = config.getint(BLESS_OPTIONS_SECTION, CERTIFICATE_VALIDITY_AFTER_SEC_OPTION)
    certificate_breakglass_validity_before_seconds = config.getint(
        BLESS_OPTIONS_SECTION,
        CERTIFICATE_BREAKGLASS_BEFORE_SEC_OPTION
    )
    certificate_breakglass_validity_after_seconds = config.getint(
        BLESS_OPTIONS_SECTION,
        CERTIFICATE_BREAKGLASS_AFTER_SEC_OPTION
    )

    breakglass_user = config.get(BLESS_OPTIONS_SECTION, BREAKGLASS_USER_OPTION)

    entropy_minimum_bits = config.getint(BLESS_OPTIONS_SECTION, ENTROPY_MINIMUM_BITS_OPTION)
    random_seed_bytes = config.getint(BLESS_OPTIONS_SECTION, RANDOM_SEED_BYTES_OPTION)
    ca_private_key_file = config.get(BLESS_CA_SECTION, CA_PRIVATE_KEY_FILE_OPTION)

    password_ciphertext_b64 = config.getpassword()

    certificate_extensions = config.get(BLESS_OPTIONS_SECTION, CERTIFICATE_EXTENSIONS_OPTION)

    encrypted_okta_api_token = config.get(OKTA_OPTIONS_SECTION, ENCRYPTED_OKTA_API_TOKEN_OPTION)
    okta_base_url = config.get(OKTA_OPTIONS_SECTION, OKTA_BASE_URL_OPTION)
    okta_allowed_groups = config.get(OKTA_OPTIONS_SECTION, OKTA_ALLOWED_GROUPS_OPTION)
    if okta_allowed_groups:
        okta_allowed_groups = set(okta_allowed_groups.split(','))
        logger.debug("Allowed okta groups: {}".format(okta_allowed_groups))

    # Process cert request
    schema = BlessSchema(strict=True)
    try:
        request = schema.load(event).data
    except ValidationError as e:
        return error_response('InputValidationError', str(e))

    logger.info('Bless lambda invoked by okta user: {}@{}, bastion user: {}, kmsauth_token: {}]'.format(
        request.okta_user,
        request.bastion_user_ip,
        request.bastion_user,
        request.kmsauth_token)
    )

    # read the private key .pem
    with open(os.path.join(os.path.dirname(__file__), ca_private_key_file), 'r') as f:
        ca_private_key = f.read()

    kms_client = boto3.client('kms', region_name=region)

    # decrypt ca private key password
    if ca_private_key_password is None:
        try:
            ca_password = kms_client.decrypt(
                CiphertextBlob=base64.b64decode(password_ciphertext_b64))
            ca_private_key_password = ca_password['Plaintext']
        except ClientError as e:
            return error_response('ClientError', str(e))

    # decrypt okta api token
    if okta_api_token is None:
        try:
            decrypted_okta_api_token = kms_client.decrypt(
                CiphertextBlob=base64.b64decode(encrypted_okta_api_token))
            okta_api_token = decrypted_okta_api_token['Plaintext']
        except ClientError as e:
            return error_response('ClientError', str(e))

    '''
    Fetch user context from Okta
    * Username
    * Groups
    * SSH key
    '''

    # add extra property to Okta user profile schema
    OktaUserProfile.types['public_key'] = str

    okta_users_client = okta.UsersClient(okta_base_url, okta_api_token)

    user = okta_users_client.get_user(request.okta_user)
    groups_info = okta_users_client.get_user_groups(request.okta_user)

    groups = set()
    for group_info in groups_info:
        # Encode unicode response from okta json api as a byte string to ease comparisons
        groups.add(group_info.profile.name.encode('utf-8'))

    logger.debug('User groups: {}'.format(groups))

    allowed_groups = okta_allowed_groups
    logger.debug('Whitelist groups: {}'.format(allowed_groups))

    logger.debug('Matched groups: {}'.format(groups.intersection(allowed_groups)))

    # If the len is greater than 0, breakglass will be false.
    breakglass = not len(groups.intersection(allowed_groups))

    public_key_to_sign = user.profile.public_key
    if public_key_to_sign.startswith(VALID_SSH_RSA_PUBLIC_KEY_HEADER):
        pass
    else:
        raise ValidationError('Invalid SSH Public Key.')

    # if running as a Lambda, we can check the entropy pool and seed it with KMS if desired
    if entropy_check:
        with open('/proc/sys/kernel/random/entropy_avail', 'r') as f:
            entropy = int(f.read())
            logger.debug(entropy)
            if entropy < entropy_minimum_bits:
                logger.info(
                    'System entropy was {}, which is lower than the entropy_'
                    'minimum {}.  Using KMS to seed /dev/urandom'.format(
                        entropy, entropy_minimum_bits))
                response = kms_client.generate_random(
                    NumberOfBytes=random_seed_bytes)
                random_seed = response['Plaintext']
                with open('/dev/urandom', 'w') as urandom:
                    urandom.write(random_seed)

    # cert values determined only by lambda and its configs
    current_time = int(time.time())
    test_user = config.get(BLESS_OPTIONS_SECTION, TEST_USER_OPTION)
    if test_user and (request.bastion_user == test_user or request.remote_usernames == test_user):
        # This is a test call, the lambda will issue an invalid
        # certificate where valid_before < valid_after
        valid_before = current_time
        valid_after = current_time + 1
        bypass_time_validity_check = True
    else:  # Normal user flow
        bypass_time_validity_check = False
        valid_before = current_time + certificate_validity_after_seconds
        valid_after = current_time - certificate_validity_before_seconds

    # Authenticate the user with KMS, if key is setup
    if config.get(KMSAUTH_SECTION, KMSAUTH_USEKMSAUTH_OPTION):
        if request.kmsauth_token:
            try:
                validator = KMSTokenValidator(
                    None,
                    config.getkmsauthkeyids(),
                    config.get(KMSAUTH_SECTION, KMSAUTH_SERVICE_ID_OPTION),
                    region
                )
                # decrypt_token will raise a TokenValidationError if token doesn't match
                validator.decrypt_token(
                    "2/user/{}".format(request.remote_usernames.split(',')[0]),
                    request.kmsauth_token
                )
            except TokenValidationError as e:
                return error_response('KMSAuthValidationError', str(e))
        else:
            return error_response('InputValidationError', 'Invalid request, missing kmsauth token')

    # Build the cert
    ca = get_ssh_certificate_authority(ca_private_key, ca_private_key_password)
    cert_builder = get_ssh_certificate_builder(ca, SSHCertificateType.USER,
                                               public_key_to_sign)
    # Handle breakglass certificate modifications
    if breakglass:
        logger.critical('Breakglass access for okta user: {}@{}, bastion user: {}'.format(
            request.okta_user,
            request.bastion_user_ip,
            request.bastion_user)
        )
        valid_before = current_time + certificate_breakglass_validity_before_seconds
        valid_after = current_time - certificate_breakglass_validity_after_seconds
        cert_builder.add_valid_principal(breakglass_user)

    for username in request.remote_usernames.split(','):
        cert_builder.add_valid_principal(username)

    cert_builder.set_valid_before(valid_before)
    cert_builder.set_valid_after(valid_after)

    if certificate_extensions:
        for e in certificate_extensions.split(','):
            if e:
                cert_builder.add_extension(e)
    else:
        cert_builder.clear_extensions()

    # cert_builder is needed to obtain the SSH public key's fingerprint
    key_id = 'AWS Request ID: {}, User: {}, Source IP: {}, Command: {}, ' \
             'Fingerprint: {}, Bless CA: {}, Expires: {}'\
        .format(
            context.aws_request_id,
            request.bastion_user,
            request.bastion_user_ip,
            request.command,
            cert_builder.ssh_public_key.fingerprint,
            context.invoked_function_arn,
            time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime(valid_before))
        )

    cert_builder.set_critical_option_source_addresses(request.bastion_ips)
    cert_builder.set_key_id(key_id)
    cert = cert_builder.get_cert_file(bypass_time_validity_check)

    logger.info(
        'Issued a cert to bastion_ips[{}] for the remote_usernames of [{}] with the key_id[{}] and '
        'valid_from[{}])'.format(
            request.bastion_ips, request.remote_usernames, key_id,
            time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime(valid_after))))
    return success_response(cert)


def success_response(cert):
    return {
        'certificate': cert
    }


def error_response(error_type, error_message):
    return {
        'errorType': error_type,
        'errorMessage': error_message
    }
