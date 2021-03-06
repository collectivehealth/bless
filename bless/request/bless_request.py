"""
.. module: bless.request.bless_request
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
import re

import ipaddress
from marshmallow import Schema, fields, post_load, ValidationError, validates_schema

# man 8 useradd
USERNAME_PATTERN = re.compile('[a-z_][a-z0-9_-]*[$]?\Z')
# It appears that most printable ascii is valid, excluding whitespace, #, and commas.
# There doesn't seem to be any practical size limits of a principal (> 4096B allowed).
PRINCIPAL_PATTERN = re.compile(r'[\d\w!"$%&\'()*+\-./:;<=>?@\[\\\]\^`{|}~]+\Z')


def validate_ips(ips):
    try:
        for ip in ips.split(','):
            ipaddress.ip_network(ip, strict=True)
    except ValueError:
        raise ValidationError('Invalid IP address.')


def validate_user(user):
    if len(user) > 32:
        raise ValidationError('Username is too long.')
    if USERNAME_PATTERN.match(user) is None:
        raise ValidationError('Username contains invalid characters.')


def validate_principals(principals):
    for principal in principals.split(','):
        if PRINCIPAL_PATTERN.match(principal) is None:
            raise ValidationError('Principal contains invalid characters.')


class BlessSchema(Schema):
    bastion_ips = fields.Str(validate=validate_ips, required=True)
    bastion_user = fields.Str(validate=validate_user, required=True)
    bastion_user_ip = fields.Str(validate=validate_ips, required=True)
    command = fields.Str(required=True)
    okta_user = fields.Str(required=True)
    remote_usernames = fields.Str(validate=validate_principals, required=True)
    kmsauth_token = fields.Str(required=False)

    @validates_schema(pass_original=True)
    def check_unknown_fields(self, data, original_data):
        unknown = set(original_data) - set(self.fields)
        if unknown:
            raise ValidationError('Unknown field', unknown)

    @post_load
    def make_bless_request(self, data):
        return BlessRequest(**data)


class BlessRequest:
    def __init__(self, bastion_ips, bastion_user, bastion_user_ip, command, okta_user,
                 remote_usernames, kmsauth_token=None):
        """
        A BlessRequest must have the following key value pairs to be valid.
        :param bastion_ips: The source IPs where the SSH connection will be initiated from.  This is
        enforced in the issued certificate.
        :param bastion_user: The user on the bastion, who is initiating the SSH request.
        :param bastion_user_ip: The IP of the user accessing the bastion.
        :param command: Text information about the SSH request of the user.
        :param okta_user: The Okta username that will be used to fetch public key.
        :param remote_usernames: Comma-separated list of username(s) or authorized principals on the remote
        server that will be used in the SSH request.  This is enforced in the issued certificate.
        :param kmsauth_token: An optional kms auth token to authenticate the user.
        """
        self.bastion_ips = bastion_ips
        self.bastion_user = bastion_user
        self.bastion_user_ip = bastion_user_ip
        self.command = command
        self.okta_user = okta_user
        self.remote_usernames = remote_usernames
        self.kmsauth_token = kmsauth_token

    def __eq__(self, other):
        return self.__dict__ == other.__dict__
