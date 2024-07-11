#!/usr/bin/env python3
""" Basic Auth """
from api.v1.auth.auth import Auth
import base64
from typing import TypeVar
from models.user import User


class BasicAuth(Auth):
    """Define BasicAuth class"""

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """
         returns the Base64 part of the
         Authorization header for a Basic Authentication
        """
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith('Basic '):
            return None
        return authorization_header[len("Basic "):]

    def decode_base64_authorization_header(self,
                                           base64_auth_header: str) -> str:
        """
             returns the decoded value
             of a Base64 string base64_authorization_header
        """
        if base64_auth_header is None:
            return None
        if not isinstance(base64_auth_header, str):
            return None
        try:
            decode_byte = base64.b64decode(base64_auth_header,
                                           validate=True)
            return decode_byte.decode('utf-8')
        except (base64.binascii.Error, UnicodeDecodeError):
            return None

    def extract_user_credentials(self,
                                 de_b64_auth_head: str) -> (str, str):
        """
            returns the user email and password
            from the Base64 decoded value
        """
        if de_b64_auth_head is None:
            return None, None
        if not isinstance(de_b64_auth_head, str):
            return None, None
        parts = de_b64_auth_head.split(':', 1)
        if len(parts) != 2:
            return None, None
        email, password = parts
        return email, password

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """
            hat returns the User instance based
            on his email and password
        """
        if user_email is None or not isinstance(
            user_email, str) or user_pwd is None or not isinstance(
                user_pwd, str):
            return None
        try:
            users = User.search({'email': user_email})
        except Exception:
            return None
        for user in users:
            if user.is_valid_password(user_pwd):
                return user
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
            overloads Auth and retrieves
            the User instance for a request
        """
        if not request:
            return None
        auth_header = self.authorization_header(request)
        if not auth_header:
            return None
        base64_creds = self.extract_base64_authorization_header(auth_header)
        if not base64_creds:
            return None
        decoded_creds = self.decode_base64_authorization_header(base64_creds)
        if not decoded_creds:
            return None
        user_credentials = self.extract_user_credentials(decoded_creds)
        user_email = user_credentials[0]
        user_password = user_credentials[1]
        user_credentials = self.user_object_from_credentials(
            user_email, user_password)
        return user_credentials
