# coding: utf-8

"""
Authentication module for MDS API calls.
"""

from datetime import datetime, timedelta

import jwt
import requests
from requests.auth import HTTPBasicAuth


class BaseAuthorization():
    """
    Represents a session that do not require any Authentication method.
    """
    def __init__(self, provider):
        """
        Establishes a session for the provider.
        """
        session = requests.Session()
        verify = getattr(provider,'ssl_verify',None)
        if verify is not None:
          session.verify = verify 

        self.session = session

    @classmethod
    def can_auth(cls, provider):
        """
        Returns True if this auth type can be used for the provider.
        """
        return all([
            hasattr(provider, "no_auth_required")
        ])


class AuthorizationToken(BaseAuthorization):
    """
    Represents an authenticated session via an Authorization token header.

    To implement a new token-based auth type, create a subclass of AuthorizationToken and implement:

        __init__(self, provider)
            Initialize self.session.

        @classmethod
        can_auth(cls, provider): bool
            Return True if the auth type can be used on the provider.

    See OAuthClientCredentialsAuth for an example implementation.
    """
    def __init__(self, provider):
        """
        Includes the Authorization token header in the session for the provider
        """
        BaseAuthorization.__init__(self, provider)
        
        #if Provider auth_type has is empty, do NOT include it (avoid initial blank)
        if provider.auth_type:
            self.session.headers.update({ "Authorization": f"{provider.auth_type} {provider.token}" })
        else:
            self.session.headers.update({ "Authorization": f"{provider.token}" })

        headers = getattr(provider, "headers", None)
        if headers:
            self.session.headers.update(headers)

    @classmethod
    def can_auth(cls, provider):
        """
        Returns True if this auth type can be used for the provider.
        """
        return all([
            hasattr(provider, "auth_type"),
            hasattr(provider, "token"),
            not hasattr(provider, "token_url")
        ])


class LoginClientCredentials(AuthorizationToken):
    """
    Represents an authenticated session via a simple username/password POST.

    Currently, your config needs:

    * username
    * password
    * login_url
    
    Optionally it may provide:
    
    * username_key (key to use in request for username, defaults to "username")
    * password_key (key to use in request for password, defaults to "password")
    * token_key (key of token value in response, default to "token")
    """
    def __init__(self, provider):
        """
        Acquires the provider token before establishing a session.
        Use provider specified names for request values or defaults.
        """
        payload = {
            getattr(provider, "username_key", "username"): provider.username,
            getattr(provider, "password_key", "password"): provider.password
        }

        r = requests.post(provider.login_url, json=payload,
                          verify=getattr(provider,'ssl_verify',None),
                          headers=getattr(provider, "login_headers",None)
                          )
        provider.token = r.json()[getattr(provider, "token_key", "token")]

        AuthorizationToken.__init__(self, provider)

    @classmethod
    def can_auth(cls, provider):
        """
        Returns True if this auth type can be used for the provider.
        """
        return all([
            hasattr(provider, "username"),
            hasattr(provider, "password"),
            hasattr(provider, "login_url")
        ])


class OAuthClientCredentials(AuthorizationToken):
    """
    Represents an authenticated session via OAuth 2.0 client_credentials grant flow.
    """
    def __init__(self, provider):
        """
        Acquires a Bearer token before establishing a session with the provider.
        """
        payload = {
            "client_id": provider.client_id,
            "client_secret": provider.client_secret,
            "grant_type": "client_credentials",
            "scope": provider.scope.split(",")
        }
        r = requests.post(provider.token_url, data=payload,
                          verify=getattr(provider,'ssl_verify',None)
                          )
        provider.token = r.json()["access_token"]
        
        AuthorizationToken.__init__(self, provider)

    @classmethod
    def can_auth(cls, provider):
        """
        Returns True if this auth type can be used for the provider.
        """
        return all([
            hasattr(provider, "client_id"),
            hasattr(provider, "client_secret"),
            hasattr(provider, "scope")
        ])


class BaseJWTCredentials(AuthorizationToken):
    """
    Represents an authenticated session via generation of a JWT token.
    """
    def __init__(self, provider):
        """
        Acquires a Bearer token before establishing a session with the provider.
        """
        headers = {
          'alg': 'RS256',
          #'alg': 'ES256',        #is it actually needed to use this one???
          'typ': 'JWT',
          'kid' : provider.private_key_id 
        }
        now = datetime.utcnow()
        payload = {
            'email': provider.client_email,
            'iat': now,
            'exp': now + timedelta(hours=1),
            'aud': self.aud,
            'iss': provider.client_email,
            'sub': provider.client_email,
        }
        provider.token = jwt.encode(key=provider.private_key,          
            payload=payload, 
            algorithm='RS256',    #is it actually needed to use this one???
            #algorithm='ES256', 
            headers=headers
        )
        
        AuthorizationToken.__init__(self, provider)

    @classmethod
    def can_auth(cls, provider):
        """
        ALways returns False, since this is only a base class.
        """
        return False

class BoltClientCredentials(AuthorizationToken):
    """
    Represents an authenticated session via the Bolt authentication scheme.

    Currently, your config needs:

    * email
    * password
    * token_url
    """
    def __init__(self, provider):
        """
        Acquires the provider token for Bolt before establishing a session.
        """
        payload = {
            "email": provider.email,
            "password": provider.password
        }
        r = requests.post(provider.token_url, params=payload,
                          verify=getattr(provider,'ssl_verify',None)
                          )
        provider.token = r.json()["token"]

        AuthorizationToken.__init__(self, provider)

    @classmethod
    def can_auth(cls, provider):
        """
        Returns True if this auth type can be used for the provider.
        """
        return all([
            provider.provider_name.lower() == "bolt",
            hasattr(provider, "email"),
            hasattr(provider, "password"),
            hasattr(provider, "token_url")
        ])


class SpinClientCredentials(AuthorizationToken):
    """
    Represents an authenticated session via the Spin authentication scheme, documented at:
    https://web.spin.pm/datafeeds

    Currently, your config needs:

    * email
    * password
    * token_url (try https://web.spin.pm/api/v1/auth_tokens)
    """
    def __init__(self, provider):
        """
        Acquires the bearer token for Spin before establishing a session.
        """
        payload = {
            "email": provider.email,
            "password": provider.password,
            "grant_type": "api"
        }
        r = requests.post(provider.token_url, params=payload,
                          verify=getattr(provider,'ssl_verify',None)
                          )
        provider.token = r.json()["jwt"]

        AuthorizationToken.__init__(self, provider)

    @classmethod
    def can_auth(cls, provider):
        """
        Returns True if this auth type can be used for the provider.
        """
        return all([
            provider.provider_name.lower() == "spin",
            hasattr(provider, "email"),
            hasattr(provider, "password"),
            hasattr(provider, "token_url")
        ])


class HelbizClientCredentials(AuthorizationToken):
    """
    Represents an authenticated session via the Helbiz authentication scheme.

    Currently, your config needs:

    * user_id
    * secret
    * token_url
    """
    def __init__(self, provider):
        """
        Acquires the provider token for Helbiz before establishing a session.
        """
        payload = {
            "user_id": provider.user_id,
            "secret": provider.secret
        }
        r = requests.post(provider.token_url, json=payload,
                          verify=getattr(provider,'ssl_verify',None)
                          )
        provider.token = r.json()["token"]

        AuthorizationToken.__init__(self, provider)

    @classmethod
    def can_auth(cls, provider):
        """
        Returns True if this auth type can be used for the provider.
        """
        return all([
            provider.provider_name.lower() == "helbiz",
            hasattr(provider, "user_id"),
            hasattr(provider, "secret"),
            hasattr(provider, "token_url")
        ])


class BitClientCredentials(AuthorizationToken):
    """
    Represents an authenticated session via the Bit authentication scheme.

    Currently, your config needs:

    * user_id
    * secret
    * token_url
    """
    def __init__(self, provider):
        """
        Acquires the provider token for Bit before establishing a session.
        """
        payload = {
            "email": provider.email,
            "password": provider.password
        }
        r = requests.post(provider.token_url, json=payload,
                          verify=getattr(provider,'ssl_verify',None)
                          )
        provider.token = r.json()["token"]
        provider.auth_type = ''       #there must be NO 'Bearer' or other prefix!!!

        AuthorizationToken.__init__(self, provider)

    @classmethod
    def can_auth(cls, provider):
        """
        Returns True if this auth type can be used for the provider.
        """
        return all([
            provider.provider_name.lower() == "bit",
            hasattr(provider, "email"),
            hasattr(provider, "password"),
            hasattr(provider, "token_url")
        ])


class BaseDottJWTCredentials(BaseJWTCredentials):

    base_protocol = 'unknown'
       
    @classmethod
    def can_auth(cls, provider):
        """
        Returns True if this auth type can be used for the provider.
        Requires the presence of the "base_protocol" attributes that must match
        the one of each derived class
        """
        return all([
            provider.provider_name.lower() == "dott",
            hasattr(provider, "private_key_id"),            
            hasattr(provider, "client_email"),
            hasattr(provider, "private_key"),            
            getattr(provider, "base_protocol", None) == cls.base_protocol,            
        ])


class DottGBFSJWTCredentials(BaseDottJWTCredentials):
  
    base_protocol = 'gbfs'
    aud = "https://gbfs.api.ridedott.com"


class DottMDSJWTCredentials(BaseDottJWTCredentials):
  
    base_protocol = 'mds'
    aud = "https://mds.api.ridedott.com"


class BasicAuthCredentials(AuthorizationToken):
    """
    Currently, your config needs:

    * username
    * password
    * token_url
    """
    def __init__(self, provider):
        """
        Acquires the bearer token before establishing a session.
        """
        payload = {
            "grant_type": "client_credentials"
        }
        r = requests.post(provider.token_url, data=payload, 
                          auth=HTTPBasicAuth(provider.username, provider.password),
                          verify=getattr(provider,'ssl_verify',None)
                          )
        provider.token = r.json()["access_token"]

        AuthorizationToken.__init__(self, provider)

    @classmethod
    def can_auth(cls, provider):
        """
        Returns True if this auth type can be used for the provider.
        """
        return all([
            hasattr(provider, "username"),
            hasattr(provider, "password"),
            hasattr(provider, "token_url")
        ])


def auth_types():
    """
    Return a list of all supported authentication types.
    """
    def all_subs(cls):
        return set(cls.__subclasses__()).union(
            [s for c in cls.__subclasses__() for s in all_subs(c)]
        ).union([cls])

    return all_subs(BaseAuthorization)
