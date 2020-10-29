
"""MONGODB-SAML Authentication helpers."""

import bson
from bson.binary import Binary
from bson.son import SON
import base64
import webbrowser
from pymongo.errors import ConfigurationError, OperationFailure


"""Exceptions raised by pymongo-auth-saml."""


class PyMongoAuthSAMLError(Exception):
    """Base class for all pymongo-auth-saml exceptions."""

class _SamlSaslContext(object):
    """MONGODB-SAML20 authentication support.

    :Parameters:
      - `domain`: domain associates with idp
    """
    def __init__(self, domain):
        self._domain = domain
        self._step = 0
        self._client_nonce = None

    def step(self, server_payload):
        """Step through the SASL conversation.

        :Parameters:
          - `server_payload`: The server payload (SASL challenge). Must be a
            bytes-like object.

        :Returns:
          The response payload for the next SASL step.

        :Raises:
          :class:`~PyMongoAuthSAMLError` on error.
        """
        self._step += 1
        if self._step == 1:
            return self._first_payload()
        elif self._step == 2:
             return self._second_payload(server_payload)
        else:
            raise PyMongoAuthSAMLError('MONGODB-SAML failed: too many steps')
        pass

    def _first_payload(self):
        """Return the first SASL payload."""
        strpayload = "n,," + self._domain
        payload = Binary(strpayload.encode("utf-8"))
        return payload

    def _second_payload(self, server_payload):
        """Return the second and final SASL payload."""
        if not server_payload:
            raise PyMongoAuthSAMLError('MONGODB-SAML failed: Missing payload')

        server_payload = self.bson_decode(server_payload)
        encodedurl = server_payload["url"]
        url = base64.urlsafe_b64decode(encodedurl).decode("utf-8")
        webbrowser.open(url)
        payload = Binary(base64.standard_b64encode("=".encode("utf-8")))
        return payload


    # Dependency injection:
    def binary_type(self):
        """Return the bson.binary.Binary type."""
        raise NotImplementedError

    def bson_encode(self, doc):
        """Encode a dictionary to BSON."""
        raise NotImplementedError

    def bson_decode(self, data):
        """Decode BSON to a dictionary."""
        return bson.decode(data)


def _authenticate_saml(credentials, sock_info):
    """Authenticate using MONGODB-SAML.
    """
    ctx = _SamlSaslContext(credentials.username)
    client_payload = ctx.step(None)
    client_first = SON([('saslStart', 1),
                        ('mechanism', 'SAML20'),
                        ('payload', client_payload)])
    server_first = sock_info.command('$external', client_first)
    res = server_first
    # Limit how many times we loop to catch protocol / library issues
    for _ in range(10):
        client_payload = ctx.step(res['payload'])
        cmd = SON([('saslContinue', 1),
                   ('conversationId', server_first['conversationId']),
                   ('payload', client_payload)])
        res = sock_info.command('$external', cmd)
        if res['done']:
            # SASL complete.
            break
