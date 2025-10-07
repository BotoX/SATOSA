import base64
import logging
import hashlib

import satosa.logging_util as lu

from .base import ResponseMicroService
from ..exception import SATOSAError

logger = logging.getLogger(__name__)


class ShibbolethComputedID(ResponseMicroService):

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.attribute = config['attribute']
        self.source = config['source']
        self.salt = config.get('salt', '')
        self.hash_algo = config.get('hash_algo', 'sha1')
        if self.hash_algo not in hashlib.algorithms_available:
            raise SATOSAError(
                "Hash algorithm not supported: {}".format(hash_algo))

    def process(self, context, data):
        state = context.state
        session_id = lu.get_session_id(state)

        value = data.attributes.get(self.source, [None])[0]
        if value is None:
            raise SATOSAError(
                "No value for attribute: {}".format(self.source))

        txt = f'{data.requester}!{value}!{self.salt}'
        hasher = hashlib.new(self.hash_algo)
        hasher.update(txt.encode('utf-8'))
        value = base64.b64encode(hasher.digest())
        value = value.decode('utf-8')
        data.attributes[self.attribute] = [value]

        logline = lu.LOG_FMT.format(id=session_id, message=f'computed "{value}" from "{txt}"')
        logger.debug(logline)

        return super().process(context, data)
