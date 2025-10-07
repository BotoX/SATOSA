import logging

import satosa.logging_util as lu

from .base import ResponseMicroService
from ..exception import SATOSAError

logger = logging.getLogger(__name__)


class EduIDEntitlement(ResponseMicroService):

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.attribute = config['attribute']
        self.source = config['source']

    def process(self, context, data):
        state = context.state
        session_id = lu.get_session_id(state)

        values = data.attributes.get(self.source, [None])
        if not values:
            raise SATOSAError(
                "No value for attribute: {}".format(self.source))

        ret = []
        if 'member@uni-graz.at' in values:
            ret.append('urn:mace:terena.org:tcs:personal-user')
            ret.append('urn:mace:dir:entitlement:common-lib-terms')

        data.attributes[self.attribute] = ret

        return super().process(context, data)
