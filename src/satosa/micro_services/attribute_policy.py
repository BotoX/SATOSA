import logging
from pprint import pprint
import sys

import satosa.logging_util as lu
from ..context import Context
from .base import RequestMicroService, ResponseMicroService

logger = logging.getLogger(__name__)

ENTITYATTRIBUTES = 'urn:oasis:names:tc:SAML:metadata:attribute&EntityAttributes'
REGISTRATIONINFO = 'urn:oasis:names:tc:SAML:metadata:rpi&RegistrationInfo'


class AttributePolicy(RequestMicroService, ResponseMicroService):
    '''
    Module to filter Attributes by a given Policy.
    '''

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = config

    def _entity_attributes(self, md):
        res = []
        if 'extensions' in md:
            for elem in md['extensions']['extension_elements']:
                if elem['__class__'] == ENTITYATTRIBUTES:
                    for attr in elem['attribute']:
                        res.append({
                            'name': attr['name'],
                            'values': [obj['text'] for obj in attr['attribute_value']]
                        })
        return res

    def _registration_authority(self, md):
        if 'extensions' in md:
            for elem in md['extensions']['extension_elements']:
                if elem['__class__'] == REGISTRATIONINFO:
                    return elem['registration_authority']

    def process_policies(self, context, policies, md, session_id, is_request):
        allowed = set()
        eattrs = self._entity_attributes(md)
        print(eattrs)
        regauth = self._registration_authority(md)

        for policy in policies:
            pid = policy['id']
            rules = policy['rules']

            for rule in rules:
                match = False
                type = rule['type']
                if type == 'EntityAttributeExactMatch':
                    attr_name = rule['attributeName']
                    attr_value = rule['attributeValue']
                    for attr in eattrs:
                        if attr_name == attr['name'] and attr_value in attr['values']:
                            match = True

                elif type == 'RegistrationAuthority':
                    registrars = rule['registrars']
                    if regauth == registrars:
                        match = True

                elif type == 'Requester':
                    value = rule['value']
                    if md['entity_id'] == value:
                        match = True

                elif type == 'ANY':
                    match = True

                if match:
                    allowed.update(policy['allowed'])
                    if is_request and 'security' in policy:
                        security = policy['security']
                        if 'force_authn' in security:
                            context.decorate(Context.KEY_FORCE_AUTHN, "true" if security['force_authn'] else "false")
                        if 'authn_context' in security:
                            context.state[Context.KEY_TARGET_AUTHN_CONTEXT_CLASS_REF] = security['authn_context']

                    msg = f'AttributePolicy Match id={pid}'
                    logline = lu.LOG_FMT.format(id=session_id, message=msg)
                    logger.debug(logline)
        return allowed


    def process(self, context, data):
        is_request = context.target_frontend is not None # backend
        is_response = context.target_frontend is None # frontend
        session_id = lu.get_session_id(context.state)

        msg = 'Incoming data.attributes {}'.format(data.attributes)
        logline = lu.LOG_FMT.format(id=session_id, message=msg)
        logger.debug(logline)

        if is_request: # backend
            mdstore = context.get_decoration(Context.KEY_METADATA_STORE)
            md = mdstore[data.requester]
        else: # frontend
            frontend = context.state['ROUTER']
            frontend = self.router.frontends[frontend]['instance']
            md = frontend.idp.metadata[data.requester]

        policies = self.config.get('policies', [])
        allowed = self.process_policies(context, policies, md, session_id, is_request)

        if is_request: # backend
            # RequestMicroService
            data.attributes = [x for x in data.attributes if x in allowed]

        else: # frontend
            # ResponseMicroService
            for key in (data.attributes.keys() - set(allowed)):
                del data.attributes[key]

        msg = 'Returning data.attributes {}'.format(data.attributes)
        logline = lu.LOG_FMT.format(id=session_id, message=msg)
        logger.debug(logline)
        return super().process(context, data)
