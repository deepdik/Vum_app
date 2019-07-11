from rest_framework import serializers
from rest_framework_jwt.settings import api_settings
from rest_framework.exceptions import APIException
#
from mentee_panel.accounts.models import *
from mentor_panel.or_accounts.models import *
from mentor_panel.or_post.models import *
from mentee_panel.review.models import *
#
import logging
logger = logging.getLogger('accounts')
#
jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
#
class APIException400(APIException):
    status_code = 400
