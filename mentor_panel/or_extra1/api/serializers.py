from rest_framework import serializers
from rest_framework_jwt.settings import api_settings
from rest_framework.exceptions import APIException
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm

from django.utils.translation import ugettext_lazy as _
from django.conf import settings

from mentee_panel.accounts.models import *
from mentor_panel.or_accounts.models import *

from mentor_panel.or_accounts.api.serializers import *
from mentor_panel.or_post.api.serializers import *

import logging
logger = logging.getLogger('accounts')

jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER

class APIException400(APIException):
    status_code = 400
