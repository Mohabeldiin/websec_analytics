"""contains only what we will use from the validators module

    The validators are used to validate the input of the user
    and to check if the input is valid or not.

    To see the full module refer to https://github.com/kvesteri/validators/tree/master/validators"""
from .email import email
from .url import url
from .utils import ValidationFailure, validator

__all__ = ('url', 'email', 'ValidationFailure', 'validator')

__version__ = '0.18.2'
