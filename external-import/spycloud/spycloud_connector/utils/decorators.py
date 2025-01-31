from typing import TYPE_CHECKING, Callable

from pydantic import ValidationError

if TYPE_CHECKING:
    from spycloud_connector.services.converter_to_stix import ConverterToStix


def validate_return_value(validate_function: Callable) -> Callable:
    """
    Validate config variable parsed value by passing it to `validate_function`.
    :param validate_function: A function taking value of config variable as only arg and returning `True` if valid, otherwise `False`.
    :return: Validate decorator
    """

    def wrapped_decorator(decorated_function: Callable):
        def decorator(*args, **kwargs):
            result = decorated_function(*args, **kwargs)

            valid_value = validate_function(result)
            if not valid_value:
                raise ValueError(
                    f"Invalid value for '{decorated_function.__name__}' config variable."
                )

            return result

        return decorator

    return wrapped_decorator


def handle_pydantic_validation_error(decorated_function: Callable):
    """
    Handle Pydantic's ValidationErrors during models instanciation.
    :param decorated_function: A ConverterToStix instance method instanciating a Pydantic model.
    :return: Decorator
    """

    def decorator(self: "ConverterToStix", *args, **kwargs):
        try:
            return decorated_function(self, *args, **kwargs)
        except ValidationError as e:
            self.helper.connector_logger.error(str(e))
            return None

    return decorator
