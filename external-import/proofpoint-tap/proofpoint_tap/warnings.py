"""Offer python warnings and tools."""

import os
import typing
import warnings
from logging import getLogger
from typing import Annotated, Any, Generic, Optional, TypeVar

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    ValidationInfo,
    model_validator,
)
from pydantic_core import core_schema

T = TypeVar("T")
logger = getLogger(__name__)


class FieldWarning(Warning):
    """Base class for field warnings."""

    def __init__(
        self,
        type_: str,
        loc: tuple[str],
        msg: str,
        input_: Any,
    ) -> None:
        """Initialize the field warning."""
        self.type = type_
        self.loc = loc
        self.msg = msg
        self.input = input_

    def __str__(self) -> str:
        """Return the string representation of the field warning."""
        return f"{'.'.join(self.loc)}{os.linesep}  {self.msg} ['type':'{self.type}', 'input_value': {self.input}]"


class ValidationWarning(Warning):
    """Base class for validation warnings."""

    def __init__(self, model: type[BaseModel], warnings: list[FieldWarning]) -> None:
        """Initialize the validation warning."""
        self.model = model
        self.warnings = warnings

    @property
    def warnings_count(self) -> int:
        """Count sub warning.

        Returns:
            (int): The number of warnings.

        """
        return len(self.warnings)

    def __str__(self) -> str:
        """Return the string representation of the validation warning."""
        warnings_repr = os.linesep.join(str(warning) for warning in self.warnings)
        return (
            f"{self.warnings_count} validation warning{'s' if self.warnings_count>1 else ''} for {self.model.__name__}{os.linesep}"
            f"{warnings_repr}"
        )


def _validate_recommended_field(value: T, info: ValidationInfo) -> T:
    """Raise a FieldWarning if the recommended field is missing."""
    if value is None:
        warnings.warn(
            FieldWarning(
                type_="missing_recommended",
                loc=(str(info.field_name),),
                msg="Recommended field is missing.",
                input_=value,
            ),
            stacklevel=2,
        )
    return value


Recommended = Annotated[Optional[T], AfterValidator(_validate_recommended_field)]
# A type to only raise warning if field is missing
# Usage:
# class MyModel(BaseModel):
#     toto: Recommended[int] = Field(...)
#
# my_model = MyModel(toto=None) # will raise a warning
# try:
#     my_model = MyModel(toto="an invalid string")
# except ValidationError as e:
#     print("Validation error in my_model:", e)


class PermissiveLiteral(Generic[T]):
    """A PermissiveLiteral class type that allows values not in the Literal.

    Examples:
        >>> class MyModel(BaseModel):
        ...     b: int
        ...     c: PermissiveLiteral[Literal["foo", "bar"]]
        ...     d: Optional[PermissiveLiteral[Literal[]"toto", "titi"]]] = Field(None)
        >>> my_correct_model = MyModel(b=1, c="foo")
        >>> my_complete_correct_model = MyModel(b=1, c="foo", d="toto")
        >>> my_warning_model = MyModel(b=1, c="other")
        >>> try:
        ...     my_incorrect_model = MyModel(b=1)
        ... except ValidationError as e:
        ...     print("Validation error in my_incorrect_model:", e)

    """

    allowed_values: tuple[Any, ...]

    def __init__(self, *allowed_values: tuple[Any, ...]) -> None:
        """Initialize the PermissiveLiteral class."""
        self.allowed_values = allowed_values

    @classmethod
    def __class_getitem__(cls, literal_type: type) -> type["PermissiveLiteral[T]"]:
        """Allow subscripting like PermissiveLiteral['foo', 'bar']."""
        allowed_values = typing.get_args(literal_type)

        # Note: we get a NewPermissiveLiteral class that is a subclass of PermissiveLiteral
        # to avoid overwriting the allowed_values class variable of the PermissiveLiteral class.
        # Otherwise, each time we would create a new PermissiveLiteral class, we would overwrite the allowed_values of the type.
        # for instance, without the NewPermissiveLiteral class:
        # MyLiteral1 = PermissiveLiteral[Literal["foo", "bar"]]
        # MyLiteral2 = PermissiveLiteral[Literal["toto", "titi"]]
        # print(MyLiteral1.allowed_values) # outputs ('toto', 'titi')
        class NewPermissiveLiteral(PermissiveLiteral):  # type: ignore[type-arg]
            def __init__(self, *args: tuple[Any], **kwargs: dict[Any, Any]) -> None:
                super().__init__(*allowed_values)

        NewPermissiveLiteral.allowed_values = allowed_values
        return NewPermissiveLiteral

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source: Any, handler: Any
    ) -> core_schema.CoreSchema:
        """Return the Pydantic core schema for the PermissiveLiteral class. Called by Pydantic."""

        def validate(value: Any) -> Any:
            if value not in cls.allowed_values:
                warnings.warn(
                    FieldWarning(
                        type_="permissive_literal_warn",
                        loc=("PermissiveLiteral",),
                        msg=f"Value '{value}' is not in the allowed values {cls.allowed_values}. Validation will pass.",
                        input_=value,
                    ),
                    stacklevel=1,
                )
            return value

        return core_schema.no_info_plain_validator_function(validate)


class PermissiveBaseModel(BaseModel):
    """Base model that allows extra fields but warns and aggregate all FieldWarning into a ValidationWarning.

    Notes:
        The unhandled data are removed from the model to avoid memory consumption but a warning is raised.

    Examples:
        >>> class MyModel(PermissiveBaseModel):
        ...     foo: str = Field(...)
        ...     bar: Recommended[int]
        ...     baz: Optional[PermissiveLiteral[Literal["a", "b", "c"]]] = Field(None)
        >>> my_model_ok = MyModel(foo='hello', bar=123)
        >>> my_model_warning = MyModel(foo='hello',baz="d", other=2)
        >>> try:
        ...     my_model_error = MyModel(foo=hello, bar='hello')
        ... except ValidationError as e:
        ...     print("Validation error in my_model_error:", e)

    """

    model_config = ConfigDict(extra="allow")

    def __init__(self, *args: tuple[Any, ...], **kwargs: dict[str, Any]) -> None:
        """Catch all emmited FieldWarning instances and aggregate them into a single ValidationWarning."""
        # Note:  we need to explicitly sepecify action="default" else category is not used.
        # (Found out from source code of warnings.catch_warnings)
        # Not that category should be in a specific based category and you cannot filter on a subclass Warning.
        # that is why we later use a type check.
        with warnings.catch_warnings(
            record=True, action="default", category=Warning
        ) as caugth_warning_messages:
            super().__init__(*args, **kwargs)
        if caugth_warning_messages:  #  "WarningMessage"
            warnings_list: list[FieldWarning] = []
            for warning in caugth_warning_messages:
                if isinstance(warning.message, FieldWarning):
                    warnings_list.append(warning.message)
            if warnings_list:
                warnings.warn(
                    ValidationWarning(model=type(self), warnings=warnings_list),
                    stacklevel=2,
                )

    @model_validator(mode="after")
    def check_extra_fields(
        self: "PermissiveBaseModel",
    ) -> "PermissiveBaseModel":
        """Check for extra fields, after model validation."""
        model_extra = self.model_extra
        if model_extra is not None and len(model_extra) > 0:
            logger.warning(f"Extra fields in {self.__class__.__name__}: {model_extra}")
            for key, value in model_extra.items():
                # emit a warning for each extra field
                warnings.warn(
                    FieldWarning(
                        type_="extra_warn",
                        loc=(key,),
                        msg="Unexpected extra field",
                        input_=value,
                    ),
                    stacklevel=2,
                )
            # finally remove the extra data from the model
            for key in list(model_extra.keys()):
                # Note: we need to do this outside the above loop to avoid
                # otherwise we would get a RuntimeError because the dictionary changed size
                # during iteration.
                delattr(self, key)
        return self
