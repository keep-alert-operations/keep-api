from pydantic import field_validator
from keep.models import Command, StrictModel, uuid_string
from keep.operators.policy import normalized_name


class OperatorCreate(StrictModel):
    command_id: str
    name: str
    _command = field_validator("command_id")(uuid_string)

    @field_validator("name")
    @classmethod
    def normalize(cls, value):
        return normalized_name(value)[0]


class OperatorRename(Command):
    name: str

    @field_validator("name")
    @classmethod
    def normalize(cls, value):
        return normalized_name(value)[0]
