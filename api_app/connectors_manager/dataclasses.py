# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import dataclasses
import typing

from api_app.core.dataclasses import AbstractConfig
from .serializers import ConnectorConfigSerializer


__all__ = ["ConnectorConfig"]


@dataclasses.dataclass
class ConnectorConfig(AbstractConfig):

    serializer_class = ConnectorConfigSerializer

    def get_full_import_path(self) -> str:
        return f"api_app.connectors_manager.connectors.{self.python_module}"

    @classmethod
    def get(cls, connector_name: str) -> typing.Optional["ConnectorConfig"]:
        """
        Returns config dataclass by connector_name if found, else None
        """
        all_configs = cls.serializer_class.read_and_verify_config()
        config_dict = all_configs.get(connector_name, None)
        if config_dict is None:
            return None  # not found
        return cls.from_dict(config_dict)

    @classmethod
    def from_dict(cls, data: dict) -> "ConnectorConfig":
        return cls(**data)

    @classmethod
    def all(cls) -> typing.Dict[str, "ConnectorConfig"]:
        return {
            name: cls.from_dict(attrs)
            for name, attrs in cls.serializer_class.read_and_verify_config().items()
        }