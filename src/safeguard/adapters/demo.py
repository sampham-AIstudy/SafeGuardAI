"""Explicit demo composition; the coordinator has no demo default."""

from .core import Adapter
from .gateways.demo import DemoGateway
from .norm import normalize


def create_demo_adapter(*, clock=None) -> Adapter:
    return Adapter(gateway_factory=DemoGateway, norm=normalize, clock=clock)
