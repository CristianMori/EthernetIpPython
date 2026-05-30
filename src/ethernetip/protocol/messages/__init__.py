"""Typed encapsulation message classes + dispatch manager.

Mirrors the C# IMessage / IMessageManager paradigm: instead of passing
raw (header, payload) tuples through the adapter's handler tree, each
encapsulation command parses into its own typed class with named fields.
Handlers consume the typed object directly — CPF parsing and field
extraction live in the message class, not in the adapter.
"""
from .imessage import IMessage, ISerializableMessage
from .encapsulation_message import EncapsulationMessage
from .nop_message import NopMessage
from .register_session_message import RegisterSessionMessage
from .unregister_session_message import UnregisterSessionMessage
from .list_identity_message import ListIdentityMessage
from .list_services_message import ListServicesMessage
from .send_rr_data_message import SendRRDataMessage
from .send_unit_data_message import SendUnitDataMessage
from .encapsulation_message_manager import EncapsulationMessageManager

__all__ = [
    'IMessage', 'ISerializableMessage',
    'EncapsulationMessage',
    'NopMessage', 'RegisterSessionMessage', 'UnregisterSessionMessage',
    'ListIdentityMessage', 'ListServicesMessage',
    'SendRRDataMessage', 'SendUnitDataMessage',
    'EncapsulationMessageManager',
]
