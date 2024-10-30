# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc
import warnings

from google.protobuf import empty_pb2 as google_dot_protobuf_dot_empty__pb2
import messenger_pb2 as messenger__pb2

GRPC_GENERATED_VERSION = '1.67.1'
GRPC_VERSION = grpc.__version__
_version_not_supported = False

try:
    from grpc._utilities import first_version_is_lower
    _version_not_supported = first_version_is_lower(GRPC_VERSION, GRPC_GENERATED_VERSION)
except ImportError:
    _version_not_supported = True

if _version_not_supported:
    raise RuntimeError(
        f'The grpc package installed is at version {GRPC_VERSION},'
        + f' but the generated code in messenger_pb2_grpc.py depends on'
        + f' grpcio>={GRPC_GENERATED_VERSION}.'
        + f' Please upgrade your grpc module to grpcio>={GRPC_GENERATED_VERSION}'
        + f' or downgrade your generated code using grpcio-tools<={GRPC_VERSION}.'
    )


class EncryptionServiceStub(object):
    """Missing associated documentation comment in .proto file."""

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.GetClientId = channel.unary_unary(
                '/messenger.EncryptionService/GetClientId',
                request_serializer=google_dot_protobuf_dot_empty__pb2.Empty.SerializeToString,
                response_deserializer=messenger__pb2.Id.FromString,
                _registered_method=True)
        self.GiveRsaKey = channel.unary_unary(
                '/messenger.EncryptionService/GiveRsaKey',
                request_serializer=messenger__pb2.RsaKey.SerializeToString,
                response_deserializer=google_dot_protobuf_dot_empty__pb2.Empty.FromString,
                _registered_method=True)
        self.GetRsaKey = channel.unary_unary(
                '/messenger.EncryptionService/GetRsaKey',
                request_serializer=messenger__pb2.Id.SerializeToString,
                response_deserializer=messenger__pb2.RsaKey.FromString,
                _registered_method=True)


class EncryptionServiceServicer(object):
    """Missing associated documentation comment in .proto file."""

    def GetClientId(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def GiveRsaKey(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def GetRsaKey(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_EncryptionServiceServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'GetClientId': grpc.unary_unary_rpc_method_handler(
                    servicer.GetClientId,
                    request_deserializer=google_dot_protobuf_dot_empty__pb2.Empty.FromString,
                    response_serializer=messenger__pb2.Id.SerializeToString,
            ),
            'GiveRsaKey': grpc.unary_unary_rpc_method_handler(
                    servicer.GiveRsaKey,
                    request_deserializer=messenger__pb2.RsaKey.FromString,
                    response_serializer=google_dot_protobuf_dot_empty__pb2.Empty.SerializeToString,
            ),
            'GetRsaKey': grpc.unary_unary_rpc_method_handler(
                    servicer.GetRsaKey,
                    request_deserializer=messenger__pb2.Id.FromString,
                    response_serializer=messenger__pb2.RsaKey.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'messenger.EncryptionService', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))
    server.add_registered_method_handlers('messenger.EncryptionService', rpc_method_handlers)


 # This class is part of an EXPERIMENTAL API.
class EncryptionService(object):
    """Missing associated documentation comment in .proto file."""

    @staticmethod
    def GetClientId(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/messenger.EncryptionService/GetClientId',
            google_dot_protobuf_dot_empty__pb2.Empty.SerializeToString,
            messenger__pb2.Id.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def GiveRsaKey(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/messenger.EncryptionService/GiveRsaKey',
            messenger__pb2.RsaKey.SerializeToString,
            google_dot_protobuf_dot_empty__pb2.Empty.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def GetRsaKey(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/messenger.EncryptionService/GetRsaKey',
            messenger__pb2.Id.SerializeToString,
            messenger__pb2.RsaKey.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)


class MessengerServiceStub(object):
    """Missing associated documentation comment in .proto file."""

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.SendMessage = channel.unary_unary(
                '/messenger.MessengerService/SendMessage',
                request_serializer=messenger__pb2.MessageRequest.SerializeToString,
                response_deserializer=messenger__pb2.MessageResponse.FromString,
                _registered_method=True)
        self.GetMessages = channel.unary_unary(
                '/messenger.MessengerService/GetMessages',
                request_serializer=messenger__pb2.GetMessagesRequest.SerializeToString,
                response_deserializer=messenger__pb2.GetMessagesResponse.FromString,
                _registered_method=True)


class MessengerServiceServicer(object):
    """Missing associated documentation comment in .proto file."""

    def SendMessage(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def GetMessages(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_MessengerServiceServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'SendMessage': grpc.unary_unary_rpc_method_handler(
                    servicer.SendMessage,
                    request_deserializer=messenger__pb2.MessageRequest.FromString,
                    response_serializer=messenger__pb2.MessageResponse.SerializeToString,
            ),
            'GetMessages': grpc.unary_unary_rpc_method_handler(
                    servicer.GetMessages,
                    request_deserializer=messenger__pb2.GetMessagesRequest.FromString,
                    response_serializer=messenger__pb2.GetMessagesResponse.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'messenger.MessengerService', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))
    server.add_registered_method_handlers('messenger.MessengerService', rpc_method_handlers)


 # This class is part of an EXPERIMENTAL API.
class MessengerService(object):
    """Missing associated documentation comment in .proto file."""

    @staticmethod
    def SendMessage(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/messenger.MessengerService/SendMessage',
            messenger__pb2.MessageRequest.SerializeToString,
            messenger__pb2.MessageResponse.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def GetMessages(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/messenger.MessengerService/GetMessages',
            messenger__pb2.GetMessagesRequest.SerializeToString,
            messenger__pb2.GetMessagesResponse.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)
