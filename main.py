import asyncio
import grpc
import messenger_pb2
import messenger_pb2_grpc
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from google.protobuf import empty_pb2
from threading import Lock

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)
lock = Lock()

client_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
client_public_key = client_private_key.public_key()

server_public_key = None
ID = None


async def grpc_client():
    global server_public_key, ID
    async with grpc.aio.insecure_channel('176.120.66.97:1488') as channel:
        print("Connecting...")
        encryption_stub = messenger_pb2_grpc.EncryptionServiceStub(channel)

        client_id_response = await encryption_stub.GetClientId(empty_pb2.Empty())
        ID = client_id_response.id
        print(f"Received client ID: {ID}")

        public_key_bytes = client_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        await encryption_stub.GiveRsaKey(messenger_pb2.RsaKey(id=ID, RsaPublicKey=public_key_bytes))

        server_key_response = await encryption_stub.GetRsaKey(messenger_pb2.Id(id=ID))
        server_public_key = serialization.load_pem_public_key(
            server_key_response.RsaPublicKey,
            backend=default_backend()
        )
        print("Received server RSA key.")

        asyncio.create_task(stream_messages(channel))


async def stream_messages(channel):
    messenger_stub = messenger_pb2_grpc.MessengerServiceStub(channel)
    async for message in messenger_stub.StreamMessages(messenger_pb2.Id(id=ID)):
        decrypted_message = client_private_key.decrypt(
            message.content,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        ).decode()
        socketio.emit('new_message', {'user': message.user, 'message': decrypted_message})


@socketio.on('send_message')
def handle_send_message(data):
    user = data['user']
    message = data['message']
    asyncio.run(send_encrypted_message(user, message))


async def send_encrypted_message(user, message):
    encrypted_content = server_public_key.encrypt(
        message.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    async with grpc.aio.insecure_channel('176.120.66.97:1488') as channel:
        messenger_stub = messenger_pb2_grpc.MessengerServiceStub(channel)
        message_request = messenger_pb2.MessageRequest(id=ID, user=user, encrypted_content=encrypted_content)
        await messenger_stub.SendMessage(message_request)


@app.route('/')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    asyncio.run(grpc_client())
    socketio.run(app, host='0.0.0.0', port=5003, allow_unsafe_werkzeug=True)
