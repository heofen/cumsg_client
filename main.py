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
from threading import Thread

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, async_mode='threading')
grpc_channel = None
port = int(input("Enter free port: "))

# Генерация ключей клиента
client_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
client_public_key = client_private_key.public_key()

server_public_key = None
ID = None


@app.route('/')
def index():
    """Раздает HTML-страницу для клиента"""
    return render_template('index.html')


async def grpc_client():
    """Подключение к серверу и обмен ключами"""
    global server_public_key, ID, grpc_channel
    grpc_channel = grpc.aio.insecure_channel('176.120.66.97:1488')

    encryption_stub = messenger_pb2_grpc.EncryptionServiceStub(grpc_channel)

    # Получение ID клиента от сервера
    client_id_response = await encryption_stub.GetClientId(empty_pb2.Empty())
    ID = client_id_response.id
    print(f"Received client ID: {ID}")

    # Отправка публичного ключа клиента на сервер
    public_key_bytes = client_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    await encryption_stub.GiveRsaKey(messenger_pb2.RsaKey(id=ID, rsa_public_key=public_key_bytes))  # Исправлено на rsa_public_key

    # Получение публичного ключа сервера
    server_key_response = await encryption_stub.GetRsaKey(messenger_pb2.Id(id=ID))
    server_public_key = serialization.load_pem_public_key(
        server_key_response.rsa_public_key,  # Исправлено на rsa_public_key
        backend=default_backend()
    )
    print("Received server RSA key.")

    # Запуск потока для обработки входящих сообщений
    asyncio.create_task(stream_messages())


async def stream_messages():
    """Получение и обработка входящих сообщений от сервера"""
    global ID, grpc_channel
    if not grpc_channel:
        print("GRPC Channel is not initialized")
        return

    messenger_stub = messenger_pb2_grpc.MessengerServiceStub(grpc_channel)
    try:
        # Постоянное слушание входящего потока
        async for message in messenger_stub.StreamMessages(messenger_pb2.Id(id=ID)):
            print(f"New message from {message.user}: {message.content}")
            socketio.emit('new_message', {'user': message.user, 'message': message.content})
    except grpc.aio._call.AioRpcError as e:
        print(f"Streaming error: {e.details()}")


@socketio.on('send_message')
def handle_send_message(data):
    """Обработка исходящих сообщений от клиента"""
    user = data['user']
    message = data['message']
    print(f"Received message from {user}: {message}")

    # Создаем новый цикл событий и запускаем корутину
    new_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(new_loop)

    # Запускаем корутину send_encrypted_message
    new_loop.run_until_complete(send_encrypted_message(user, message))



async def send_encrypted_message(user, message):
    """Отправка зашифрованного сообщения на сервер"""
    global server_public_key
    if server_public_key is None:
        print("Server public key is not initialized.")
        return

    try:
        encrypted_content = server_public_key.encrypt(
            message.encode(),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        print(f"Sending encrypted message from {user}: {message}")

        async with grpc.aio.insecure_channel('176.120.66.97:1488') as channel:
            messenger_stub = messenger_pb2_grpc.MessengerServiceStub(channel)
            message_request = messenger_pb2.MessageRequest(id=ID, user=user, encrypted_content=encrypted_content)
            response = await messenger_stub.SendMessage(message_request)

            # Логирование результата отправки
            print(f"Message sent. Success: {response.success}")

            if not response.success:
                print("Failed to send message.")
    except Exception as e:
        print(f"Error while sending message: {e}")


def start_grpc_client():
    asyncio.run(grpc_client())


# Вставьте этот блок перед запуском приложения в __main__
if __name__ == '__main__':
    # Создаем основной event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Передаем loop в socketio для использования в других потоках
    socketio.loop = loop

    # Запуск gRPC клиента в отдельном потоке
    grpc_thread = Thread(target=start_grpc_client)
    grpc_thread.start()

    # Запуск Flask приложения
    socketio.run(app, host='0.0.0.0', port=port, allow_unsafe_werkzeug=True)
