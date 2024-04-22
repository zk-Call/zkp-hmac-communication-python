from queue import Queue
from threading import Thread
from src.HMAC.core import HMACClient
from src.SeedGeneration.core import SeedGenerator

DEBUG = True


def print_msg(who: str, message: str) -> None:
    """
    Function to print debug messages. Prints the message only if the DEBUG flag is set to True.

    Args:
        who (str): Identifier of the message sender.
        message (str): Message to print.
    """
    if DEBUG:
        print(f'[{who}] {message}\n')


def client(client_socket: Queue, server_socket: Queue):
    """
    Function representing the client logic.

    Args:
        client_socket (Queue): Queue for data exchange between the client and server.
        server_socket (Queue): Queue for data exchange between the server and client.
    """
    # Generating the main seed
    main_seed = SeedGenerator(phrase="job").generate()

    # Creating an instance of HMACClient for encrypting messages
    obj = HMACClient(algorithm="sha256", secret=main_seed, symbol_count=1)

    # Sending the main seed to the server
    server_socket.put(main_seed)

    # Checking if the server has successfully received the seed
    if client_socket.get() == obj.encrypt_message(''):
        # If successful, send a message to the server
        message = 'hello'
        server_socket.put(obj.encrypt_message_by_chunks(message))
        print_msg('client', f'client sent message {message}')

        # Checking if the server has successfully decrypted the message
        if client_socket.get() == obj.encrypt_message(message):
            print_msg('client', 'server has decrypt message')


def server(server_socket: Queue, client_socket: Queue):
    """
    Function representing the server logic.

    Args:
        server_socket (Queue): Queue for data exchange between the server and client.
        client_socket (Queue): Queue for data exchange between the client and server.
    """
    # Receiving the main seed from the client
    main_seed = server_socket.get()

    # Creating an instance of HMACClient for encrypting messages
    obj = HMACClient(algorithm="sha256", secret=main_seed, symbol_count=1)

    # Sending an empty message to the client as acknowledgment
    client_socket.put(obj.encrypt_message(''))

    # Receiving the encrypted message from the client
    msg = server_socket.get()
    print_msg('server', f'msg encrypted {msg}')

    # Decrypting the message
    msg_raw = obj.decrypt_message_by_chunks(msg)
    print_msg('server', f'msg raw {msg_raw}')

    # Sending the encrypted message back to the client
    client_socket.put(obj.encrypt_message(msg_raw))


def main():
    """
    Main function to run the client and server threads.
    """
    client_socket, server_socket = Queue(), Queue()
    threads = []
    threads.append(Thread(target=client, args=(client_socket, server_socket)))
    threads.append(Thread(target=server, args=(server_socket, client_socket)))

    # Starting the threads
    for thread in threads:
        thread.start()

    # Joining the threads to wait for their completion
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
