from src.ZeroKnowledge.core import ZeroKnowledge
from src.ZeroKnowledge.models import ZeroKnowledgeSignature, ZeroKnowledgeData
from queue import Queue
from threading import Thread

DEBUG = True


def print_msg(who: str, message: str) -> None:
    """
    Function to print debug messages.

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
    # Creating a "Zero-Knowledge" object for the client with specified curve and hash algorithm
    client_object = ZeroKnowledge.new(curve_name="secp256k1", hash_alg="sha3_256")
    idenity = 'John'

    # Creating a signature for the client identity
    signature = client_object.create_signature(idenity)

    # Sending the signature to the server
    server_socket.put(signature.to_json())
    print_msg('client', f'its signature {signature.to_json()}')

    # Receiving token from the server
    token = client_socket.get()
    print_msg('client', f'its token {token}')

    # Generating proof using client identity and token
    proof = client_object.sign(idenity, token).to_json()
    print_msg('client', f'proof {proof}')

    # Sending proof to the server
    server_socket.put(proof)

    # Receiving result from the server
    result = client_socket.get()
    print_msg('client', f"{result}")


def server(server_socket: Queue, client_socket: Queue):
    """
    Function representing the server logic.

    Args:
        server_socket (Queue): Queue for data exchange between the server and client.
        client_socket (Queue): Queue for data exchange between the client and server.
    """
    # Setting the server password
    server_password = "SecretServerPassword"

    # Creating a "Zero-Knowledge" object for the server with specified curve and hash algorithm
    server_zk = ZeroKnowledge.new(curve_name="secp384r1", hash_alg="sha3_512")

    # Creating a signature for the server password
    server_signature: ZeroKnowledgeSignature = server_zk.create_signature(server_password)

    # Receiving client signature from the client
    sig = server_socket.get()
    client_signature = ZeroKnowledgeSignature.from_json(sig)
    print_msg('server', f'its client signature {client_signature.to_json()}')

    # Creating a "Zero-Knowledge" object for the client using client signature parameters
    client_zk = ZeroKnowledge(client_signature.params)
    print_msg('server', f'its client_zk {client_zk}')

    # Generating a token signed by the server for the client
    token = server_zk.sign(server_password, client_zk.token())
    print_msg('server', f'its token {token}')

    # Sending the token to the client
    client_socket.put(token.to_json())

    # Receiving proof from the client
    proof = ZeroKnowledgeData.from_json(server_socket.get())
    print_msg('server', f'its proof {proof}')

    # Verifying the received proof
    token = ZeroKnowledgeData.from_json(proof.data)
    print_msg('server', f'its token {token}')
    server_verif = server_zk.verify(token, server_signature)
    print_msg('server', f'its server_verif {server_verif}')

    # If server verification fails, notify the client
    if not server_verif:
        client_socket.put(False)
    else:
        # Otherwise, verify the proof using client signature
        client_verif = client_zk.verify(proof, client_signature, data=token)
        print_msg('server', f'its client_verif {client_verif}')
        client_socket.put(client_verif)


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

    # Waiting for threads to finish execution
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
