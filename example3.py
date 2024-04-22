from src.ZeroKnowledge.core import ZeroKnowledge
from src.ZeroKnowledge.models import ZeroKnowledgeSignature, ZeroKnowledgeData
from queue import Queue
from threading import Thread
from src.HMAC.core import HMACClient
from src.SeedGeneration.core import SeedGenerator

DEBUG = True


def print_msg(who: str, message: str) -> None:
    if DEBUG:
        print(f'[{who}] {message}\n')


def client(client_socket: Queue, server_socket: Queue):
    # Initializing a "Zero-Knowledge" object for the client with specified curve and hash algorithm
    client_object = ZeroKnowledge.new(curve_name="secp256k1", hash_alg="sha3_256")

    # Generating a main seed for encryption
    main_seed = SeedGenerator(phrase="job").generate()

    # Defining the client's identity
    idenity = 'John'

    # Creating a signature for the client's identity
    signature = client_object.create_signature(idenity)

    # Sending the signature to the server via server_socket
    server_socket.put(signature.to_json())
    print_msg('client', f'its signature {signature.to_json()}')

    # Receiving a token from the server via client_socket
    token = client_socket.get()
    print_msg('client', f'its token {token}')

    # Generating a proof of identity using the client's identity and token
    proof = client_object.sign(idenity, token).to_json()
    print_msg('client', f'proof {proof}')

    # Sending the proof to the server via server_socket
    server_socket.put(proof)

    # Receiving a result from the server via client_socket
    result = client_socket.get()
    print_msg('client', f"{result}")

    # If the result is True, proceed with further communication steps
    if result:
        # Sending the main seed to the server
        server_socket.put(main_seed)

        # Initializing an HMACClient object for message encryption/decryption
        obj = HMACClient(algorithm="sha256", secret=main_seed, symbol_count=1)

        # Verifying an empty message received from the server
        if client_socket.get() == obj.encrypt_message(''):
            # Sending a message to the server
            message = 'hello'
            server_socket.put(obj.encrypt_message_by_chunks(message))
            print_msg('client', f'client sent message {message}')

            # Verifying if the server has decrypted the message correctly
            if client_socket.get() == obj.encrypt_message(message):
                print_msg('client', 'server has decrypt message')


def server(server_socket: Queue, client_socket: Queue):
    # Defining the server's password
    server_password = "SecretServerPassword"

    # Initializing a "Zero-Knowledge" object for the server with specified curve and hash algorithm
    server_zk = ZeroKnowledge.new(curve_name="secp384r1", hash_alg="sha3_512")

    # Creating a signature for the server's password
    server_signature: ZeroKnowledgeSignature = server_zk.create_signature(server_password)

    # Receiving the client's signature from the client via server_socket
    sig = server_socket.get()
    client_signature = ZeroKnowledgeSignature.from_json(sig)
    print_msg('server', f'its client signature {client_signature.to_json()}')

    # Initializing a "Zero-Knowledge" object for the client using client signature parameters
    client_zk = ZeroKnowledge(client_signature.params)
    print_msg('server', f'its client_zk {client_zk}')

    # Generating a token signed by the server for the client
    token = server_zk.sign(server_password, client_zk.token())
    print_msg('server', f'its token {token}')

    # Sending the token to the client via client_socket
    client_socket.put(token.to_json())

    # Receiving a proof from the client via server_socket
    proof = ZeroKnowledgeData.from_json(server_socket.get())
    print_msg('server', f'its proof {proof}')

    # Verifying the received proof
    token = ZeroKnowledgeData.from_json(proof.data)
    print_msg('server', f'its token {token}')

    # Verifying the token and the server signature
    server_verif = server_zk.verify(token, server_signature)
    print_msg('server', f'its server_verif {server_verif}')

    # If server verification fails, notify the client
    if not server_verif:
        client_socket.put(False)
    else:
        # Otherwise, verify the proof using the client signature
        client_verif = client_zk.verify(proof, client_signature, data=token)
        print_msg('server', f'its client_verif {client_verif}')
        client_socket.put(client_verif)

        # Receiving the main seed from the client via server_socket
        main_seed = server_socket.get()

        # Initializing an HMACClient object for message encryption/decryption using the received main seed
        obj = HMACClient(algorithm="sha256", secret=main_seed, symbol_count=1)

        # Sending an empty message to the client
        client_socket.put(obj.encrypt_message(''))

        # Receiving an encrypted message from the client via server_socket
        msg = server_socket.get()
        print_msg('server', f'msg encrypted {msg}')

        # Decrypting the message
        msg_raw = obj.decrypt_message_by_chunks(msg)
        print_msg('server', f'msg raw {msg_raw}')

        # Sending the decrypted message back to the client
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
