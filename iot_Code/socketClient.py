import socket, json, time
import CryptoHelper, Helper, Properties


def connect_to_server():
    # Create a socket object
    s = socket.socket()

    # Define the port on which you want to connect
    port = 20003

    # connect to the server on local computer
    s.connect(('127.0.0.1', port))

    print("Client Socket: ", s.getsockname())
    print("Server Socket: ", s.getpeername())

    return s


def send_to_server(s, j):
    """
    send messages
    :param s: socket
    :param j: message
    :return:
    """
    # s.send(b"random messages")
    Properties.START_TIME = time.time()

    s.send(j.encode())


def receive_from_server(s):
    """
    receive data from the server
    :param s: socket
    :return:
    """
    msg = s.recv(1024)
    if(len(msg) > 0):
        print("*** Received: ", msg)
        # msg_json = json.loads(msg)
        # print("*** Received (json): ", msg_json)
        CryptoHelper.aes_gcm_decryption_with_tag(msg)


def close_connection(s):
    # close the connection
    s.close()


def test(s, j):
    print("JSON_: ", j)
