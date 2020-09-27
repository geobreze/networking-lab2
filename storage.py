import os

STORAGE_PATH = 'storage'


def get_for_user(user: str, file: str) -> bytes:
    f = open(STORAGE_PATH + '/' + user + '/' + file, 'rb')
    data = f.read()
    f.close()
    return data


def create_for_user(user: str, file: str, data: bytes):
    f = open(STORAGE_PATH + '/' + user + '/' + file, 'wb')
    f.write(data)
    f.close()


def delete_for_user(user: str, file: str):
    os.remove(STORAGE_PATH + '/' + user + '/' + file)


def authenticate(user: str, passwd: str = ''):
    for registered_user in os.listdir(STORAGE_PATH):
        if registered_user == user:
            return True
    return False
