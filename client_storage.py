import os

from common import crypt

RSA_PUB_FILE = 'rsa_id.pub'
RSA_PRI_FILE = 'rsa_id'
STORAGE_PATH = 'client_storage'


def check_rsa():
    return os.path.isfile(STORAGE_PATH + '/' + RSA_PUB_FILE) and os.path.isfile(STORAGE_PATH + '/' + RSA_PRI_FILE)


def gen_rsa():
    pub, private = crypt.generate_rsa_keypair()
    pub_f = open(STORAGE_PATH + '/' + RSA_PUB_FILE, 'wb')
    private_f = open(STORAGE_PATH + '/' + RSA_PRI_FILE, 'wb')
    pub_f.write(pub)
    private_f.write(private)
    pub_f.close()
    private_f.close()


def get_rsa_pair():
    pub_f = open(STORAGE_PATH + '/' + RSA_PUB_FILE, 'rb')
    pub = pub_f.read()
    pub_f.close()
    private_f = open(STORAGE_PATH + '/' + RSA_PRI_FILE, 'rb')
    private = private_f.read()
    private_f.close()
    return pub, private


def edit_file(name, initial_data=b''):
    f = open(STORAGE_PATH + '/' + name, 'wb')
    f.write(initial_data)
    f.close()
    os.system('notepad ' + STORAGE_PATH + '/' + name)
    f = open(STORAGE_PATH + '/' + name, 'rb')
    data = f.read()
    f.close()
    os.remove(STORAGE_PATH + '/' + name)
    return data
