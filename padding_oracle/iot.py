import flask
from flask import Flask, jsonify, request
import base64
from helpers import PKCS7_unpad, CBC_decrypt

app = Flask(__name__)

import logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

key = b"\x81\xf8\xb5\xf0\xf0\xf0\xaan\x07\xbd\x81\xc59\xbc3UGV\x96J\xf3-~\xff0G\x842\x06\xed\xad\xa8"
iv = b"uf\xd1\x7f\xce\xf2'5\xfe\xf2\xd5tNs\xa2L"
ciphertext = b'\xf5\x95\t\xa1\x13\xbf\x82T\xc9\xf1x\xec\x9dO\x1a\xed1w\xfbH\xf7\xd4}\xd5\xa3\xf5\xf8\xd5<\xefy\xe7[&\x02j\x82\xd4Y\xffZdi\x82,\x04\x14Z\xc9\xa9\x82\xd3\x9c\xad{\xb4\xbe\xf0\xfdS\xa4K{d'


@app.route('/api/cache', methods=['GET'])
def cache():
    '''Returns the cached ciphertext'''
    ret_data = {
        'iv': str(base64.b64encode(iv), 'utf8'),
        'ciphertext': str(base64.b64encode(ciphertext), 'utf8')
        }
    return jsonify(ret_data)


@app.route('/api/execute', methods=['POST'])
def execute():
    '''Attempts to execute the given command. Returns True on success, False if
    command is invalid or fails'''
    if 'ciphertext' not in request.form \
            or 'iv' not in request.form:
        return respond(500)

    # Input data processing
    ciphertext = base64.b64decode(request.form['ciphertext'])
    iv = base64.b64decode(request.form['iv'])
    try:
        plaintext_padded = CBC_decrypt((iv, ciphertext), key)
    except ValueError:
        return respond(500)
    try:
        _ = PKCS7_unpad(plaintext_padded)
    except ValueError:
        return respond(500)

    return respond(200)


def respond(status_code):
    if status_code == 200:
        success = True
    else:
        success = False
    response = jsonify({
        'success': success,
    })
    response.status_code = status_code
    return response


if __name__ == '__main__':
    app.run(debug=False, port=12000)
