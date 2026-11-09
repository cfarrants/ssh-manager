"""One-shot OpenSSH password prompt bridge; secrets stay off disk and argv."""
import json
import os
import re
import socket
import sys


def main():
    prompt = sys.argv[1] if len(sys.argv)>1 else ''
    if os.environ.get('SM_ASKPASS_KIND')=='key':
        valid=bool(re.search(r'passphrase.*:\s*$',prompt,re.IGNORECASE)) and os.environ['SM_LOGIN_USER'] in prompt
    else:
        valid=bool(re.search(r'password:\s*$',prompt,re.IGNORECASE)) and os.environ['SM_LOGIN_USER']+'@' in prompt
    if not valid:raise SystemExit(1)
    with socket.create_connection(('127.0.0.1',int(os.environ['SM_ASKPASS_PORT'])),timeout=5) as conn:
        conn.sendall((os.environ['SM_ASKPASS_TOKEN']+'\n').encode())
        stream=conn.makefile('rb')
        password=json.loads(stream.readline(65536))
    print(password)


if __name__=='__main__':main()
