import json
import socket
import ssl

def load_server_list(file_path='server_list.json'):
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def extract_tld(domain):
    return domain.strip().split('.')[-1].lower()

def find_server(tld, server_list, mode="whois"):
    for entry in server_list:
        if entry['domain'].lower() == tld:
            if mode == "rdap":
                return entry['rdap'].rstrip('/')
            else:
                return entry['whois']
    return None

def query_whois(domain, server):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        s.connect((server, 43))
        s.sendall((domain + "\r\n").encode())
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
    return response.decode(errors='ignore')

def query_rdap(domain, server):
    if '/' in server:
        host, base_path = server.split('/', 1)
        base_path = '/' + base_path.rstrip('/')
    else:
        host = server
        base_path = ''
    path = f"{base_path}/domain/{domain}"
    port = 443
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            request = f"GET {path} HTTP/1.1\r\n" \
                      f"Host: {host}\r\n" \
                      f"User-Agent: XMQuery\r\n" \
                      f"Connection: close\r\n\r\n"
            ssock.sendall(request.encode())
            response = b""
            while True:
                data = ssock.recv(4096)
                if not data:
                    break
                response += data
    header, _, body = response.partition(b"\r\n\r\n")
    return json.loads(body.decode(errors='ignore'))

def query(domain, server, mode="whois"):
    if mode == "whois":
        return query_whois(domain, server)
    elif mode == "rdap":
        return query_rdap(domain, server)
    else:
        raise ValueError("未知的查询模式 {}".format(mode))

server_list = load_server_list()
mode = input("whois/rdap:\n").strip().lower()
while True:
    domain = input("domain:\n").strip().lower()
    tld = extract_tld(domain)
    server = find_server(tld, server_list, mode)
    if not server:
        print(f"不支持 {tld} 的 {mode} 域名查询")
        continue
    try:
        result = query(domain, server, mode)
        print(result)
    except Exception as e:
        print(f"查询失败：{e}")