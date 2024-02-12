import base64
import json
import socket
from pathlib import Path
from typing import Dict, List
from urllib.parse import unquote

CURRENT_PATH = Path(__file__).parent
node_count = 0
port_start = 40000


def vless_node_handle(node: str) -> Dict:
    global node_count
    node_count += 1
    node = node.replace("vless://", "")
    uuid = node.split("@")[0]
    node = node.replace(f"{uuid}@", "")
    address = node.split(":")[0]
    node = node.replace(f"{address}:", "")
    port = node.split("?")[0]
    node = node.replace(f"{port}?", "")
    remarks = node.split("#")[-1]
    node = node.replace(f"#{remarks}", "")
    remarks = unquote(remarks).strip()
    param = node.split("&")
    param_dict = {}
    for item in param:
        key, value = item.split("=")
        param_dict[key] = value
    encryption = param_dict.get("encryption")
    flow = param_dict.get("flow")
    security = param_dict.get("security")
    sni = param_dict.get("sni")
    fingerprint = param_dict.get("fp")
    type_ = param_dict.get("type")

    if security == "reality":
        pbk = param_dict.get("pbk")
        sid = param_dict.get("sid")
        streamSettings = {
            "network": type_,
            "security": security,
            "realitySettings": {
                "serverName": sni,
                "fingerprint": fingerprint,
                "show": False,
                "publicKey": pbk,
                "shortId": sid,
                "spiderX": "",
            },
        }
    elif security == "tls":
        streamSettings = {
            "network": type_,
            "security": security,
            "tlsSettings": {
                "allowInsecure": False,
                "serverName": sni,
                "fingerprint": fingerprint,
                "show": False,
            },
        }
    else:
        streamSettings = {}

    return {
        "tag": f"out_bound_{node_count}_{remarks}",
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": address,
                    "port": int(port),
                    "users": [
                        {
                            "id": uuid,
                            "aLterId": 0,
                            "security": "auto",
                            "encryption": encryption,
                            "flow": flow,
                        }
                    ],
                }
            ]
        },
        "streamSettings": streamSettings,
    }


def trojan_node_handle(node: str) -> Dict:
    global node_count
    node_count += 1
    node = node.replace("trojan://", "")
    password = node.split("@")[0]
    node = node.replace(f"{password}@", "")
    address = node.split(":")[0]
    node = node.replace(f"{address}:", "")
    port = node.split("?")[0]
    node = node.replace(f"{port}?", "")
    remarks = node.split("#")[-1]
    node = node.replace(f"#{remarks}", "")
    remarks = unquote(remarks).strip()
    param = node.split("&")
    param_dict = {}
    for item in param:
        key, value = item.split("=")
        param_dict[key] = value
    security = param_dict.get("security")
    sni = param_dict.get("sni")
    type_ = param_dict.get("type")
    return {
        "tag": f"out_bound_{node_count}_{remarks}",
        "protocol": "trojan",
        "settings": {
            "servers": [
                {
                    "address": address,
                    "password": password,
                    "port": int(port),
                }
            ]
        },
        "streamSettings": {
            "network": type_,
            "security": security,
            "tlsSettings": {
                "allowInsecure": False,
                "serverName": sni,
            },
        },
    }


def ss_node_handle(node: str) -> Dict:
    global node_count
    node_count += 1
    node = node.replace("ss://", "")
    remarks = node.split("#")[-1]
    node = node.replace(f"#{remarks}", "")
    remarks = unquote(remarks).strip()
    port = node.split(":")[-1]
    node = node.replace(f":{port}", "")
    address = node.split("@")[-1]
    node = node.replace(f"@{address}", "")
    node = base64.b64decode(node).decode()
    method, password = node.split(":")
    return {
        "tag": f"out_bound_{node_count}_{remarks}",
        "protocol": "shadowsocks",
        "settings": {
            "servers": [
                {
                    "address": address,
                    "method": method,
                    "password": password,
                    "port": int(port),
                }
            ]
        },
        "streamSettings": {
            "network": "tcp",
        },
    }


def wireguard_node_handle(node: str) -> Dict:
    global node_count
    node_count += 1
    node = node.replace("wireguard://", "")
    node_info = (base64.b64decode(node).decode()).split("\n")
    data = {}
    for item in node_info:
        if " = " in item:
            key, value = item.split(" = ")
            data[key] = value

    private_key = data["PrivateKey"]
    address = [item.strip() for item in (data["Address"]).split(",")]
    public_key = data["PublicKey"]
    endpoint = data["Endpoint"]
    return {
        "tag": f"out_bound_{node_count}_wireguard",
        "protocol": "wireguard",
        "settings": {
            "secretKey": private_key,
            "address": address,
            "peers": [
                {
                    "publicKey": public_key,
                    "preSharedKey": "",
                    "keepAlive": 25,
                    "allowedIPs": ["0.0.0.0/0"],
                    "endpoint": endpoint,
                }
            ],
            "mtu": 1280,
        },
    }


def vmess_node_handle(node: str) -> Dict:
    global node_count
    node_count += 1
    node = node.replace("vmess://", "")
    node = base64.b64decode(node).decode()
    node_info: Dict = json.loads(node)
    remarks = node_info["ps"]
    return {
        "tag": f"out_bound_{node_count}_{remarks}",
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": node_info["add"],
                    "port": int(node_info["port"]),
                    "users": [
                        {
                            "id": node_info["id"],
                            "alterId": int(node_info["aid"]),
                            "security": node_info["scy"],
                        }
                    ],
                }
            ]
        },
        "streamSettings": {"network": node_info["net"]},
    }


def read_node() -> List[Dict]:
    outbounds: List[Dict] = []
    with open(CURRENT_PATH / "node.txt", "r", encoding="utf-8") as f:
        for item in f:
            if item.startswith("vless://"):
                outbounds.append(vless_node_handle(item))
            elif item.startswith("trojan://"):
                outbounds.append(trojan_node_handle(item))
            elif item.startswith("ss://"):
                outbounds.append(ss_node_handle(item))
            elif item.startswith("wireguard://"):
                outbounds.append(wireguard_node_handle(item))
            elif item.startswith("vmess://"):
                outbounds.append(vmess_node_handle(item))
    if not outbounds:
        print("未读取到任何节点信息")
        exit(1)
    return outbounds


def set_inbounds(outbounds: List[Dict]) -> List[Dict]:
    global port_start
    inbounds = []
    port_start = find_free_ports(40000, len(outbounds))
    port = port_start
    for port, item in enumerate(outbounds, start=port):
        tag: str = item["tag"]
        inbounds.append(
            {
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "http",
                "settings": {"auth": "noauth", "udp": False, "userLevel": 0},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
                "tag": tag.replace("out_bound", "in_bound"),
            }
        )
    return inbounds


def set_routing(in_bound) -> Dict:
    rules = []
    for item in in_bound:
        tag: str = item["tag"]
        rules.append(
            {
                "type": "field",
                "inboundTag": tag,
                "outboundTag": tag.replace("in_bound", "out_bound"),
            }
        )
    return {"rules": rules}


def find_free_ports(start_range, num_ports=1) -> int:
    def port_is_free(port) -> bool:
        temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            temp_socket.bind(("localhost", port))
            return True
        except socket.error:
            return False
        finally:
            temp_socket.close()

    count = 0
    port = start_range
    while count < num_ports:
        if port_is_free(port):
            count += 1
        else:
            count = 0
        port += 1
    return port - num_ports


if __name__ == "__main__":
    outbounds = read_node()
    inbounds = set_inbounds(outbounds)
    routing = set_routing(inbounds)
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": routing,
    }
    with open(CURRENT_PATH / "config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4, ensure_ascii=False)
    print(
        f"xray config.json已生成，端口起始位置: {port_start}, 共{len(outbounds)}个节点"
    )
