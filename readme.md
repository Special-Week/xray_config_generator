# xray config生成脚本，可根据v2ray格式的多个节点，生成xray的多出口多入口配置文件，个人主要于爬虫使用

## 用法
### 0. 安装python3(略)
### 1. 将v2ray格式的节点复制到`node.txt`文件中!
大概长这样
![](./readmeImg/image.png)
### 2. 运行脚本
```shell
python __main__.py
```
### 3. 生成的配置文件在同级目录下的`config.json`中
### 4. 下载对应平台的[xray-core](https://github.com/xtls/Xray-core/releases)
### 5. 将config.json移动到xray同级目录
### 6. xray启动



## 注：
- inbounds类型为http代理
- 支持的节点类型：shadowsocks, vmess, vless, wireguard, trojan
- 成功生成配置文件后，控制台会打印xray config.json已生成，端口起始位置: xxxxx, 共xx个节点，比如输出了“xray config.json已生成，端口起始位置: 40001, 共10个节点”
- 生成并启动xray后，通过http代理来使用结点, 如下图
![](./readmeImg/image2.png)