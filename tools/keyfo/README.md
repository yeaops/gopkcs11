# keyfo

一个用 Go 实现的 SSH 密钥格式转换工具，支持多种密钥类型的生成和格式转换。

## 支持的密钥类型

- **rsa** - RSA 密钥 (1024/2048/4096 位)
- **ecdsa** - ECDSA 密钥 (P-256/P-384/P-521)
- **ed25519** - Ed25519 密钥 (推荐)
- **dsa** - DSA 密钥 (已废弃，不推荐使用)
- **ecdsa-sk** / **ed25519-sk** - 安全密钥类型 (暂未实现)

## 支持的格式

- **pem** - PEM 格式 (Base64 编码，带标头)
- **der** - DER 格式 (二进制编码)
- **ssh** - SSH authorized key 格式

## 安装

```bash
go build -o keyfo
```

## 使用方法

### 生成密钥

```bash
# 生成 Ed25519 密钥对 (推荐)
./keyfo -cmd generate -type ed25519 -output my_key

# 生成 RSA 2048 位密钥对
./keyfo -cmd generate -type rsa -size 2048 -output my_rsa_key

# 生成 ECDSA P-256 密钥对
./keyfo -cmd generate -type ecdsa -size 256 -output my_ecdsa_key
```

### 格式转换

```bash
# SSH 公钥转换为 PEM 格式
./keyfo -cmd convert -input my_key.pub -from ssh -to pem -output my_key.pub.pem

# 私钥转换为 DER 格式
./keyfo -cmd convert -input my_key -from pem -to der -output my_key.der

# PEM 公钥转换为 SSH 格式
./keyfo -cmd convert -input my_key.pub.pem -from pem -to ssh -output my_key_converted.pub
```

### 帮助信息

```bash
./keyfo -help
```

## 命令行参数

### 生成密钥

- `-cmd generate` - 生成密钥命令
- `-type <type>` - 密钥类型 (rsa, ecdsa, ed25519, dsa)
- `-size <size>` - 密钥大小 (RSA: 1024/2048/4096, ECDSA: 256/384/521, DSA: 1024/2048/3072)
- `-output <file>` - 输出文件名前缀

### 转换格式

- `-cmd convert` - 转换格式命令
- `-input <file>` - 输入文件路径
- `-from <format>` - 源格式 (pem, der, ssh)
- `-to <format>` - 目标格式 (pem, der, ssh)
- `-output <file>` - 输出文件路径 (可选，默认输出到标准输出)

## 示例

### Ed25519 密钥操作流程

```bash
# 生成 Ed25519 密钥对
./keyfo -cmd generate -type ed25519 -output id_ed25519

# 查看生成的文件
ls -la id_ed25519*
# id_ed25519      (私钥，PEM 格式)
# id_ed25519.pub  (公钥，SSH 格式)

# 转成 PEM 格式
./keyfo -cmd convert -input id_ed25519.pub -from ssh -to pem -output id_ed25519.pub.pem

# 转成 DER 格式
./keyfo -cmd convert -input id_ed25519     -from pem -to der -output id_ed25519.der
./keyfo -cmd convert -input id_ed25519.pub -from ssh -to der -output id_ed25519.pub.der
```

### RSA 密钥操作示例

```bash
# 生成 RSA 4096 位密钥
./keyfo -cmd generate -type rsa -size 4096 -output id_rsa

# 转成 PEM 格式
./keyfo -cmd convert -input id_rsa.pub -from ssh -to pem -output id_rsa.pub.pem

# 转成 DER 格式
./keyfo -cmd convert -input id_rsa     -from pem -to der -output id_rsa.der
./keyfo -cmd convert -input id_rsa.pub -from ssh -to der -output id_rsa.pub.der
```

## 文件格式说明

### PEM 格式
```
-----BEGIN PRIVATE KEY-----
[Base64 编码的密钥数据]
-----END PRIVATE KEY-----
```

### SSH 格式
```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEM/yAaPUA4AwZj5ctG5YNPq...
```

### DER 格式
二进制格式，通常用于程序间交换或存储。

## 注意事项

1. **安全性**: 私钥文件权限默认设置为 600 (仅所有者可读写)
2. **兼容性**: 生成的密钥与 OpenSSH 和 OpenSSL 工具完全兼容
3. **推荐**: 对于新项目，推荐使用 Ed25519 密钥类型
4. **废弃警告**: DSA 算法已被标记为废弃，请使用更安全的替代方案

## 依赖

- Go 1.16+
- golang.org/x/crypto/ssh

## 开发

```bash
# 克隆项目
git clone <repository>
cd keyfo

# 安装依赖
go mod tidy

# 构建
go build -o keyfo

# 运行测试
go test ./...
```