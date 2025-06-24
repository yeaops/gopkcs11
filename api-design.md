# PKCS#11库API设计原则

本文档说明了gopkcs11库API设计的关键原则和理念，重点关注如何创建一个易于使用且功能强大的接口。

## API设计核心原则

### 1. 最小公共API表面积

我们的设计目标是将公开的API表面积降到最低，同时保持足够的灵活性和功能性。这种方法有以下好处:

- **降低认知负担**: 用户只需了解一个主包而不是多个子包
- **简化依赖管理**: 单一包导入点使依赖更清晰
- **版本控制更轻松**: 单一包的版本管理比多包系统更简单
- **更好的封装**: 实现细节被隐藏，只有设计良好的接口才会暴露

### 2. 对象导向与接口驱动设计

API设计采用对象导向方法，但充分利用Go的接口功能:

```go
// 核心会话接口
type Session interface {
    // 基本操作
    Close() error
    Login(userType uint, pin string) error
    Logout() error
    
    // 密钥操作
    GenerateKey(mech *Mechanism, template []*Attribute) (Key, error)
    GenerateKeyPair(mech *Mechanism, pubTemplate, privTemplate []*Attribute) (PublicKey, PrivateKey, error)
    FindObjects(template []*Attribute) ([]Object, error)
    
    // 加密操作
    Encrypt(mech *Mechanism, key Key, data []byte) ([]byte, error)
    Decrypt(mech *Mechanism, key Key, ciphertext []byte) ([]byte, error)
    Sign(mech *Mechanism, key PrivateKey, data []byte) ([]byte, error)
    Verify(mech *Mechanism, key PublicKey, data, signature []byte) (bool, error)
    
    // 其他操作...
}

// 密钥接口继承体系
type Key interface {
    Handle() ObjectHandle
    Attributes() []*Attribute
    GetAttribute(attributeType uint) (*Attribute, error)
}

type PublicKey interface {
    Key
    // 公钥特定方法
}

type PrivateKey interface {
    Key
    // 私钥特定方法
}

type SecretKey interface {
    Key
    // 对称密钥特定方法
}
```

### 3. 错误处理标准化

提供详细且一致的错误处理:

```go
// 标准错误类型
type Error struct {
    Code      uint   // PKCS#11错误码
    Message   string // 错误描述
    Operation string // 引发错误的操作
    Cause     error  // 原始错误（如适用）
}

// 常见错误检查辅助函数
func IsTokenNotPresent(err error) bool
func IsUserNotLoggedIn(err error) bool
func IsSessionHandleInvalid(err error) bool
```

### 4. 内置版本兼容性

在API中直接处理版本差异，而不是让用户处理:

```go
// 版本信息作为Context的一部分提供
func (ctx *Context) Version() (major, minor uint)
func (ctx *Context) SupportedFeatures() []string
func (ctx *Context) SupportsFeature(feature string) bool

// 当使用v3.0特定功能时
if ctx.SupportsFeature("multipleAuth") {
    // 使用v3.0登录
    err = session.LoginUser(gopkcs11.CKU_USER, "username", "password")
} else {
    // 回退到标准登录
    err = session.Login(gopkcs11.CKU_USER, "password")
}
```

### 5. 上下文管理与资源清理

促进良好的资源管理实践:

```go
// 上下文创建
ctx, err := gopkcs11.New("/path/to/library.so") 
if err != nil {
    return err
}
defer ctx.Finalize() // 确保资源被释放

// 会话管理
session, err := ctx.OpenSession(slotID, flags)
if err != nil {
    return err
}
defer session.Close() // 确保会话被关闭
```

## 厂商扩展设计

我们的设计允许访问厂商特定功能，同时保持主API的清晰度:

```go
// 检查厂商扩展支持
if ctx.SupportsVendor("thales") {
    // 获取特定厂商扩展
    thales := ctx.ThalesExtension()
    
    // 使用厂商特定功能
    result, err := thales.SpecialFunction(session, param1, param2)
    // ...
}
```

厂商扩展遵循一致的模式，但允许特定于厂商的功能:

```go
// Thales扩展接口
type ThalesExtension interface {
    // 厂商标识
    Vendor() string
    Version() string
    
    // 厂商特定功能
    GenerateCryptogram(session Session, key Key, data []byte) ([]byte, error)
    // ... 其他Thales特定方法
}
```

## 代码示例

### 基本用法示例

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/yeaops/gopkcs11"
)

func main() {
    // 初始化库
    ctx, err := gopkcs11.New("/usr/lib/softhsm/libsofthsm2.so")
    if err != nil {
        log.Fatalf("初始化失败: %v", err)
    }
    defer ctx.Finalize()
    
    // 获取可用插槽
    slots, err := ctx.GetSlotList(true)
    if err != nil {
        log.Fatalf("获取插槽列表失败: %v", err)
    }
    
    if len(slots) == 0 {
        log.Fatal("没有找到插槽")
    }
    
    // 打开会话
    session, err := ctx.OpenSession(slots[0], gopkcs11.CKF_SERIAL_SESSION|gopkcs11.CKF_RW_SESSION)
    if err != nil {
        log.Fatalf("打开会话失败: %v", err)
    }
    defer session.Close()
    
    // 用户登录
    err = session.Login(gopkcs11.CKU_USER, "1234")
    if err != nil {
        log.Fatalf("登录失败: %v", err)
    }
    
    // 生成随机数
    random, err := session.GenerateRandom(16)
    if err != nil {
        log.Fatalf("生成随机数失败: %v", err)
    }
    
    fmt.Printf("随机数: %x\n", random)
}
```

### 实现标准Go加密接口

```go
package main

import (
    "crypto"
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "io/ioutil"
    "log"
    
    "github.com/yeaops/gopkcs11"
)

func main() {
    // 初始化PKCS#11
    ctx, err := gopkcs11.New("/path/to/pkcs11/lib.so")
    if err != nil {
        log.Fatalf("初始化失败: %v", err)
    }
    defer ctx.Finalize()
    
    // 创建会话
    slots, _ := ctx.GetSlotList(true)
    session, err := ctx.OpenSession(slots[0], gopkcs11.CKF_SERIAL_SESSION)
    if err != nil {
        log.Fatalf("打开会话失败: %v", err)
    }
    defer session.Close()
    
    // 登录
    session.Login(gopkcs11.CKU_USER, "1234")
    
    // 查找私钥
    privateKeys, err := session.FindObjects([]*gopkcs11.Attribute{
        gopkcs11.NewAttribute(gopkcs11.CKA_CLASS, gopkcs11.CKO_PRIVATE_KEY),
        gopkcs11.NewAttribute(gopkcs11.CKA_LABEL, "my-signing-key"),
    })
    if err != nil || len(privateKeys) == 0 {
        log.Fatalf("找不到签名密钥: %v", err)
    }
    
    // 获取HSM签名者实现crypto.Signer接口
    signer := ctx.NewSigner(session, privateKeys[0].(gopkcs11.PrivateKey))
    
    // 读取要签名的数据
    data, _ := ioutil.ReadFile("document.txt")
    
    // 计算数据哈希
    hashed := crypto.SHA256.New()
    hashed.Write(data)
    digest := hashed.Sum(nil)
    
    // 使用HSM中的密钥签名
    signature, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
    if err != nil {
        log.Fatalf("签名失败: %v", err)
    }
    
    fmt.Printf("签名: %x\n", signature)
}
```

## 最佳实践总结

1. **单一入口点**: 用户只需导入一个包。

2. **隐藏实现细节**: 使用internal目录和Go的可见性规则。

3. **直观命名**: 使用明确且一致的命名约定。

4. **安全默认值**: 提供安全的默认配置。

5. **资源管理**: 明确的资源生命周期和清理。

6. **错误处理**: 提供详细且有用的错误消息。

7. **文档完善**: 每个公共API都有明确的文档和例子。

8. **Go惯用法**: 遵循Go的标准库和最佳实践。