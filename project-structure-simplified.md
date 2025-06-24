# 简化的项目结构设计

为了尽量减少暴露给库使用者的包数量，保持API简洁，我们对gopkcs11库的目录结构进行了重新设计。

## 目录结构

```
gopkcs11/
├── cmd/
│   └── examples/       # 示例应用程序
├── docs/               # 文档和厂商头文件
│   └── utimaco/        # Utimaco厂商头文件
│       └── cs_pkcs11ext.h  # Utimaco PKCS#11扩展头文件
├── internal/           # 内部包，不对外暴露
│   ├── pkcs11/         # 底层PKCS#11 CGo封装
│   │   ├── constants.go  # PKCS#11常量定义
│   │   ├── types.go      # PKCS#11类型定义
│   │   └── wrapper.go    # PKCS#11 CGo包装函数
│   ├── session/        # 会话管理内部实现
│   ├── token/          # 令牌管理内部实现
│   ├── object/         # 对象管理内部实现
│   ├── mechanism/      # 加密机制内部实现
│   └── vendor/         # 厂商特定扩展内部实现
│       ├── thales/     # Thales HSM扩展
│       ├── luna/       # Luna HSM扩展
│       ├── aws/        # AWS CloudHSM扩展
│       └── utimaco/    # Utimaco HSM扩展
│           └── utimaco.go  # Utimaco特定实现
├── test/              # 集成测试
├── examples/          # 文档示例代码
├── main.go            # 主包入口
├── context.go         # 上下文对象
├── session.go         # 会话对象
├── object.go          # 密钥和对象
├── mechanism.go       # 机制类型
├── attribute.go       # 属性类型
├── error.go           # 错误处理
└── utimaco.go         # Utimaco厂商扩展(公共API)
```

## 公共API结构（对库用户暴露的内容）

```go
// 主包 gopkcs11 - 这是唯一需要导入的包
package gopkcs11

// 核心类型和接口
type Context struct { ... }      // 主要PKCS#11上下文
type Session struct { ... }      // 会话处理
type Object struct { ... }       // PKCS#11对象通用表示
type Key interface { ... }       // 密钥接口
type Mechanism struct { ... }    // 加密机制
type Attribute struct { ... }    // 属性类型

// 具体密钥类型
type PublicKey struct { ... }
type PrivateKey struct { ... }
type SecretKey struct { ... }

// 配置选项
type Config struct { ... }
type SessionConfig struct { ... }
type VendorConfig struct { ... }

// 常量和类型定义
const (
    // 会话标志
    CKF_RW_SESSION      = 0x00000002
    CKF_SERIAL_SESSION  = 0x00000004
    // ...其他常量
)

// 创建新的PKCS#11上下文
func New(path string) (*Context, error)
func NewWithConfig(config *Config) (*Context, error)

// 版本和扩展功能
func (ctx *Context) Version() (major, minor uint)
func (ctx *Context) SupportedFeatures() []string
func (ctx *Context) SupportsVendor(vendor string) bool

// 仅在主包中声明供应商扩展接口
func (ctx *Context) ThalesExtension() (*ThalesExtension, error)
func (ctx *Context) LunaExtension() (*LunaExtension, error)
func (ctx *Context) AWSExtension() (*AWSExtension, error)
func (ctx *Context) UtimacoExtension() (*UtimacoExtension, error)
```

## Utimaco扩展API

我们在主包中提供了Utimaco厂商特定的扩展API，无需导入额外的包：

```go
// UtimacoExtension提供对Utimaco HSM特定扩展的访问
type UtimacoExtension struct {
    // 内部字段
}

// 创建密钥备份
func (ext *UtimacoExtension) CreateBackup(session *Session, key Object, backupKey Object) ([]byte, error)

// 从备份导入密钥
func (ext *UtimacoExtension) ImportFromBackup(session *Session, backupKey Object, backupData []byte, template []*Attribute) (Object, error)

// 获取设备信息
func (ext *UtimacoExtension) GetDeviceInfo(slot Slot) ([]byte, error)

// Utimaco特定常量
const (
    // Utimaco特定机制
    CKM_CS_DH_PKCS_DERIVE_RAW = MechanismType(0x80000100)
    CKM_CS_ECDSA_ECIES        = MechanismType(0x80000101)
    // ...其他机制
    
    // Utimaco特定属性
    CKA_CS_COUNTER           = AttributeType(0x80000100)
    CKA_CS_LIFECYCLE         = AttributeType(0x80000101)
    // ...其他属性
    
    // Utimaco特定对象类型
    CKO_CS_SECURE_KEY_BACKUP = ObjectClass(0x80000001)
    CKO_CS_CUSTOM_DATA       = ObjectClass(0x80000002)
)
```

## 设计理念

1. **单一入口点**
   - 用户只需导入一个 `github.com/yeaops/gopkcs11` 包
   - 所有核心功能和厂商扩展直接从主包中访问
   - 避免用户需要导入多个子包

2. **隐藏实现细节**
   - 所有实现细节(包括厂商特定实现)放在 `internal/` 目录中
   - 使用Go的可见性控制保护内部API
   - 严格控制暴露给用户的API表面

3. **厂商扩展集成**
   - 厂商特定的常量、类型和函数在主包中定义
   - 厂商扩展通过主上下文对象的方法提供
   - 厂商头文件保存在docs目录中作为参考

4. **统一用法模式**
   - 所有厂商扩展遵循相同的访问模式
   - 厂商特定功能仅在支持时可用
   - 错误处理遵循Go风格

## 使用示例

### 基本用法

```go
package main

import (
    "log"
    
    "github.com/yeaops/gopkcs11"
)

func main() {
    // 初始化PKCS#11上下文
    ctx, err := gopkcs11.New("/path/to/pkcs11/library.so")
    if err != nil {
        log.Fatalf("初始化错误: %v", err)
    }
    defer ctx.Finalize()
    
    // 打开会话
    slot := uint(0) // 或通过ctx.GetSlotList获取
    session, err := ctx.OpenSession(slot, gopkcs11.CKF_SERIAL_SESSION|gopkcs11.CKF_RW_SESSION)
    if err != nil {
        log.Fatalf("打开会话失败: %v", err)
    }
    defer session.Close()
    
    // 用户登录
    err = session.Login(gopkcs11.CKU_USER, "1234")
    if err != nil {
        log.Fatalf("登录失败: %v", err)
    }
    
    // 生成密钥对
    publicTemplate := []*gopkcs11.Attribute{
        gopkcs11.NewAttribute(gopkcs11.CKA_CLASS, gopkcs11.CKO_PUBLIC_KEY),
        gopkcs11.NewAttribute(gopkcs11.CKA_KEY_TYPE, gopkcs11.CKK_RSA),
        gopkcs11.NewAttribute(gopkcs11.CKA_VERIFY, true),
        gopkcs11.NewAttribute(gopkcs11.CKA_MODULUS_BITS, 2048),
    }
    
    privateTemplate := []*gopkcs11.Attribute{
        gopkcs11.NewAttribute(gopkcs11.CKA_CLASS, gopkcs11.CKO_PRIVATE_KEY),
        gopkcs11.NewAttribute(gopkcs11.CKA_KEY_TYPE, gopkcs11.CKK_RSA),
        gopkcs11.NewAttribute(gopkcs11.CKA_SIGN, true),
        gopkcs11.NewAttribute(gopkcs11.CKA_PRIVATE, true),
    }
    
    publicKey, privateKey, err := session.GenerateKeyPair(
        gopkcs11.NewMechanism(gopkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil),
        publicTemplate,
        privateTemplate,
    )
    if err != nil {
        log.Fatalf("生成密钥对失败: %v", err)
    }
    
    // 使用密钥进行操作
    // ...
}
```

### 使用Utimaco特定扩展

```go
package main

import (
    "log"
    
    "github.com/yeaops/gopkcs11"
)

func main() {
    ctx, err := gopkcs11.New("/path/to/utimaco/library.so")
    if err != nil {
        log.Fatalf("初始化错误: %v", err)
    }
    
    // 检查是否支持Utimaco扩展
    if ctx.SupportsVendor("utimaco") {
        // 获取Utimaco扩展
        utimacoExt, err := ctx.UtimacoExtension()
        if err != nil {
            log.Fatalf("获取Utimaco扩展失败: %v", err)
        }
        
        // 打开会话
        slot := uint(0)
        session, _ := ctx.OpenSession(slot, gopkcs11.CKF_SERIAL_SESSION)
        defer session.Close()
        
        // 查找备份密钥
        backupKeys, _ := session.FindObjects([]*gopkcs11.Attribute{
            gopkcs11.NewAttribute(gopkcs11.CKA_CLASS, gopkcs11.CKO_SECRET_KEY),
            gopkcs11.NewAttribute(gopkcs11.CKA_LABEL, "backup-key"),
        })
        
        if len(backupKeys) > 0 {
            // 查找要备份的密钥
            keys, _ := session.FindObjects([]*gopkcs11.Attribute{
                gopkcs11.NewAttribute(gopkcs11.CKA_CLASS, gopkcs11.CKO_SECRET_KEY),
                gopkcs11.NewAttribute(gopkcs11.CKA_LABEL, "my-key"),
            })
            
            if len(keys) > 0 {
                // 使用Utimaco特定功能备份密钥
                backupData, err := utimacoExt.CreateBackup(session, keys[0], backupKeys[0])
                if err != nil {
                    log.Fatalf("创建备份失败: %v", err)
                }
                
                log.Printf("密钥备份成功，备份数据长度: %d bytes", len(backupData))
            }
        }
        
        // 获取设备信息
        deviceInfo, err := utimacoExt.GetDeviceInfo(ctx.GetSlots(true)[0])
        if err != nil {
            log.Fatalf("获取设备信息失败: %v", err)
        }
        
        log.Printf("设备信息: %v", deviceInfo)
    }
}