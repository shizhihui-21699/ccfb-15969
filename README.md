# unsafe-lint

基于语法树和简化控制流分析的 Rust 静态检查器，针对两类反复出现的 `unsafe`
内存安全问题：

1. **展开期双重释放（`unwind_double_free`）**——在 `unsafe` 块里先用裸指针
   复制出一个值，写回之前调用了可能恐慌的代码；一旦闭包/泛型方法恐慌，栈
   展开会让同一个值被局部变量和原始槽位各释放一次。
2. **无约束的 `unsafe impl Send/Sync`（`send_sync_without_bound`）**——给
   泛型容器手写自动 trait 实现，却没有对出现在自身类型中的类型参数施加
   `T: Send` / `T: Sync` 约束，导致用户可以用 `Rc<RefCell<_>>` 等非线程
   安全类型实例化出 `Send`/`Sync`。

## 构建与使用

```bash
cargo build --release

# 检查单个文件或整个 crate 目录（递归跳过 target/ 与隐藏目录）
./target/release/unsafe-lint path/to/file.rs
./target/release/unsafe-lint path/to/crate

# 机器可读输出
./target/release/unsafe-lint --json path/to/crate

# 抑制某条 lint（也可以在源码里写 #[allow(...)] / #![allow(...)]）
./target/release/unsafe-lint --allow unwind_double_free path/to/crate
```

有发现时退出码为 `1`，无发现为 `0`，参数错误为 `2`。

## 检查器一：展开期双重释放

### 分析模型

检查器在每个 `unsafe fn` 与 `unsafe { ... }` 块内维护一组"所有权重复
窗口"（interval），每条记录包含：

- 内存槽位的规范化签名（`*p`、`(*p).field`），
- 持有复制值的局部绑定名，
- 开窗语句的 span 与描述，
- 块嵌套深度，
- 是否处于受保护状态。

**开窗**（所有权被暂时复制）的识别：

- `ptr::read` / `ptr::read_volatile` / `ptr::read_unaligned` 调用，
- 裸指针方法 `p.read()` / `p.read_volatile()`，
- 对已知裸指针的解引用复制 `let v = *p;`，
- 字段复制 `let f = (*p).field;`。

裸指针的来源包括：函数参数中的 `*const T`/`*mut T`、显式类型标注的
`let`、`addr_of!(_)`、`x as *const _`、`as_ptr()`/`as_mut_ptr()` 等。

**关窗**（槽位被修复）的识别：

- `ptr::write*` / `ptr::drop_in_place` 写回匹配槽位，
- 裸指针方法 `p.write(v)` / `p.replace(..)` 等，
- 赋值 `*p = v`、`(*p).f = v`（槽位签名做去解引用/去括号规范化后
  按前缀重叠匹配），
- `mem::forget(v)` 消耗掉复制出的所有者，
- `mem::replace` / `ptr::replace` 原子地完成移动与写回。

### 控制流

采用线性语句流 + 递归下降的简化控制流分析：`if`/`match`/循环/闭包分别
递归处理，窗口按块深度在块退出时裁剪。窗口在某个分支内闭合时按保守
策略处理——只要存在一条路径让恐慌发生在修复之前，就报告。块结束时仍
未修复的非保护窗口直接报告（必然双重释放）。`return`/`break`/`continue`
/`?` 提前离开作用域时同样报告。

### 恐慌判定（保守方向）

任何不在白名单内的调用都被视为可能展开。白名单只包含不会展开的裸
指针/内存原语（`ptr::*`、`mem::forget`、`MaybeUninit::*` 等）和
`Some`/`Ok` 等纯移动的枚举构造器。此外显式识别：

- `panic!`/`unreachable!`/`todo!`/`unimplemented!`：无条件恐慌，
- `assert!`/`debug_assert!`/`println!`/用户宏：保守视为可展开，
- 下标/切片：越界恐慌，
- 整数算术：debug 溢出与除零恐慌，
- `unwrap*`/`expect`：失败变体恐慌，
- 单段路径调用（闭包参数、局部函数）：用户代码，保守处理。

### 必须不误报的正确写法

| 模式 | 不误报的原因 |
| --- | --- |
| `ManuallyDrop::new(ptr::read(p))` | 局部无析构器，展开不会释放槽位 |
| `let v: ManuallyDrop<T>` 显式标注 | 同上 |
| `MaybeUninit::new(..)` / `slot.write(..)` | 目标从未初始化，不存在重复所有者 |
| 守卫对象（`Drop` 内含 `ptr::write` 修复） | pass 1 先收集所有修复型 `Drop` impl，构造守卫时把对应窗口标记为受保护 |
| `scopeguard` / `defer_on_unwind!` 等守卫宏 | 宏名命中守卫宏列表，按 token 引用保护窗口 |
| `mem::forget(v)` | 复制出的所有者被消耗 |
| `panic = "abort"` 的 crate | 读取 `Cargo.toml` 的 `[profile.dev]`，没有栈展开就不可能双重释放 |
| 宏定义体 | `macro_rules!`/`macro` 项整体跳过，不分析模板代码 |
| 宏展开产物 | 展开 token 的 span 行为 0，任何行 0 span 都不报告 |
| `#[allow(unwind_double_free)]` | 函数/块/局部属性与文件级 inner 属性均生效 |

## 检查器二：无约束的 unsafe Send/Sync

### 判定规则

1. 只看正向（非负实现）的 `unsafe impl`，且 trait 末段恰为 `Send` 或
   `Sync`；
2. 收集 impl 声明的全部类型参数（lifetime 与 const 参数无需该约束）；
3. 计算在自身类型中**可达**的参数：先做语法收集，再回查同文件的结构体/
   枚举定义，把仅出现在裸指针（`*const T`、`*mut T`）或
   `PhantomData<*const T>` 之后的参数剔除——那里不存在 `T` 值，自动
   trait 不受影响；普通 `PhantomData<T>` 仍计为可达（dropck/方差）；
4. 内联约束与 `where T: Send` 都算数，仅 `?Sized` 不算；
5. 对每个可达且无对应约束的参数报告一条，触发路径说明：
   缺约束的参数 → 它如何出现在实现类型中 → 用户如何用非线程安全类型
   实例化。

## 输出示例

```text
tests/fixtures/unwind/bugs.rs:15:9: a potentially unwinding call sits between an ownership copy and the write-back [unwind_double_free]
  -> window opened: `ptr::read` duplicates ownership of `slot`
  -> duplicated value binding: value
  -> call to local/closure `callback` may panic or run a user `Drop` (function call)
  => on unwind the local drops, then the still-initialized slot drops the same allocation again
```

`--json` 输出与 `model::Finding` 一一对应：`lint`、`file`、`line`、
`column`、`message`、`trigger_path`。

## 测试

```bash
cargo test
```

14 个集成测试覆盖：全部 bug 夹具命中、全部正确写法静默、宏定义不分析、
守卫宏保护、`PhantomData<*const T>` 豁免、`panic = "abort"` 抑制、
`#[allow]` 抑制、JSON 序列化、解析错误不崩溃，以及多窗口/分支/循环/
方法调用形式/多类型参数/枚举等边界。

## 已知局限

- **无类型推断**：工具只做语法级分析。函数内跨语句的指针别名、方法
  接收者是否真的是裸指针，依赖局部注册与白名单，复杂别名场景可能漏报
  （漏报方向是安全的）。
- **跨文件/跨 crate 的守卫类型不可见**：修复型 `Drop` impl 只在同一
  文件内收集；外部 crate 提供的守卫类型需要改用 `ManuallyDrop` 或加
  `#[allow]`。
- **panic 策略只看 dev profile**：`[profile.release] panic = "abort"`
  不会抑制 lint，因为检查默认面向 `cargo check`/`cargo test` 的配置。
- **宏调用是不透明的**：不做宏展开（也不依赖 nightly 的
  `-Zunpretty=expanded`）；语句级宏按"可能展开为恐慌代码"保守处理，
  守卫宏按名称识别。
- **分支内修复按保守策略**：若窗口只在部分分支修复，工具仍会报告，
  因为存在未修复路径。
