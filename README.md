# 主机配置基线核查器(等保复测)

面向等保复测场景的**离线、无 agent** 主机基线核查工具。只读取配置文件快照,
不连接、不修改目标系统;规则用 YAML 描述,结论全部带**文件路径 + 行号 + 原始行**
证据,支持同一台机器两次快照的变好/变差对比,产出单文件 HTML 报告与整改清单。

## 为什么零第三方依赖

目标环境通常离线且不允许随意装包,本工具只用 Python 标准库,
内置 YAML 子集解析器(`baseline_checker/yaml_lite.py`),
在 `python3 -I`(隔离模式,忽略 PYTHONPATH 与当前目录注入)下运行,
避免快照目录中被放置 `json.py` 之类的模块劫持。

## 目录结构

```
baseline_audit.py            # 启动脚本
baseline_checker/
  yaml_lite.py               # 零依赖 YAML 子集解析器
  models.py                  # Entry / Evidence / HostInfo 数据模型
  utils.py                   # 续行拼接、引号分词等
  parsers/                   # 各配置文件解析器(保留行号与上下文)
    snapshot.py  sshd.py  sudoers.py  pam.py
    sysctl.py   login_defs.py  cron.py
  facts.py                   # 事实层:规则查询的统一入口
  engine.py                  # 规则加载(include)、算子、判定、证据汇总
  diff.py                    # 两次核查结果对比
  report.py                  # HTML / JSON / 整改清单 Markdown
  cli.py                     # audit / diff / selftest 三个子命令
rules/                       # YAML 规则库,主文件 rules.yml 用 include 聚合
snapshots/                   # 4 台不同发行版的快照样例
tests/                       # 42 个单元测试
```

## 快照样例

| 目录 | 发行版 | 特点 |
|---|---|---|
| `snapshots/host-rhel8` | RHEL 8.9 | Ansible 下发的规范配置,核查应接近全合规 |
| `snapshots/host-ubuntu2204` | Ubuntu 22.04 | 默认配置 + 手工改动,留了 NOPASSWD ALL、curl\|bash 等问题 |
| `snapshots/host-ubuntu2204-fixed` | 同上,整改后 | 用于 diff,大部分变好,故意埋一处变差 |
| `snapshots/host-debian11` | Debian 11 | 最小化安装,大量文件缺失,检验空结果策略 |
| `snapshots/host-rhel8-messy` | CentOS 7.9 | **故意写得很乱**:注释、反斜杠续行、重复键、引号、通配 include、Match 块全有 |

每个快照根目录的 `snapshot.json` 记录主机元数据与文件权限(模拟只采集到 stat、
没有实体文件的情况)。

## 使用方法

```bash
# 单台核查(产物写到 audit_output/<主机名>/)
python3 -I baseline_audit.py audit snapshots/host-rhel8-messy

# 同一台机器两次快照对比(变好/变差/仍不符合)
python3 -I baseline_audit.py diff \
    snapshots/host-ubuntu2204 \
    snapshots/host-ubuntu2204-fixed

# 与历史 result.json 对比
python3 -I baseline_audit.py audit snapshots/host-x --baseline audit_output/host-x/result.json

# 自检
python3 -I baseline_audit.py selftest
```

退出码:存在不符合或判定错误时返回 1,便于接入 CI/流水线卡点。

## 解析器对复杂写法的处理

- **sshd_config**:`Include` 递归(支持 glob、绝对/相对路径、循环包含保护);
  `Match` 块内配置带条件上下文;重复键按 sshd 语义**首次出现生效**,
  被遮蔽的行一并保留在证据里;`Address` 归一为 `addr`。
- **sudoers**:`#include`/`#includedir`/`@include`、反斜杠续行、四类别名、
  `Defaults@host`/`:user`/`!flag` 限定符、NOPASSWD 等命令标签;
  自动跳过 `~` 结尾与 `.` 开头的片段。
- **PAM**:方括号动作组 `[success=1 default=bad]` 整体解析、
  `include`/`substack` 递归、模块路径 `-` 前缀容错、续行拼接。
- **sysctl**:`=` 与 `:` 分隔、`;` 注释、续行;按**最后出现生效**标记生效行,
  并在证据里附被遮蔽行号。
- **login.defs**:同名键最后一次生效,全部重复行留证。
- **cron**:系统/用户 crontab(用户 spool 无用户名列)、`@reboot` 等简写、
  环境变量行、allow/deny 名单,自动标注 curl|bash、/dev/tcp、base64 -d 等危险特征。

## 规则写法

```yaml
- id: SSHD-002
  title: 禁止 root 直接远程登录
  component: sshd
  severity: high
  tags: [等保-8.1.4.1, 访问控制]
  fact: sshd.setting          # 事实层注册的 fact 名
  args: { key: PermitRootLogin }
  operator: in
  expected: ["no", "prohibit-password"]
  on_empty: fail              # 没有匹配项时:fail / pass
  rationale: ...
  remediation: ...
  references: [CIS 5.2.10]
```

上下文相关的 Match 块判断通过 `args.match` 选择器实现;
半结构化事实(如 sudoers 授权、PAM 模块参数)用 `pass_when` 复合判定。
规则文件支持 `include` 引用其他文件或整个目录。

## 判定语义与空结果策略

- `match_policy`:`all`(默认)/`any`/`none`,控制多条事实如何汇总。
- `on_empty`:配置项缺失时显式指定 PASS 或 FAIL,
  例如现代 OpenSSH 已删除 `Protocol` 指令,缺省即安全,用 `pass`;
  而 `PermitRootLogin` 不允许依赖发行版默认值,用 `fail`。
- 每条 FAIL 在 HTML 里默认展开,证据可直接定位到行;整改清单按高/中/低危排序。
