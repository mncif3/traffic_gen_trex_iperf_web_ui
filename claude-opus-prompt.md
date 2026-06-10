# TRex Web UI 架构问题 — 给 Claude Opus 的提示词

## 项目背景

GitHub: https://github.com/mncif3/traffic_gen_trex_iperf_web_ui

服务器 UB-174 (192.168.100.174, Ubuntu 24.04, 16GB)，4 张 Intel X710 10G 网卡。Web UI 在 8888 端口，提供 6 个 Tab：BGP / Traffic Streams / Statistics / Hosts / iPerf3 / QoS Test。

## 硬件拓扑

```
174 X710 NICs (PCI 08/09/0a/0b):
  08:00.0 → enp8s0np0  (i40e driver) → 10G Port 0 → 交换机 171 Eth513
  09:00.0 → enp9s0np3  (i40e driver) → 10G Port 1
  0a:00.0 → enp10s0np2 (i40e driver) → 10G Port 2
  0b:00.0 → enp11s0np1 (i40e driver) → 10G Port 3 → 交换机 172 Eth513

交换机:
  192.168.100.171 (SONiC, AS65001), Eth513 ↔ 174 10G P0
  192.168.100.172 (SONiC, AS65002), Eth513 ↔ 174 10G P3
```

## 当前架构 — 三套系统混用

### 系统 1: TRex (Cisco 流量生成器)
- 安装位置: `/opt/trex/` (v3.06)
- **自带 BIRD** 在 `/opt/trex/bird/` — TRex 原生用 BIRD 做 BGP
- 配置: `/etc/trex_cfg.yaml`，定义 Port 0/IP 10.0.0.0, Port 1/IP 10.0.0.2，接口 enp8s0np0/enp11s0np1
- **当前状态: 未运行**。NIC 全部绑在 i40e 内核驱动上，TRex 需要 vfio-pci (DPDK)，两者互斥

### 系统 2: iPerf3 + Namespace (打流 + QoS 测试)
- 两个 namespace: `iperf_ns` (IP 10.20.0.0 → 172 Eth513), `iperf_ns2` (IP 10.0.0.2 → 171 Eth513)
- **当前状态: namespace 存在但里面没有接口** — NIC 还在宿主机上
- iperf3 server 跑在 iperf_ns，client 跑在 iperf_ns2，流量经交换机
- 已验证跑通 9.42 Gbps

### 系统 3: ExaBGP (BGP 路由)
- Web UI 的 BGP Tab 用 ExaBGP (`/home/cunshen/.local/bin/exabgp`)
- 独立于 TRex 和 iperf3，手动管理 neighbor 和路由通告
- **当前状态: 未运行**

## 核心问题

### 问题 1: NIC 归属冲突 — TRex vs iPerf3 互斥

TRex 需要 DPDK (vfio-pci 绑定 NIC，绕过内核)，iperf3 需要内核网络栈 (namespace + i40e 驱动)。**同一张 NIC 不能同时给 TRex 和 iperf3 用。**

```
当前: 4 张 X710 全绑 i40e → iperf3 能用，TRex 用不了
TRex 模式: 需要把某几张 NIC 切到 vfio-pci → iperf3 不能用那些口
```

**想法1**: 4 张 X710，指定 2 张给 TRex (vfio-pci)，2 张给 iperf3 (i40e + namespace)。TRex 用 Port 0/1 (08/09) 打流 + BIRD BGP，iperf3 用 Port 2/3 (0a/0b) 做 QoS 测试。两个系统并行跑。

**想法2**: 动态切换。需要打流时切到 vfio-pci 跑 TRex，需要 iperf3 时切回 i40e。方案复杂但灵活。

### 问题 2: BGP 选型 — BIRD vs ExaBGP vs FRR vs GoBGP

TRex 自带 BIRD (`/opt/trex/bird/`)，Cisco TRex 生态就是用 BIRD 做 control-plane BGP。当前 Web UI 单独跑 ExaBGP，跟 TRex 完全割裂。

**建议**: 用 TRex 自带的 BIRD 替代 ExaBGP。BIRD 可以和 TRex 的流量生成深度集成 — BIRD 学到的路由可以直接喂给 TRex 的 stream builder 生成测试流量。

需要确认:
- `/opt/trex/bird/` 里 BIRD 的版本和配置方式
- TRex 的 STL API 能不能读取 BIRD 的 RIB
- BIRD 能不能跑在 TRex 的 DPDK 口上做 BGP

### 问题 3: Namespace 到底怎么配的

`ip netns exec iperf_ns ip link` 显示空 — namespace 里没有接口。但 `_get_interfaces()` 能扫到 IP (10.0.0.2, 10.20.0.0)。IP 究竟是配在哪的？

需要排查:
```bash
ip netns exec iperf_ns ip addr show
ip netns exec iperf_ns2 ip addr show
ip -4 addr show | grep -E "10\.0\.|10\.20\."
```

### 问题 4: 固定 IP 策略

不管用 TRex 还是 iperf3，数据面 IP 固定不变:
- **Port 0 → 171 Eth513**: `10.0.0.2` (iperf_ns2 namespace)
- **Port 3 → 172 Eth513**: `10.20.0.0` (iperf_ns namespace)

BGP 邻居也是这两个 IP 之间通过交换机建立。

## 期望的最终架构

```
┌─ TRex (vfio-pci, DPDK) ──────────────────────────┐
│  BIRD BGP ←→ 交换机 171/172 (BGP ECMP)           │
│  Traffic Generator (Scapy, 自定义 DSCP/QoS)       │
│  Port 0 (08:00.0) → 171 Eth513 (10.0.0.2)        │
│  Port 1 (09:00.0) → ???                           │
├─ iPerf3 (i40e, kernel namespace) ─────────────────┤
│  iperf_ns2 → 171 Eth513 (10.0.0.2)                │
│  iperf_ns  → 172 Eth513 (10.20.0.0)              │
│  QoS Test: DSCP 打流 + 交换机队列计数器            │
├─ Web UI (:8888) ──────────────────────────────────┤
│  BGP Tab → BIRD status/neighbor management        │
│  Traffic Tab → TRex stream builder                │
│  iPerf3 Tab → namespace iperf3 streams            │
│  QoS Tab → DSCP test + switch queue counters      │
└───────────────────────────────────────────────────┘
```

## 请帮忙分析

1. TRex 能不能跟 iperf3 共用同一个数据面 IP（TRex 用 DPDK 模拟那个 IP）？
2. BIRD 要怎么配才能替代 ExaBGP，跟交换机 171/172 建 BGP 邻居？
3. 4 张 X710 的最佳分配方案是什么？（几张给 TRex，几张给 iperf3）
4. TRex 的 BIRD 能不能同时做 BGP 路由交换 AND 把路由喂给 TRex 的 traffic generator？
5. 如果 TRex 不能跟 iperf3 namespace 共用端口，要不要放弃其中一边？还是全切 TRex，iperf3 只用 TRex 的 latency stream 代替？

## 已有代码

GitHub 仓库里 `app.py` 是目前运行的完整代码，包含了所有 6 个 Tab 的前端和后端。你可以直接读。
