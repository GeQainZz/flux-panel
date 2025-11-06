package com.admin.common.utils;

import com.admin.common.dto.GostConfigDto;
import com.admin.common.dto.GostDto;
import com.admin.entity.Tunnel;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.aspectj.apache.bcel.generic.RET;


import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;

public class GostUtil {


    public static GostDto AddLimiters(Long node_id, Long name, String speed) {
        JSONObject data = createLimiterData(name, speed);
        return WebSocketServer.send_msg(node_id, data, "AddLimiters");
    }

    public static GostDto UpdateLimiters(Long node_id, Long name, String speed) {
        JSONObject data = createLimiterData(name, speed);
        JSONObject req = new JSONObject();
        req.put("limiter", name + "");
        req.put("data", data);
        return WebSocketServer.send_msg(node_id, req, "UpdateLimiters");
    }

    public static GostDto DeleteLimiters(Long node_id, Long name) {
        JSONObject req = new JSONObject();
        req.put("limiter", name + "");
        return WebSocketServer.send_msg(node_id, req, "DeleteLimiters");
    }

    public static GostDto AddService(Long node_id, String name, Integer in_port, Integer limiter,
                                     String remoteAddr, Integer fow_type, Tunnel tunnel,
                                     String strategy, String interfaceName, String ssUri) {
        // 解析可选的 ssUri -> SsOption
        SsOption ss = null;
        if (StringUtils.isNotBlank(ssUri)) {
            ss = parseSsUri(ssUri); // 你已有此方法；确保填充: enable=true, addr, method, password, type
            ss.enable = true;
            if (StringUtils.isBlank(ss.type)) ss.type = "tcp"; // 默认 tcp
        }

        String chainName = null;
        if (ss != null && ss.enable) {
            chainName = name + "_chains";
            JSONObject chainData = buildSsChain(chainName, ss);
            System.out.println("先下发链: " + JSONObject.toJSONString(chainData, true));
            WebSocketServer.send_msg(node_id, chainData, "AddChains"); // 先下发链
        }

        JSONArray services = new JSONArray();
        for (String protocol : new String[]{"tcp", "udp"}) {
            JSONObject svc = createServiceConfig(
                    name, in_port, limiter, remoteAddr, protocol,
                    fow_type, tunnel, strategy, interfaceName,
                    chainName // ← 传给 handler
            );
            services.add(svc);
        }
        // 打印检查
        System.out.println("AddService.services: " + JSONObject.toJSONString(services, true));
        return WebSocketServer.send_msg(node_id, services, "AddService");
    }

    private static JSONObject buildSsChain(String chainName, SsOption ss) {
        // hop.nodes[0].connector
        JSONObject connector = new JSONObject();
        connector.put("type", "ss");

        // ★ 按你的接收端实现：cipher 放在 auth.username
        JSONObject auth = new JSONObject();
        auth.put("username", ss.method);       // 例如 "aes-128-gcm"
        auth.put("password", ss.password);     // 你的 SS 密码
        connector.put("auth", auth);

        // node.dialer
        JSONObject dialer = new JSONObject();
        dialer.put("type", "tcp");

        // 可选：如果你的 ss 服务器要用 SNI/TLS（按你给的配置示例）
        JSONObject tls = new JSONObject();
        tls.put("serverName", ss.addr.split(":")[0]); // 172.81.111.100
        dialer.put("tls", tls);

        // node
        JSONObject node = new JSONObject();
        node.put("name", "node-" + chainName);
        node.put("addr", ss.addr);          // "host:port"，如 "172.81.111.100:52234"
        node.put("connector", connector);
        node.put("dialer", dialer);

        JSONArray nodes = new JSONArray();
        nodes.add(node);

        JSONObject hop = new JSONObject();
        hop.put("name", "hop-" + chainName);
        hop.put("nodes", nodes);

        JSONArray hops = new JSONArray();
        hops.add(hop);

        JSONObject chain = new JSONObject();
        chain.put("name", chainName);
        chain.put("hops", hops);

        return chain; // 作为 AddChains 的 data
    }

    // ==== 3) 基于 SsOption 构造并下发 SS chain（connector=relay，dialer=ss）====
    private static void ensureSsChain(Long nodeId, String chainName, SsOption ss, String interfaceName) {
        if (ss == null || !ss.enable) return;

        String[] hp = splitHostPort(ss.addr);
        String host = hp[0], port = hp[1];

        // 1) connector: ss
        JSONObject ssConnector = new JSONObject();
        ssConnector.put("type", "ss");

        JSONObject auth = new JSONObject();
        auth.put("password", ss.password);
        ssConnector.put("auth", auth);

        JSONObject cm = new JSONObject();
        cm.put("cipher", ss.method);
        cm.put("method", ss.method);      // ★ 用 method，很多构建不认 cipher
        if (Boolean.TRUE.equals(ss.nodelay)) cm.put("nodelay", true);

        // TCP/UDP 指示（你同时下发 tcp/udp 两个 service，建议默认允许 UDP）
        // 大多数版本用 udp:true；如果日志报未知键，再换 network:"udp"
        cm.put("udp", true);              // ★ 允许经 SS 走 UDP
        cm.put("network", "udp");      // ← 如果上面那行不被识别，再用这一行

        ssConnector.put("metadata", cm);

        // 2) dialer: tcp（或 quic）
        JSONObject dialer = new JSONObject();
        dialer.put("type", "tcp");

        // 3) node：指向 SS 服务器
        JSONObject node = new JSONObject();
        node.put("name", "node-" + chainName);
        node.put("addr", host + ":" + port);
        node.put("connector", ssConnector);
        node.put("dialer", dialer);
        if (StringUtils.isNotBlank(interfaceName)) node.put("interface", interfaceName);

        JSONArray nodes = new JSONArray(); nodes.add(node);
        JSONObject hop = new JSONObject(); hop.put("name", "hop-" + chainName); hop.put("nodes", nodes);
        JSONArray hops = new JSONArray(); hops.add(hop);

        JSONObject data = new JSONObject();
        data.put("name", chainName);
        data.put("hops", hops);

        System.out.println("node_id:"+nodeId+"\nAddService.data: "+JSONObject.toJSONString(data));
        WebSocketServer.send_msg(nodeId, data, "AddChains");
    }

    // host:port / [ipv6]:port 解析
    private static String[] splitHostPort(String addr) {
        String a = addr.trim();
        String host, port;
        if (a.startsWith("[")) {
            int rb = a.indexOf(']');
            if (rb < 0 || rb + 2 >= a.length() || a.charAt(rb + 1) != ':')
                throw new IllegalArgumentException("非法 IPv6 地址格式: " + addr);
            host = a.substring(1, rb);
            port = a.substring(rb + 2);
        } else {
            int i = a.lastIndexOf(':');
            if (i <= 0 || i == a.length() - 1)
                throw new IllegalArgumentException("必须是 host:port 形式: " + addr);
            host = a.substring(0, i);
            port = a.substring(i + 1);
        }
        int p = Integer.parseInt(port);
        if (p < 1 || p > 65535) throw new IllegalArgumentException("端口不合法: " + addr);
        return new String[]{host, port};
    }

    public static GostDto UpdateService(Long node_id, String name, Integer in_port, Integer limiter, String remoteAddr, Integer fow_type, Tunnel tunnel, String strategy, String interfaceName,String ssUri) {
        JSONArray services = new JSONArray();
        String[] protocols = {"tcp", "udp"};
        for (String protocol : protocols) {
            SsOption ss = null;
            if (StringUtils.isNotBlank(ssUri)) {
                try {
                    ss = parseSsUri(ssUri); // 需解析出 addr/method/password/type/nodelay/enable
                } catch (Exception e) {
                    throw new RuntimeException("ss转换失败", e);
                }
            }
            String chainName = null;
            if (ss != null && ss.enable) {
                chainName = name + "_chains";
                JSONObject chainData = buildSsChain(chainName, ss);
                System.out.println("先下发链: " + JSONObject.toJSONString(chainData, true));
                WebSocketServer.send_msg(node_id, chainData, "AddChains"); // 先下发链
            }
            JSONObject service = createServiceConfig(name, in_port, limiter, remoteAddr, protocol, fow_type, tunnel, strategy, interfaceName,chainName);
            services.add(service);
        }
        return WebSocketServer.send_msg(node_id, services, "UpdateService");
    }

    public static GostDto DeleteService(Long node_id, String name) {
        JSONObject data = new JSONObject();
        JSONArray services = new JSONArray();
        services.add(name + "_tcp");
        services.add(name + "_udp");
        data.put("services", services);
        return WebSocketServer.send_msg(node_id, data, "DeleteService");
    }

    public static GostDto AddRemoteService(Long node_id, String name, Integer out_port, String remoteAddr,  String protocol, String strategy, String interfaceName) {
        JSONObject data = new JSONObject();
        data.put("name", name + "_tls");
        data.put("addr", ":" + out_port);

        if (StringUtils.isNotBlank(interfaceName)) {
            JSONObject metadata = new JSONObject();
            metadata.put("interface", interfaceName);
            data.put("metadata", metadata);
        }


        JSONObject handler = new JSONObject();
        handler.put("type", "relay");
        data.put("handler", handler);
        JSONObject listener = new JSONObject();
        listener.put("type", protocol);
        data.put("listener", listener);
        JSONObject forwarder = new JSONObject();
        JSONArray nodes = new JSONArray();

        String[] split = remoteAddr.split(",");
        int num = 1;
        for (String addr : split) {
            JSONObject node = new JSONObject();
            node.put("name", "node_" + num );
            node.put("addr", addr);
            nodes.add(node);
            num ++;
        }
        if (strategy == null || strategy.equals("")){
            strategy = "fifo";
        }
        forwarder.put("nodes", nodes);
        JSONObject selector = new JSONObject();
        selector.put("strategy", strategy);
        selector.put("maxFails", 1);
        selector.put("failTimeout", "600s");
        forwarder.put("selector", selector);

        data.put("forwarder", forwarder);
        JSONArray services = new JSONArray();
        services.add(data);
        return WebSocketServer.send_msg(node_id, services, "AddService");
    }

    public static GostDto UpdateRemoteService(Long node_id, String name, Integer out_port, String remoteAddr,String protocol, String strategy, String interfaceName) {
        JSONObject data = new JSONObject();
        data.put("name", name + "_tls");
        data.put("addr", ":" + out_port);

        if (StringUtils.isNotBlank(interfaceName)) {
            JSONObject metadata = new JSONObject();
            metadata.put("interface", interfaceName);
            data.put("metadata", metadata);
        }


        JSONObject handler = new JSONObject();
        handler.put("type", "relay");
        data.put("handler", handler);
        JSONObject listener = new JSONObject();
        listener.put("type", protocol);
        data.put("listener", listener);
        JSONObject forwarder = new JSONObject();
        JSONArray nodes = new JSONArray();

        String[] split = remoteAddr.split(",");
        int num = 1;
        for (String addr : split) {
            JSONObject node = new JSONObject();
            node.put("name", "node_" + num );
            node.put("addr", addr);
            nodes.add(node);
            num ++;
        }
        if (strategy == null || strategy.equals("")){
            strategy = "fifo";
        }
        forwarder.put("nodes", nodes);
        JSONObject selector = new JSONObject();
        selector.put("strategy", strategy);
        selector.put("maxFails", 1);
        selector.put("failTimeout", "600s");
        forwarder.put("selector", selector);

        data.put("forwarder", forwarder);
        JSONArray services = new JSONArray();
        services.add(data);
        return WebSocketServer.send_msg(node_id, services, "UpdateService");
    }

    public static GostDto DeleteRemoteService(Long node_id, String name) {
        JSONArray data = new JSONArray();
        data.add(name + "_tls");
        JSONObject req = new JSONObject();
        req.put("services", data);
        return WebSocketServer.send_msg(node_id, req, "DeleteService");
    }

    public static GostDto PauseService(Long node_id, String name) {
        JSONObject data = new JSONObject();
        JSONArray services = new JSONArray();
        services.add(name + "_tcp");
        services.add(name + "_udp");
        data.put("services", services);
        return WebSocketServer.send_msg(node_id, data, "PauseService");
    }

    public static GostDto ResumeService(Long node_id, String name) {
        JSONObject data = new JSONObject();
        JSONArray services = new JSONArray();
        services.add(name + "_tcp");
        services.add(name + "_udp");
        data.put("services", services);
        return WebSocketServer.send_msg(node_id, data, "ResumeService");
    }

    public static GostDto PauseRemoteService(Long node_id, String name) {
        JSONObject data = new JSONObject();
        JSONArray services = new JSONArray();
        services.add(name + "_tls");
        data.put("services", services);
        return WebSocketServer.send_msg(node_id, data, "PauseService");
    }

    public static GostDto ResumeRemoteService(Long node_id, String name) {
        JSONObject data = new JSONObject();
        JSONArray services = new JSONArray();
        services.add(name + "_tls");
        data.put("services", services);
        return WebSocketServer.send_msg(node_id, data, "ResumeService");
    }

    public static class SsOption {
        public boolean enable;
        public String addr;     // host:port
        public String method;   // cipher
        public String password; // SS 密码
        public Boolean nodelay; // 可选
        public String type;     // tcp/udp, 默认为 tcp
    }

    public static void main(String[] args) {
        SsOption ssOption = parseSsUri("ss://YWVzLTI1Ni1nY206dU56L2VSbEdhSVErKzIxNEZHWW1Zc2Nvb0NEajNza3NwQ3lEdWJEWWt2Zz0@localhost:10041?type=tcp#test-gost");
        System.out.println(JSONObject.toJSONString(ssOption));
    }
    // 解析 SIP002 兼容的 ss://URI
    public static SsOption parseSsUri(String ssUri) {
        if (ssUri == null || !ssUri.startsWith("ss://")) throw new RuntimeException("ss转换失败");

        String raw = ssUri.substring("ss://".length());     // 去掉协议头
        String tag = null;
        int hash = raw.indexOf('#');                        // 去掉 #tag
        if (hash >= 0) {
            tag = URLDecoder.decode(raw.substring(hash + 1), StandardCharsets.UTF_8);
            raw = raw.substring(0, hash);
        }

        String userinfo;   // base64(method:password)
        String serverPart; // host:port[?query]

        int at = raw.indexOf('@');
        if (at >= 0) {
            userinfo = raw.substring(0, at);
            serverPart = raw.substring(at + 1);
        } else {
            // 少见变体：整体 base64 包含 host:port；此处简单兜底
            String dec = b64DecodeUrlSafe(raw);
            int idx = dec.indexOf('@');
            if (idx < 0) throw new IllegalArgumentException("ss uri: 无法拆出认证与服务器部分");
            userinfo = b64Encode(dec.substring(0, idx)); // 重新编码，复用解码逻辑
            serverPart = dec.substring(idx + 1);
        }

        // 解析 method:password
        String creds = b64DecodeUrlSafe(userinfo);
        int colon = creds.indexOf(':');
        if (colon < 0) throw new IllegalArgumentException("ss uri: 认证段缺少 method:password");
        String method = creds.substring(0, colon);
        String password = creds.substring(colon + 1);

        // 解析 host:port 与查询参数
        String query = null;
        int q = serverPart.indexOf('?');
        if (q >= 0) {
            query = serverPart.substring(q + 1);
            serverPart = serverPart.substring(0, q);
        }
        String hostPort = serverPart; // 形如 localhost:10041

        // 解析 type（tcp/udp），默认 tcp
        String type = "tcp";
        if (query != null && !query.isEmpty()) {
            for (String kvp : query.split("&")) {
                int eq = kvp.indexOf('=');
                String k = eq >= 0 ? kvp.substring(0, eq) : kvp;
                String v = eq >= 0 ? kvp.substring(1 + eq) : "";
                k = URLDecoder.decode(k, StandardCharsets.UTF_8);
                v = URLDecoder.decode(v, StandardCharsets.UTF_8);
                if ("type".equalsIgnoreCase(k) && !v.isEmpty()) {
                    type = v;
                }
                // 如需支持 plugin、udp-over-tcp 等，可在这里继续扩展
            }
        }

        SsOption ss = new SsOption();
        ss.enable = true;
        ss.addr = hostPort;
        ss.method = method;
        ss.password = password;
        ss.nodelay = null; // 如需要可从额外参数带入
        ss.type = type;
        return ss;
    }

    private static String b64DecodeUrlSafe(String s) {
        // 兼容 URL-safe 与缺省 padding 的 Base64
        String t = s.replace('-', '+').replace('_', '/');
        int pad = (4 - (t.length() % 4)) % 4;
        t += "====".substring(0, pad);
        return new String(Base64.getDecoder().decode(t), StandardCharsets.UTF_8);
    }

    private static String b64Encode(String s) {
        return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    public static GostDto AddChains(Long node_id,
                                    String name,
                                    String remoteAddr,     // 你的“出口”/最终上游地址
                                    String protocol,       // 现有 dialer 的协议（tcp/quic…）
                                    String interfaceName,  // 可选
                                    String ssUri          // 新增：可选的 SS 中转)
    ) {
        SsOption ss = null;
        if (ssUri != null && !ssUri.isBlank()) {
            try { ss = parseSsUri(ssUri); }
            catch (Exception ex) {
                throw new RuntimeException("ss转换失败");
            }
        }

        // === 现有 dialer ===
        JSONObject dialer = new JSONObject();
        dialer.put("type", protocol);
        if (Objects.equals(protocol, "quic")) {
            JSONObject metadata = new JSONObject();
            metadata.put("keepAlive", true);
            metadata.put("ttl", "10s");
            dialer.put("metadata", metadata);
        }

        // === 现有 connector（出口 hop 使用 relay）===
        JSONObject connector = new JSONObject();
        connector.put("type", "relay");

        // === 出口 hop 的 node ===
        JSONObject node = new JSONObject();
        node.put("name", "node-" + name);
        node.put("addr", remoteAddr);
        node.put("connector", connector);
        node.put("dialer", dialer);
        if (StringUtils.isNotBlank(interfaceName)) {
            node.put("interface", interfaceName);
        }

        JSONArray hops = new JSONArray();

        // === (可选) SS 中转 hop，插在最前面：入口 -> SS -> 你的出口 ===
        if (ss != null && ss.enable) {
            JSONObject ssConnector = new JSONObject();
            ssConnector.put("type", "ss");
            // SS 的认证在 connector.auth/password
            JSONObject auth = new JSONObject();
            auth.put("password", ss.password);
            ssConnector.put("auth", auth);

            // SS 的额外元数据（cipher、nodelay 等）
            JSONObject ssMeta = new JSONObject();
            ssMeta.put("cipher", ss.method);
            if (ss.nodelay != null) ssMeta.put("nodelay", String.valueOf(ss.nodelay));
            ssConnector.put("metadata", ssMeta);

            JSONObject ssNode = new JSONObject();
            ssNode.put("name", "ss-node-" + name);
            ssNode.put("addr", ss.addr);
            ssNode.put("connector", ssConnector);
            // SS hop 的拨号通常就是 tcp
            JSONObject ssDialer = new JSONObject();
            ssDialer.put("type", "tcp");
            ssNode.put("dialer", ssDialer);

            JSONArray ssNodes = new JSONArray();
            ssNodes.add(ssNode);

            JSONObject ssHop = new JSONObject();
            ssHop.put("name", "hop-ss-" + name);
            ssHop.put("nodes", ssNodes);

            // 插在最前面
            hops.add(ssHop);
        }

        // === 原来的出口 hop ===
        JSONArray nodes = new JSONArray();
        nodes.add(node);

        JSONObject hop = new JSONObject();
        hop.put("name", "hop-" + name);
        hop.put("nodes", nodes);

        hops.add(hop);

        // === 组装 chain ===
        JSONObject data = new JSONObject();
        data.put("name", name + "_chains");
        data.put("hops", hops);
        System.out.println("AddChains.data: "+JSONObject.toJSONString(data));
        return WebSocketServer.send_msg(node_id, data, "AddChains");
    }

    public static GostDto UpdateChains(Long node_id, String name, String remoteAddr, String protocol, String interfaceName) {
        JSONObject dialer = new JSONObject();
        dialer.put("type", protocol);

        if (Objects.equals(protocol, "quic")){
            JSONObject metadata = new JSONObject();
            metadata.put("keepAlive", true);
            metadata.put("ttl", "10s");
            dialer.put("metadata", metadata);
        }


        JSONObject connector = new JSONObject();
        connector.put("type", "relay");

        JSONObject node = new JSONObject();
        node.put("name", "node-" + name);
        node.put("addr", remoteAddr);
        node.put("connector", connector);
        node.put("dialer", dialer);

        if (StringUtils.isNotBlank(interfaceName)) {
            node.put("interface", interfaceName);
        }

        JSONArray nodes = new JSONArray();
        nodes.add(node);

        JSONObject hop = new JSONObject();
        hop.put("name", "hop-" + name);
        hop.put("nodes", nodes);

        JSONArray hops = new JSONArray();
        hops.add(hop);

        JSONObject data = new JSONObject();
        data.put("name", name + "_chains");
        data.put("hops", hops);
        JSONObject req = new JSONObject();
        req.put("chain", name + "_chains");
        req.put("data", data);
       return WebSocketServer.send_msg(node_id, req, "UpdateChains");
    }

    public static GostDto DeleteChains(Long node_id, String name) {
        JSONObject data = new JSONObject();
        data.put("chain", name + "_chains");
        return WebSocketServer.send_msg(node_id, data, "DeleteChains");
    }

    private static JSONObject createLimiterData(Long name, String speed) {
        JSONObject data = new JSONObject();
        data.put("name", name.toString());
        JSONArray limits = new JSONArray();
        limits.add("$ " + speed + "MB " + speed + "MB");
        data.put("limits", limits);
        return data;
    }

    private static JSONObject createServiceConfig(
            String name,
            Integer in_port,
            Integer limiter,
            String remoteAddr,
            String protocol,            // "tcp" / "udp"
            Integer fow_type,
            Tunnel tunnel,
            String strategy,
            String interfaceName,
            String chainNameOrNull               // 新增：可为空；非空且 enable=true 时走 SS
    ) {
        JSONObject service = new JSONObject();
        service.put("name", name + "_" + protocol);

        // 监听地址
        if ("tcp".equalsIgnoreCase(protocol)) {
            service.put("addr", tunnel.getTcpListenAddr() + ":" + in_port);
        } else {
            service.put("addr", tunnel.getUdpListenAddr() + ":" + in_port);
        }

        // 可选：指定出口网卡
        if (StringUtils.isNotBlank(interfaceName)) {
            JSONObject md = new JSONObject();
            md.put("interface", interfaceName);
            service.put("metadata", md);
        }

        // 限流
        if (limiter != null) {
            service.put("limiter", limiter.toString());
        }

        // 入站 handler / listener
        JSONObject handler = createHandler(protocol, name, fow_type);
        if (StringUtils.isNotBlank(chainNameOrNull)) {
            // ★ 关键：链挂在 handler
            handler.put("chain", chainNameOrNull);
        }
        service.put("handler", handler);


        JSONObject listener = createListener(protocol);
        service.put("listener", listener);

        // 仅在端口转发时组 forwarder
        if (isPortForwarding(fow_type)) {
            if (StringUtils.isBlank(remoteAddr)) {
                throw new IllegalArgumentException("端口转发时 remoteAddr 不能为空");
            }
            //JSONObject forwarder = createForwarder(remoteAddr, strategy);
            JSONObject forwarder = new JSONObject();
            JSONArray nodes = new JSONArray();

            String[] split = remoteAddr.split(",");
            int num = 1;
            for (String addr : split) {
                JSONObject n = new JSONObject();
                n.put("name", "target_" + num);
                n.put("addr", addr);
                // ★ 关键：这里不要再放 chain 字段
                nodes.add(n);
                num++;
            }

            if (StringUtils.isBlank(strategy)) strategy = "fifo";
            JSONObject selector = new JSONObject();
            selector.put("strategy", strategy);
            selector.put("maxFails", 1);
            selector.put("failTimeout", "600s");

            forwarder.put("nodes", nodes);
            forwarder.put("selector", selector);

            service.put("forwarder", forwarder);
        }
        return service;
    }

    /**
     * 在 forwarder.chain 内联一个“只有 1 个 hop / 1 个 node 的 SS 出口”
     * 结构等价于：
     * chain:
     *   hops:
     *   - nodes:
     *     - addr: <ssHost:ssPort>
     *       connector:
     *         type: "ss"
     *         auth:
     *           password: "<ss_password>"
     *         metadata:
     *           method: "<cipher>"           // 如 aes-128-gcm / chacha20-ietf-poly1305
     *           udp: true/false              // 按需
     *       dialer:
     *         type: "tcp"
     */
    private static JSONObject buildInlineSsChain(SsOption ss, String protocol, String interfaceName) {
        // --- connector:ss ---
        JSONObject ssConnector = new JSONObject();
        ssConnector.put("type", "ss");

        JSONObject auth = new JSONObject();
        auth.put("password", ss.password);
        ssConnector.put("auth", auth);

        JSONObject meta = new JSONObject();
        // 有的版本字段名是 method，有的是 cipher；两者都给最保险
        meta.put("method", ss.method);
        meta.put("cipher", ss.method);
        if ("udp".equalsIgnoreCase(protocol) || "udp".equalsIgnoreCase(ss.type)) {
            meta.put("udp", true);
            meta.put("network", "udp"); // 部分构建会识别该键
        }
        ssConnector.put("metadata", meta);

        // --- node ---
        JSONObject node = new JSONObject();
        node.put("name", "ss-exit");
        node.put("addr", ss.addr);          // 形如 "172.81.111.100:52234"
        node.put("connector", ssConnector);

        // SS 往外拨通常 tcp 就够
        JSONObject dialer = new JSONObject();
        dialer.put("type", "tcp");
        node.put("dialer", dialer);

        if (StringUtils.isNotBlank(interfaceName)) {
            node.put("interface", interfaceName);
        }

        // hop / chain
        JSONArray nodes = new JSONArray();
        nodes.add(node);

        JSONObject hop = new JSONObject();
        hop.put("name", "hop-ss-inline");
        hop.put("nodes", nodes);

        JSONArray hops = new JSONArray();
        hops.add(hop);

        JSONObject chain = new JSONObject();
        chain.put("hops", hops);
        return chain;
    }






    private static JSONObject createHandler(String protocol, String name, Integer fow_type) {
        JSONObject handler = new JSONObject();
        handler.put("type", protocol);

        // 隧道转发需要添加链配置
        if (isTunnelForwarding(fow_type)) {
            handler.put("chain", name + "_chains");
        }

        return handler;
    }

    private static JSONObject createListener(String protocol) {
        JSONObject listener = new JSONObject();
        listener.put("type", protocol);
        if (Objects.equals(protocol, "udp")){
            JSONObject metadata = new JSONObject();
            metadata.put("keepAlive", true);
            listener.put("metadata", metadata);
        }
        return listener;
    }

    // 兼容旧签名
    private static JSONObject createForwarder(String remoteAddr, String strategy) {
        return createForwarder(remoteAddr, strategy, null);
    }

    // 新签名：可选 chainName；不为空时，forwarder 顶层与每个 node 都挂同一条 chain
    private static JSONObject createForwarder(String remoteAddr, String strategy, String chainName) {
        JSONObject forwarder = new JSONObject();

        // 顶层 chain（注意：gost v3 期望是 string，而不是 {"name": "..."}）
        if (StringUtils.isNotBlank(chainName)) {
            forwarder.put("chain", chainName);
        }

        JSONArray nodes = new JSONArray();
        String[] split = remoteAddr.split(",");
        int i = 1;
        for (String addr : split) {
            if (StringUtils.isBlank(addr)) continue;
            JSONObject n = new JSONObject();
            n.put("name", "node_" + i++);
            n.put("addr", addr.trim());

            // 节点级 chain（建议也挂，版本/策略选择器上更稳）
            if (StringUtils.isNotBlank(chainName)) {
                n.put("chain", chainName);
            }
            nodes.add(n);
        }
        forwarder.put("nodes", nodes);

        if (StringUtils.isBlank(strategy)) strategy = "fifo";
        JSONObject selector = new JSONObject();        // 千万别打成 "stor"
        selector.put("strategy", strategy);
        selector.put("maxFails", 1);
        selector.put("failTimeout", "600s");
        forwarder.put("selector", selector);

        return forwarder;
    }




    private static boolean isPortForwarding(Integer fow_type) {
        return fow_type != null && fow_type == 1;
    }

    private static boolean isTunnelForwarding(Integer fow_type) {
        return fow_type != null && fow_type != 1;
    }

}
