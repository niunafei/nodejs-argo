#!/usr/bin/env node
/**
 * Argo 节点部署脚本 - 注释增强版
 *
 * 主要功能：VLESS/VMess/Trojan WebSocket + Cloudflare Tunnel；可选 VLESS Reality、
 * Hysteria2、SOCKS5；输出 Base64 订阅、明文节点清单、Clash Meta/Mihomo YAML；
 * 提供 /sub、/clash 和 /health HTTP 接口；可选哪吒监控及定时访问用户自有 URL。
 *
 * 隐私边界：不包含节点/订阅上传、旧节点远程删除、Telegram 推送或第三方 ISP/GeoIP 查询。
 * 必要外联仍包括：下载 cloudflared/Xray/哪吒二进制、Cloudflare Tunnel 通信、（未设置
 * SERVER_IP 时）查询公网 IP、（启用哪吒时）向用户配置的哪吒服务器发送监控数据、
 * （启用 AUTO_ACCESS 时）访问用户配置的 PROJECT_URL。下载二进制目前没有哈希/签名校验。
 *
 * 安全提示：/sub 和 /clash 含节点凭据，默认可公开访问；建议配置 ACCESS_TOKEN。
 */

const http = require("http"); // Node 内置 HTTP 服务模块
const axios = require("axios"); // HTTP 请求：下载依赖、获取公网 IP、可选定时访问
const os = require('os'); // 获取 CPU 架构
const fs = require("fs"); // 文件读写与清理
const path = require("path"); // 跨平台文件路径处理
const crypto = require('crypto'); // X25519 密钥生成、证书 SHA-256 指纹
const { promisify } = require('util'); // 将 callback API 转为 Promise
const { exec: execCommand, execSync } = require('child_process'); // 执行 shell 命令
const exec = promisify(execCommand); // Promise 版本的 exec

// ====================== 环境变量说明（均可在部署平台设置） ======================
const FILE_PATH = process.env.FILE_PATH || '.npm'; // 运行目录：保存订阅、Clash YAML、配置及临时二进制
const SUB_PATH = process.env.SUB_PATH || 'sub'; // 订阅 HTTP 路径；默认 /sub
const SERVER_IP_OVERRIDE = process.env.SERVER_IP || ''; // 手动指定公网 IP；设置后不再请求 ip.sb
const PORT = Number(process.env.SERVER_PORT || process.env.PORT || 3000); // Node HTTP 服务监听端口
const UUID = process.env.UUID || '9afd1229-b893-40c1-84dd-51e7ce204913'; // 节点 UUID/密码；强烈建议自行更换为随机值
const NEZHA_SERVER = process.env.NEZHA_SERVER || ''; // 哪吒服务端地址；v1 常用 host:port，v0 通常为域名
const NEZHA_PORT = process.env.NEZHA_PORT || ''; // 哪吒 v1 留空；哪吒 v0 填 Agent 端口
const NEZHA_KEY = process.env.NEZHA_KEY || ''; // 哪吒 v1 client_secret 或 v0 Agent 密钥
const ARGO_DOMAIN = process.env.ARGO_DOMAIN || ''; // 固定 Cloudflare Tunnel 域名；需与 ARGO_AUTH 同时配置
const ARGO_AUTH = process.env.ARGO_AUTH || ''; // Cloudflare Tunnel Token 或 credentials JSON；留空使用临时隧道
const ARGO_PORT = Number(process.env.ARGO_PORT || 8001); // Xray WS 回落端口；固定隧道的 service 端口需与之对应
const S5_PORT = process.env.S5_PORT || ''; // 可选 SOCKS5 TCP 端口；留空/无效值不启用
const HY2_PORT = process.env.HY2_PORT || ''; // 可选 Hysteria2 UDP 端口；留空/无效值不启用
const REALITY_PORT = process.env.REALITY_PORT || ''; // 可选 VLESS Reality TCP 端口；留空/无效值不启用
const CFIP = process.env.CFIP || 'saas.sin.fan'; // WS 节点连接地址（优选域名/IP），不是 Argo 隧道域名
const CFPORT = Number(process.env.CFPORT || 443); // CFIP 对应端口，通常 443
const NAME = process.env.NAME || ''; // 节点名称；留空时使用 Node
const SHOW_LOG = !['false', 'disable', 'no'].includes(String(process.env.SHOW_LOG || 'true').toLowerCase()); // 普通日志开关
const ACCESS_TOKEN = process.env.ACCESS_TOKEN || ''; // 可选 HTTP 访问口令；设置后 /sub 和 /clash 需要 token
const HEALTH_PATH = process.env.HEALTH_PATH || 'health'; // 健康检查路径；默认 /health
const AUTO_ACCESS = ['1', 'true', 'yes', 'on'].includes(String(process.env.AUTO_ACCESS || 'false').toLowerCase()); // 是否定时访问 PROJECT_URL，默认关闭
const PROJECT_URL = process.env.PROJECT_URL || ''; // AUTO_ACCESS=true 时访问的 URL；不会发送给第三方登记服务
const AUTO_ACCESS_INTERVAL_RAW = Number(process.env.AUTO_ACCESS_INTERVAL_MS || 300000); // 原始间隔配置，非法值会回退默认值
const AUTO_ACCESS_INTERVAL_MS = Math.max(60000, Number.isFinite(AUTO_ACCESS_INTERVAL_RAW) ? AUTO_ACCESS_INTERVAL_RAW : 300000); // 自动访问间隔（毫秒），默认 5 分钟，最小 1 分钟
const PRINT_CLASH = ['1', 'true', 'yes', 'on'].includes(String(process.env.PRINT_CLASH || 'false').toLowerCase()); // 是否把含密码的完整 Clash YAML 打印到日志，默认关闭
// ================================================================================


// SHOW_LOG 只控制 console 日志；alwaysLog 始终输出关键启动信息。
if (!SHOW_LOG) {
  console.log = () => {};
  console.error = () => {};
}
// 不受 SHOW_LOG 影响的关键日志输出。
function alwaysLog(msg) {
  process.stdout.write(msg + '\n');
}

// 创建运行目录；递归创建可避免父目录不存在时失败。
if (!fs.existsSync(FILE_PATH)) {
  fs.mkdirSync(FILE_PATH);
  // console.log(`${FILE_PATH} is created`);
} else {
  // console.log(`${FILE_PATH} already exists`);
}

// 检查端口是否为 1-65535 的有效整数；无效/空值代表不启用可选协议。
function isValidPort(port) {
  try {
    if (port === null || port === undefined || port === '') return false;
    if (typeof port === 'string' && port.trim() === '') return false;
    const portNum = parseInt(port);
    if (isNaN(portNum)) return false;
    if (portNum < 1 || portNum > 65535) return false;
    return true;
  } catch (error) {
    return false;
  }
}

// 为下载的可执行文件生成随机文件名，减少同目录文件名冲突（不代表文件安全）。
function generateRandomName() {
  const characters = 'abcdefghijklmnopqrstuvwxyz';
  let result = '';
  for (let i = 0; i < 6; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return result;
}

// 运行期状态与路径：subContent 用于 HTTP 订阅响应；privateKey/publicKey 用于 Reality。
let subContent = null; // Base64 订阅缓存；HTTP /sub 优先从内存返回
let privateKey = ''; // Reality 服务端私钥；不要对外发布
let publicKey = ''; // Reality 客户端公钥；写入分享链接和 Clash YAML
const npmName = generateRandomName(); // 哪吒 v1 Agent 临时二进制文件名
const webName = generateRandomName(); // Xray 临时二进制文件名
const botName = generateRandomName(); // cloudflared 临时二进制文件名
const phpName = generateRandomName(); // 哪吒 v0 Agent 临时二进制文件名
let npmPath = path.join(FILE_PATH, npmName); // 哪吒 v1 Agent 文件路径
let phpPath = path.join(FILE_PATH, phpName); // 哪吒 v0 Agent 文件路径
let webPath = path.join(FILE_PATH, webName); // Xray 文件路径
let botPath = path.join(FILE_PATH, botName); // cloudflared 文件路径
let subPath = path.join(FILE_PATH, 'sub.txt'); // Base64 编码订阅文件
let listPath = path.join(FILE_PATH, 'list.txt'); // 明文节点链接清单（仅本地临时文件）
let clashPath = path.join(FILE_PATH, 'clash.yaml'); // 自动生成的 Clash Meta/Mihomo 配置
let bootLogPath = path.join(FILE_PATH, 'boot.log'); // Quick Tunnel 启动日志，用于提取临时域名
let configPath = path.join(FILE_PATH, 'config.json'); // Xray 服务端配置文件
let certPath = path.resolve(FILE_PATH, 'cert.pem'); // Hysteria2 TLS 证书
let keyPath = path.resolve(FILE_PATH, 'private.key'); // Hysteria2 TLS 私钥

// 清理历史文件
function cleanupOldFiles() {
  // 仅删除本脚本已知的生成文件，不再清空整个 FILE_PATH，避免误删用户自己的文件。
  const generatedFiles = [
    subPath, listPath, clashPath, bootLogPath, configPath,
    path.join(FILE_PATH, 'config.yaml'), path.join(FILE_PATH, 'tunnel.json'),
    path.join(FILE_PATH, 'tunnel.yml'), // Reality 的 key.txt 保留，以便重启后复用同一密钥
    certPath, keyPath, npmPath, phpPath, webPath, botPath
  ];
  for (const generatedFile of generatedFiles) {
    try {
      if (fs.existsSync(generatedFile) && fs.statSync(generatedFile).isFile()) fs.unlinkSync(generatedFile);
    } catch (error) {
      console.error(`清理文件失败 ${generatedFile}: ${error.message}`);
    }
  }
}

// 生成 VLESS Reality 所需的 X25519 密钥对。
function generateX25519Keypair() {
  const { publicKey: pubKey, privateKey: privKey } = crypto.generateKeyPairSync('x25519');
  const privateKeyRaw = privKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32);
  const publicKeyRaw = pubKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  return {
    privateKey: privateKeyRaw.toString('base64url'),
    publicKey: publicKeyRaw.toString('base64url')
  };
}

// 生成/加载 Reality 密钥；key.txt 会保留在 FILE_PATH，重启后复用同一组密钥。
function generateOrLoadKeyPair() {
  const keyFilePath = path.join(FILE_PATH, 'key.txt');
  if (fs.existsSync(keyFilePath)) {
    const content = fs.readFileSync(keyFilePath, 'utf8');
    const privateKeyMatch = content.match(/PrivateKey:\s*(.*)/);
    const publicKeyMatch = content.match(/PublicKey:\s*(.*)/);
    if (privateKeyMatch && publicKeyMatch) {
      privateKey = privateKeyMatch[1].trim();
      publicKey = publicKeyMatch[1].trim();
      try { fs.chmodSync(keyFilePath, 0o600); } catch (error) { /* 某些平台不支持 chmod */ }
      console.log('Reality 密钥已加载（私钥不输出到日志）');
      return;
    }
  }
  const keypair = generateX25519Keypair();
  privateKey = keypair.privateKey;
  publicKey = keypair.publicKey;
  fs.writeFileSync(keyFilePath, `PrivateKey: ${privateKey}\nPublicKey: ${publicKey}\n`, { encoding: 'utf8', mode: 0o600 });
  try { fs.chmodSync(keyFilePath, 0o600); } catch (error) { /* 某些平台不支持 chmod */ }
  console.log('Reality 密钥已生成并保存（私钥不输出到日志）');
}

// 为 Hysteria2 创建 TLS 证书；证书与私钥仅用于 HY2 服务端 TLS。
// openssl 不可用时写入的备用 EC 私钥（仅用于 Hysteria2 TLS 证书生成兜底）。
const FALLBACK_EC_KEY =
  '-----BEGIN EC PARAMETERS-----\n' +
  'BggqhkjOPQMBBw==\n' +
  '-----END EC PARAMETERS-----\n' +
  '-----BEGIN EC PRIVATE KEY-----\n' +
  'MHcCAQEEIM4792SEtPqIt1ywqTd/0bYidBqpYV/++siNnfBYsdUYoAoGCCqGSM49\n' +
  'AwEHoUQDQgAE1kHafPj07rJG+HboH2ekAI4r+e6TL38GWASANnngZreoQDF16ARa\n' +
  '/TsyLyFoPkhLxSbehH/NBEjHtSZGaDhMqQ==\n' +
  '-----END EC PRIVATE KEY-----\n';
// 与 FALLBACK_EC_KEY 配套的备用自签名证书。
const FALLBACK_CERT =
  '-----BEGIN CERTIFICATE-----\n' +
  'MIIBejCCASGgAwIBAgIUfWeQL3556PNJLp/veCFxGNj9crkwCgYIKoZIzj0EAwIw\n' +
  'EzERMA8GA1UEAwwIYmluZy5jb20wHhcNMjUwOTE4MTgyMDIyWhcNMzUwOTE2MTgy\n' +
  'MDIyWjATMREwDwYDVQQDDAhiaW5nLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH\n' +
  'A0IABNZB2nz49O6yRvh26B9npACOK/nuky9/BlgEgDZ54Ga3qEAxdegEWv07Mi8h\n' +
  'aD5IS8Um3oR/zQRIx7UmRmg4TKmjUzBRMB0GA1UdDgQWBBTV1cFID7UISE7PLTBR\n' +
  'BfGbgkrMNzAfBgNVHSMEGDAWgBTV1cFID7UISE7PLTBRBfGbgkrMNzAPBgNVHRMB\n' +
  'Af8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIAIDAJvg0vd/ytrQVvEcSm6XTlB+\n' +
  'eQ6OFb9LbLYL9f+sAiAffoMbi4y/0YUSlTtz7as9S8/lciBF5VCUoVIKS+vX2g==\n' +
  '-----END CERTIFICATE-----\n';

// 确保证书和私钥存在：优先调用 openssl 生成；不可用时写入脚本内置的备用证书。
function ensureTlsCertificates(certPath, keyPath) {
  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) return;
  fs.mkdirSync(path.dirname(certPath), { recursive: true });
  try {
    execSync('openssl version', { stdio: 'ignore' });
    execSync(`openssl ecparam -genkey -name prime256v1 -out "${keyPath}"`, { stdio: 'ignore' });
    execSync(`openssl req -new -x509 -days 3650 -key "${keyPath}" -out "${certPath}" -subj "/CN=bing.com"`, { stdio: 'ignore' });
    return;
  } catch (e) { /* openssl not available */ }
  fs.writeFileSync(keyPath, FALLBACK_EC_KEY);
  fs.writeFileSync(certPath, FALLBACK_CERT);
}

// 计算证书 SHA-256 指纹；优先使用 openssl，缺少 openssl 时使用 Node.js crypto。
function getCertificateFingerprint(certPath) {
  // 方案1: 优先用 openssl
  try {
    const result = execSync(
      `openssl x509 -noout -fingerprint -sha256 -in "${certPath}"`,
      { encoding: 'utf8', timeout: 3000 }
    ).trim();
    const match = result.match(/=(.+)$/);
    if (match && match[1]) {
      return match[1].toUpperCase();
    }
  } catch (e) {
    // openssl 不可用，继续用 Node.js crypto
  }

  // 方案2: Node.js crypto 兜底
  try {
    const certData = fs.readFileSync(certPath, 'utf8');
    const derMatch = certData.match(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/);
    if (!derMatch) return '';
    const derBase64 = derMatch[1].replace(/\s/g, '');
    const derBuffer = Buffer.from(derBase64, 'base64');
    const hash = crypto.createHash('sha256').update(derBuffer).digest('hex');
    return hash.match(/.{2}/g).join(':').toUpperCase();
  } catch (error) {
    console.error('Failed to calculate certificate fingerprint:', error);
    return '';
  }
}

// 生成 Xray 服务端配置：三种 WS 入站默认启用，Reality/HY2/SOCKS5 按端口变量选配。
async function generateConfig() {
  const config = {
    log: { access: '/dev/null', error: '/dev/null', loglevel: 'none' },
    inbounds: [
      { tag: 'vless-fallback-in', port: ARGO_PORT, listen: '::', protocol: 'vless', settings: { clients: [{ id: UUID, flow: 'xtls-rprx-vision' }], decryption: 'none', fallbacks: [{ dest: 3001 }, { path: "/vless-argo", dest: 3002 }, { path: "/vmess-argo", dest: 3003 }, { path: "/trojan-argo", dest: 3004 }] }, streamSettings: { network: 'tcp' } },
      { tag: 'vless-tcp-in', port: 3001, listen: "127.0.0.1", protocol: "vless", settings: { clients: [{ id: UUID }], decryption: "none" }, streamSettings: { network: "tcp", security: "none" } },
      { tag: 'vless-ws-in', port: 3002, listen: "127.0.0.1", protocol: "vless", settings: { clients: [{ id: UUID, level: 0 }], decryption: "none" }, streamSettings: { network: "ws", security: "none", wsSettings: { path: "/vless-argo" } }, sniffing: { enabled: true, destOverride: ["http", "tls", "quic"], metadataOnly: false } },
      { tag: 'vmess-ws-in', port: 3003, listen: "127.0.0.1", protocol: "vmess", settings: { clients: [{ id: UUID, alterId: 0 }] }, streamSettings: { network: "ws", wsSettings: { path: "/vmess-argo" } }, sniffing: { enabled: true, destOverride: ["http", "tls", "quic"], metadataOnly: false } },
      { tag: 'trojan-ws-in', port: 3004, listen: "127.0.0.1", protocol: "trojan", settings: { clients: [{ password: UUID }] }, streamSettings: { network: "ws", security: "none", wsSettings: { path: "/trojan-argo" } }, sniffing: { enabled: true, destOverride: ["http", "tls", "quic"], metadataOnly: false } },
    ],
    dns: { servers: ["https+local://8.8.8.8/dns-query"] },
    outbounds: [{ protocol: "freedom", tag: "direct" }, { protocol: "blackhole", tag: "block" }]
  };

  // VLESS Reality 配置
  if (isValidPort(REALITY_PORT)) {
    config.inbounds.push({
      tag: "vless-in",
      listen: "::",
      port: parseInt(REALITY_PORT),
      protocol: "vless",
      settings: {
        clients: [{ id: UUID, flow: "xtls-rprx-vision" }],
        decryption: "none"
      },
      streamSettings: {
        network: "raw",
        security: "reality",
        realitySettings: {
          show: false,
          dest: "www.iij.ad.jp:443",
          xver: 0,
          serverNames: ["www.iij.ad.jp"],
          privateKey: privateKey,
          shortIds: [""]
        }
      }
    });
  }

  // Hysteria2 配置
  if (isValidPort(HY2_PORT)) {
    config.inbounds.push({
      tag: "hysteria-in",
      listen: "::",
      port: parseInt(HY2_PORT),
      protocol: "hysteria",
      settings: {
        version: 2,
        clients: [{ auth: UUID }]
      },
      streamSettings: {
        network: "hysteria",
        hysteriaSettings: {
          version: 2,
          masquerade: {
            type: "proxy",
            url: "https://bing.com"
          }
        },
        security: "tls",
        tlsSettings: {
          alpn: ["h3"],
          certificates: [
            {
              certificateFile: certPath,
              keyFile: keyPath
            }
          ]
        }
      }
    });
  }

  // S5 配置
  if (isValidPort(S5_PORT)) {
    config.inbounds.push({
      tag: "s5-in",
      listen: "::",
      port: parseInt(S5_PORT),
      protocol: "socks",
      settings: {
        auth: "password",
        accounts: [
          {
            user: UUID.substring(0, 8),
            pass: UUID.slice(-12)
          }
        ],
        udp: true
      }
    });
  }

  fs.writeFileSync(path.join(FILE_PATH, 'config.json'), JSON.stringify(config, null, 2));
}

// 判断 CPU 架构，用于选择 ARM64 或 AMD64 的外部二进制文件。
function getSystemArchitecture() {
  const arch = os.arch();
  if (arch === 'arm' || arch === 'arm64' || arch === 'aarch64') {
    return 'arm';
  } else {
    return 'amd';
  }
}

// 下载依赖二进制；当前版本未做 SHA256/签名校验，务必确认下载源可信。
function downloadFile(fileName, fileUrl, callback) {
  const filePath = fileName;
  const tempFilePath = `${filePath}.download`;

  if (!fs.existsSync(FILE_PATH)) {
    fs.mkdirSync(FILE_PATH, { recursive: true });
  }

  const writer = fs.createWriteStream(tempFilePath);

  axios({
    method: 'get',    
    url: fileUrl,
    responseType: 'stream',
  })
    .then(response => {
      response.data.pipe(writer);

      writer.on('finish', () => {
        writer.close((closeError) => {
          if (closeError) {
            const errorMessage = `Download ${path.basename(filePath)} failed: ${closeError.message}`;
            fs.unlink(tempFilePath, () => { });
            console.error(errorMessage);
            callback(errorMessage);
            return;
          }
          try {
            fs.renameSync(tempFilePath, filePath);
          } catch (renameError) {
            const errorMessage = `Download ${path.basename(filePath)} failed: ${renameError.message}`;
            fs.unlink(tempFilePath, () => { });
            console.error(errorMessage);
            callback(errorMessage);
            return;
          }
          console.log(`Download ${path.basename(filePath)} successfully`);
          callback(null, filePath);
        });
      });

      writer.on('error', err => {
        fs.unlink(tempFilePath, () => { });
        const errorMessage = `Download ${path.basename(filePath)} failed: ${err.message}`;
        console.error(errorMessage);
        callback(errorMessage);
      });
    })
    .catch(err => {
      fs.unlink(tempFilePath, () => { });
      const errorMessage = `Download ${path.basename(filePath)} failed: ${err.message}`;
      console.error(errorMessage);
      callback(errorMessage);
    });
}

// 下载并启动 Xray、Cloudflared；仅配置 NEZHA_SERVER 与 NEZHA_KEY 时才启动哪吒 Agent。
async function downloadFilesAndRun() {
  const architecture = getSystemArchitecture();
  const filesToDownload = getFilesForArchitecture(architecture);

  if (filesToDownload.length === 0) {
    console.log(`Can't find a file for the current architecture`);
    return;
  }

  const downloadPromises = filesToDownload.map(fileInfo => {
    return new Promise((resolve, reject) => {
      const tryDownload = (urlIndex) => {
        downloadFile(fileInfo.fileName, fileInfo.fileUrls[urlIndex], (err, filePath) => {
          if (!err) {
            resolve(filePath);
            return;
          }

          if (urlIndex + 1 < fileInfo.fileUrls.length) {
            console.log(`Retrying ${path.basename(fileInfo.fileName)} from backup source`);
            tryDownload(urlIndex + 1);
            return;
          }

          reject(err);
        });
      };

      tryDownload(0);
    });
  });

  try {
    await Promise.all(downloadPromises);
  } catch (err) {
    console.error('Error downloading files:', err);
    return;
  }

  // 给下载的二进制文件增加可执行权限；filePaths 是本次实际下载的文件路径数组。
  function authorizeFiles(filePaths) {
    const newPermissions = 0o775;
    filePaths.forEach(absoluteFilePath => {
      if (fs.existsSync(absoluteFilePath)) {
        try {
          fs.chmodSync(absoluteFilePath, newPermissions);
          console.log(`Empowerment success for ${absoluteFilePath}: ${newPermissions.toString(8)}`);
        } catch (err) {
          console.error(`Empowerment failed for ${absoluteFilePath}: ${err}`);
        }
      }
    });
  }
  const filesToAuthorize = NEZHA_PORT ? [npmPath, webPath, botPath] : [phpPath, webPath, botPath];
  authorizeFiles(filesToAuthorize);

  // 运行ne-zha
  if (NEZHA_SERVER && NEZHA_KEY) {
    if (!NEZHA_PORT) {
      const port = NEZHA_SERVER.includes(':') ? NEZHA_SERVER.split(':').pop() : '';
      const tlsPorts = new Set(['443', '8443', '2096', '2087', '2083', '2053']);
      const nezhatls = tlsPorts.has(port) ? 'true' : 'false';
      const configYaml = `
client_secret: ${NEZHA_KEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: true
ip_report_period: 1800
report_delay: 4
server: ${NEZHA_SERVER}
skip_connection_count: true
skip_procs_count: true
temperature: false
tls: ${nezhatls}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: ${UUID}`;

      fs.writeFileSync(path.join(FILE_PATH, 'config.yaml'), configYaml);

      const command = `nohup ${phpPath} -c "${FILE_PATH}/config.yaml" >/dev/null 2>&1 &`;
      try {
        await exec(command);
        console.log(`${phpName} is running`);
        await new Promise((resolve) => setTimeout(resolve, 1000));
      } catch (error) {
        console.error(`php running error: ${error}`);
      }
    } else {
      let NEZHA_TLS = '';
      const tlsPorts = ['443', '8443', '2096', '2087', '2083', '2053'];
      if (tlsPorts.includes(NEZHA_PORT)) {
        NEZHA_TLS = '--tls';
      }
      const command = `nohup ${npmPath} -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} --disable-auto-update --report-delay 4 --skip-conn --skip-procs >/dev/null 2>&1 &`;
      try {
        await exec(command);
        console.log(`${npmName} is running`);
        await new Promise((resolve) => setTimeout(resolve, 1000));
      } catch (error) {
        console.error(`npm running error: ${error}`);
      }
    }
  } else {
    console.log('NEZHA variable is empty,skip running');
  }

  // 运行xr-ay
  const command1 = `nohup ${webPath} -c ${FILE_PATH}/config.json >/dev/null 2>&1 &`;
  try {
    await exec(command1);
    console.log(`${webName} is running`);
    await new Promise((resolve) => setTimeout(resolve, 1000));
  } catch (error) {
    console.error(`web running error: ${error}`);
  }

  // 运行cloud-fared
  if (fs.existsSync(botPath)) {
    let args;

    if (ARGO_AUTH.match(/^[A-Z0-9a-z=]{120,250}$/)) {
      args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${ARGO_AUTH}`;
    } else if (ARGO_AUTH.match(/TunnelSecret/)) {
      args = `tunnel --edge-ip-version auto --config "${path.resolve(FILE_PATH, 'tunnel.yml')}" run`;
    } else {
      args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile "${path.resolve(bootLogPath)}" --loglevel info --url http://localhost:${ARGO_PORT}`;
    }

    try {
            await exec(`nohup "${path.resolve(botPath)}" ${args} >/dev/null 2>&1 &`);
      console.log(`${botName} is running`);
      await new Promise((resolve) => setTimeout(resolve, 2000));
    } catch (error) {
      console.error(`Error executing command: ${error}`);
    }
  }
  await new Promise((resolve) => setTimeout(resolve, 5000));
}

// 按架构选择主/备用下载源；哪吒二进制只在用户显式启用哪吒时下载。
function getFilesForArchitecture(architecture) {
  const baseUrl = architecture === 'arm' ? 'https://arm64.oooen.com' : 'https://amd64.oooen.com';
  const backupUrl = architecture === 'arm' ? 'https://arm64.ssss.nyc.mn' : 'https://amd64.ssss.nyc.mn';
  const baseFiles = [
    { fileName: webPath, fileUrls: [`${baseUrl}/web`, `${backupUrl}/web`] },
    { fileName: botPath, fileUrls: [`${baseUrl}/bot`, `${backupUrl}/bot`] }
  ];

  if (NEZHA_SERVER && NEZHA_KEY) {
    if (NEZHA_PORT) {
      baseFiles.unshift({
        fileName: npmPath,
        fileUrls: [`${baseUrl}/agent`, `${backupUrl}/agent`]
      });
    } else {
      baseFiles.unshift({
        fileName: phpPath,
        fileUrls: [`${baseUrl}/v1`, `${backupUrl}/v1`]
      });
    }
  }

  return baseFiles;
}

// 写入固定 Cloudflare Tunnel 凭据及 tunnel.yml；支持 credentials JSON 或 Token。
// 将固定 Tunnel 凭据落盘；未提供固定凭据时由 cloudflared 创建临时 Quick Tunnel。
function argoType() {
  if (!ARGO_AUTH || !ARGO_DOMAIN) {
    console.log("ARGO_DOMAIN or ARGO_AUTH is empty, use quick tunnels");
    return;
  }

  if (ARGO_AUTH.includes('TunnelSecret')) {
    fs.writeFileSync(path.join(FILE_PATH, 'tunnel.json'), ARGO_AUTH);
    const tunnelYaml = `
  tunnel: ${ARGO_AUTH.split('"')[11]}
  credentials-file: ${path.join(FILE_PATH, 'tunnel.json')}
  protocol: http2

  ingress:
    - hostname: ${ARGO_DOMAIN}
      service: http://localhost:${ARGO_PORT}
      originRequest:
        noTLSVerify: true
    - service: http_status:404
  `;
    fs.writeFileSync(path.join(FILE_PATH, 'tunnel.yml'), tunnelYaml);
  } else {
    console.log(`Using token connect to tunnel, please set ${ARGO_PORT} in clouudflare`);
  }
}

// 轮询 cloudflared 日志，最多等待 timeoutMs 毫秒，返回包含 trycloudflare.com 的日志内容。
async function waitForQuickTunnelLog(timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      if (fs.existsSync(bootLogPath)) {
        const content = fs.readFileSync(bootLogPath, 'utf-8');
        if (/trycloudflare\.com/.test(content)) return content;
      }
    } catch (error) {
      // 日志文件可能仍在创建中
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  return '';
}

// 取得固定域名或从 cloudflared 日志提取临时域名，再生成节点订阅与 Clash 配置。
async function extractDomains() {
  let argoDomain;

  if (ARGO_AUTH && ARGO_DOMAIN) {
    argoDomain = ARGO_DOMAIN;
    console.log('ARGO_DOMAIN:', argoDomain);
    await generateLinks(argoDomain);
  } else {
    try {
      const fileContent = await waitForQuickTunnelLog();
      const lines = fileContent.split('\n');
      const argoDomains = [];
      lines.forEach((line) => {
        const domainMatch = line.match(/https?:\/\/([^ ]*trycloudflare\.com)\/?/);
        if (domainMatch) {
          const domain = domainMatch[1];
          argoDomains.push(domain);
        }
      });

      if (argoDomains.length > 0) {
        argoDomain = argoDomains[0];
        console.log('ArgoDomain:', argoDomain);
        await generateLinks(argoDomain);
      } else {
        console.log('ArgoDomain not found, re-running bot to obtain ArgoDomain');
        fs.unlinkSync(path.join(FILE_PATH, 'boot.log'));
        // Quick Tunnel 未能从日志提取域名时，结束旧 cloudflared 进程后重启一次。
        async function killBotProcess() {
          try {
            if (process.platform === 'win32') {
              await exec(`taskkill /f /im ${botName}.exe > nul 2>&1`);
            } else {
              await exec(`pkill -f "[${botName.charAt(0)}]${botName.substring(1)}" > /dev/null 2>&1`);
            }
          } catch (error) {
            // 忽略输出
          }
        }
        killBotProcess();
        await new Promise((resolve) => setTimeout(resolve, 3000));
        const args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile "${path.resolve(bootLogPath)}" --loglevel info --url http://localhost:${ARGO_PORT}`;
        try {
          await exec(`nohup "${path.resolve(botPath)}" ${args} >/dev/null 2>&1 &`);
          console.log(`${botName} is running`);
          await new Promise((resolve) => setTimeout(resolve, 6000));
          await extractDomains();
        } catch (error) {
          console.error(`Error executing command: ${error}`);
        }
      }
    } catch (error) {
      console.error('Error reading boot.log:', error);
    }
  }
}

// 获取公网 IP：优先使用 SERVER_IP；未设置时请求 ip.sb，供 HY2/Reality/SOCKS5 节点使用。
// 获取 HY2/Reality/SOCKS5 直连节点所需的公网 IP。
async function getServerIP() {
  if (SERVER_IP_OVERRIDE) return SERVER_IP_OVERRIDE;
  let serverIP = '';
  try {
    const ipv4Response = await axios.get('https://ipv4.ip.sb', { timeout: 3000 });
    serverIP = ipv4Response.data.trim();
  } catch (err) {
    try {
      serverIP = execSync('curl -sm 3 https://ipv4.ip.sb').toString().trim();
    } catch (curlErr) {
      try {
        const ipv6Response = await axios.get('https://ipv6.ip.sb', { timeout: 3000 });
        serverIP = `[${ipv6Response.data.trim()}]`;
      } catch (ipv6AxiosErr) {
        try {
          serverIP = `[${execSync('curl -sm 3 https://ipv6.ip.sb').toString().trim()}]`;
        } catch (ipv6CurlErr) {
          console.error('Failed to get IP address:', ipv6CurlErr.message);
        }
      }
    }
  }
  return serverIP;
}

// 生成分享链接、Base64 订阅、明文节点清单和 Clash/Mihomo YAML；只保存在本地，不上传。
// 按当前启用协议生成分享 URI、Base64 订阅和 Mihomo YAML。
async function generateLinks(argoDomain) {
  const nodeName = NAME || 'Node';
  // 只有启用 HY2/Reality/SOCKS5 时才需要查询直连公网 IP，纯 WS/Argo 节点不额外请求 IP 查询站。
  const needsDirectIP = isValidPort(HY2_PORT) || isValidPort(REALITY_PORT) || isValidPort(S5_PORT);
  const SERVER_IP = needsDirectIP ? await getServerIP() : '';
  const CLASH_SERVER_IP = SERVER_IP.replace(/^\[|\]$/g, ''); // Clash 的 server 字段使用裸 IPv6 地址，不带 URI 方括号

  return new Promise((resolve) => {
    setTimeout(() => {
      const VMESS = { v: '2', ps: `${nodeName}`, add: CFIP, port: CFPORT, id: UUID, aid: '0', scy: 'auto', net: 'ws', type: 'none', host: argoDomain, path: '/vmess-argo?ed=2560', tls: 'tls', sni: argoDomain, alpn: '', fp: 'firefox' };
      let subTxt = `
vless://${UUID}@${CFIP}:${CFPORT}?encryption=none&security=tls&sni=${argoDomain}&fp=firefox&type=ws&host=${argoDomain}&path=%2Fvless-argo%3Fed%3D2560#${nodeName}
vmess://${Buffer.from(JSON.stringify(VMESS)).toString('base64')}

trojan://${UUID}@${CFIP}:${CFPORT}?security=tls&sni=${argoDomain}&fp=firefox&type=ws&host=${argoDomain}&path=%2Ftrojan-argo%3Fed%3D2560#${nodeName}
    `;

      // HY2_PORT是有效端口号时生成hysteria2节点
      if (isValidPort(HY2_PORT)) {
        const fingerprint = getCertificateFingerprint(certPath);
        const fingerprintParam = fingerprint ? `&pinSHA256=${encodeURIComponent(fingerprint)}` : '';
        const hysteriaNode = `\nhysteria2://${UUID}@${SERVER_IP}:${HY2_PORT}/?sni=www.bing.com&insecure=0&alpn=h3&obfs=none${fingerprintParam}#${nodeName}`;
        subTxt += hysteriaNode;
      }

      // REALITY_PORT是有效端口号时生成reality节点
      if (isValidPort(REALITY_PORT)) {
        const vlessNode = `\nvless://${UUID}@${SERVER_IP}:${REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.iij.ad.jp&fp=firefox&pbk=${publicKey}&type=tcp&headerType=none#${nodeName}`;
        subTxt += vlessNode;
      }

      // S5_PORT是有效端口号时生成socks5节点
      if (isValidPort(S5_PORT)) {
        const S5_AUTH = Buffer.from(`${UUID.substring(0, 8)}:${UUID.slice(-12)}`).toString('base64');
        const s5Node = `\nsocks://${S5_AUTH}@${SERVER_IP}:${S5_PORT}#${nodeName}`;
        subTxt += s5Node;
      }

      // 生成 Clash Meta / Mihomo 可用的 YAML 配置
      const clashProxies = [];
      const clashName = (suffix) => `${nodeName} ${suffix}`;
      const q = (value) => JSON.stringify(String(value)); // JSON 字符串也是合法 YAML 字符串

      clashProxies.push({
        type: 'vless', name: clashName('VLESS-WS'), server: CFIP, port: Number(CFPORT),
        uuid: UUID, tls: true, servername: argoDomain, network: 'ws',
        'client-fingerprint': 'firefox', 'skip-cert-verify': false,
        'ws-opts': { path: '/vless-argo?ed=2560', headers: { Host: argoDomain } }
      });
      clashProxies.push({
        type: 'vmess', name: clashName('VMess-WS'), server: CFIP, port: Number(CFPORT),
        uuid: UUID, alterId: 0, cipher: 'auto', tls: true, servername: argoDomain,
        network: 'ws', 'client-fingerprint': 'firefox',
        'ws-opts': { path: '/vmess-argo?ed=2560', headers: { Host: argoDomain } }
      });
      clashProxies.push({
        type: 'trojan', name: clashName('Trojan-WS'), server: CFIP, port: Number(CFPORT),
        password: UUID, tls: true, servername: argoDomain, 'skip-cert-verify': false,
        network: 'ws', 'ws-opts': { path: '/trojan-argo?ed=2560', headers: { Host: argoDomain } }
      });

      if (isValidPort(HY2_PORT)) {
        clashProxies.push({
          type: 'hysteria2', name: clashName('Hysteria2'), server: CLASH_SERVER_IP,
          port: Number(HY2_PORT), password: UUID, tls: true,
          servername: 'www.bing.com', 'skip-cert-verify': true, alpn: ['h3']
        });
      }
      if (isValidPort(REALITY_PORT)) {
        clashProxies.push({
          type: 'vless', name: clashName('VLESS-Reality'), server: CLASH_SERVER_IP,
          port: Number(REALITY_PORT), uuid: UUID, network: 'tcp', tls: true,
          servername: 'www.iij.ad.jp', 'client-fingerprint': 'firefox',
          'skip-cert-verify': false, udp: true,
          flow: 'xtls-rprx-vision', 'reality-opts': { 'public-key': publicKey, 'short-id': '' }
        });
      }
      if (isValidPort(S5_PORT)) {
        clashProxies.push({
          type: 'socks5', name: clashName('SOCKS5'), server: CLASH_SERVER_IP,
          port: Number(S5_PORT), username: UUID.substring(0, 8), password: UUID.slice(-12),
          udp: true
        });
      }

      const yamlProxy = (proxy) => {
        const lines = [`  - type: ${proxy.type}`, `    name: ${q(proxy.name)}`, `    server: ${q(proxy.server)}`, `    port: ${proxy.port}`];
        for (const [key, value] of Object.entries(proxy)) {
          if (['type', 'name', 'server', 'port'].includes(key)) continue;
          if (Array.isArray(value)) {
            lines.push(`    ${key}:`, ...value.map(v => `      - ${q(v)}`));
          } else if (value && typeof value === 'object') {
            lines.push(`    ${key}:`);
            for (const [nestedKey, nestedValue] of Object.entries(value)) {
              if (nestedValue && typeof nestedValue === 'object' && !Array.isArray(nestedValue)) {
                lines.push(`      ${nestedKey}:`);
                for (const [innerKey, innerValue] of Object.entries(nestedValue)) lines.push(`        ${innerKey}: ${q(innerValue)}`);
              } else {
                lines.push(`      ${nestedKey}: ${q(nestedValue)}`);
              }
            }
          } else if (typeof value === 'string') {
            lines.push(`    ${key}: ${q(value)}`);
          } else {
            lines.push(`    ${key}: ${value}`);
          }
        }
        return lines.join('\n');
      };

      const proxyNames = clashProxies.map(proxy => proxy.name);
      const clashTxt = [
        'mixed-port: 7890', 'allow-lan: false', 'mode: rule', 'log-level: warning', 'ipv6: true',
        'dns:', '  enable: true', '  enhanced-mode: redir-host', '  nameserver:',
        '    - 223.5.5.5', '    - 1.1.1.1', 'proxies:',
        ...clashProxies.map(yamlProxy),
        'proxy-groups:', '  - name: PROXY', '    type: select', '    proxies:',
        ...proxyNames.map(name => `      - ${q(name)}`),
        '      - DIRECT', 'rules:', '  - DOMAIN,localhost,DIRECT',
        '  - DOMAIN-SUFFIX,local,DIRECT', '  - DOMAIN-SUFFIX,lan,DIRECT',
        '  - DOMAIN-SUFFIX,cn,DIRECT', '  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve',
        '  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve',
        '  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve',
        '  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve',
        '  - IP-CIDR6,::1/128,DIRECT,no-resolve',
        '  - IP-CIDR6,fc00::/7,DIRECT,no-resolve', '  - MATCH,PROXY', ''
      ].join('\n');

      // 订阅保留原有 Base64 格式；Clash 配置另存为文件并直接打印，方便复制
      fs.writeFileSync(subPath, Buffer.from(subTxt).toString('base64'));
      fs.writeFileSync(listPath, subTxt, 'utf8');
      fs.writeFileSync(clashPath, clashTxt, 'utf8');
      console.log(`${FILE_PATH}/sub.txt saved successfully`);
      console.log(`${FILE_PATH}/clash.yaml saved successfully`);
      if (PRINT_CLASH) {
        alwaysLog('\n========== Clash 配置开始（复制以下内容导入 Mihomo / Clash Meta）==========\n');
        alwaysLog(clashTxt);
        alwaysLog('========== Clash 配置结束 ==========\n');
      } else {
        alwaysLog(`Clash YAML 已生成：${clashPath}；可访问 /clash 获取。默认不打印凭据，避免泄露到部署日志。`);
      }
      // 将原有 Base64 订阅内容保存到全局变量，供 HTTP /sub 订阅路由使用
      subContent = Buffer.from(subTxt).toString('base64');
      resolve(subTxt);
    }, 2000);
  });
}

// 90 秒后清理临时二进制与服务端配置；保留 sub.txt、clash.yaml 供用户读取。
// 延迟清理临时可执行文件和运行配置；订阅文件与 Clash YAML 不在删除列表中。
function cleanFiles() {
  setTimeout(() => {
    const filesToDelete = [bootLogPath, configPath, webPath, botPath, listPath, certPath, keyPath];

    if (NEZHA_PORT) {
      filesToDelete.push(npmPath);
    } else if (NEZHA_SERVER && NEZHA_KEY) {
      filesToDelete.push(phpPath);
    }

    if (process.platform === 'win32') {
      exec(`del /f /q ${filesToDelete.join(' ')} > nul 2>&1`, (error) => {
        console.clear();
        alwaysLog('App is running');
        console.log('Thank you for using this script, enjoy!');
      });
    } else {
      exec(`rm -rf ${filesToDelete.join(' ')} >/dev/null 2>&1`, (error) => {
        console.clear();
        alwaysLog('App is running');
        console.log('Thank you for using this script, enjoy!');
      });
    }
  }, 90000);
}

// 可选自动访问用户自己的 URL：不再向第三方“保活登记服务”提交 PROJECT_URL。
// 这是尽力而为的定时请求，不能保证托管平台不休眠；需遵守平台规则。
function startAutoAccess() {
  if (!AUTO_ACCESS || !PROJECT_URL) {
    console.log('AUTO_ACCESS 未启用或 PROJECT_URL 为空，跳过定时访问');
    return;
  }
  const visit = async () => {
    try {
      const response = await axios.get(PROJECT_URL, { timeout: 10000, maxRedirects: 3 });
      console.log(`AUTO_ACCESS 请求完成：HTTP ${response.status}`);
    } catch (error) {
      console.error(`AUTO_ACCESS 请求失败：${error.message}`);
    }
  };
    visit(); // 启动后先访问一次
  const timer = setInterval(visit, AUTO_ACCESS_INTERVAL_MS);
  if (typeof timer.unref === 'function') timer.unref();
}

// 主运行逻辑
async function startserver() {
  try {
    cleanupOldFiles();
    argoType();

    // 生成 Reality 密钥对 (仅当 REALITY_PORT 开启才生成)
    if (isValidPort(REALITY_PORT)) {
      generateOrLoadKeyPair();
    }

    // 生成 TLS 证书 (用于 Hysteria2)
    if (isValidPort(HY2_PORT)) {
      ensureTlsCertificates(certPath, keyPath);
    }

    await generateConfig();
    await downloadFilesAndRun();
    await extractDomains();
    cleanFiles(); // 等节点和隧道启动流程完成后再开始延迟清理，避免下载慢时提前删文件
    startAutoAccess();
  } catch (error) {
    console.error('Error in startserver:', error);
  }
}
startserver().catch(error => {
  console.error('Unhandled error in startserver:', error);
});

// HTTP 服务：/health 用于存活探测；/sub、/clash 是敏感配置接口，可用 ACCESS_TOKEN 保护。
const server = http.createServer(async (req, res) => {
  const requestUrl = new URL(req.url, `http://127.0.0.1:${PORT}`);
  const urlPath = requestUrl.pathname;

  // 健康检查仅证明 Node HTTP 服务能响应，不代表 Xray、Cloudflare Tunnel 或代理链路可用。
  if (urlPath === `/${HEALTH_PATH.replace(/^\/+/, '')}`) {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify({ status: 'ok', uptime: Math.floor(process.uptime()), timestamp: new Date().toISOString() }));
    return;
  }

  // 设置 ACCESS_TOKEN 后，订阅与 Clash 配置可通过 ?token=... 或 Bearer Token 访问。
  if (ACCESS_TOKEN && (urlPath === '/clash' || urlPath === `/${SUB_PATH}`)) {
    const bearer = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    const queryToken = requestUrl.searchParams.get('token') || '';
    if (bearer !== ACCESS_TOKEN && queryToken !== ACCESS_TOKEN) {
      res.writeHead(401, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Unauthorized');
      return;
    }
  }

  // Clash 配置路由：可通过 http(s)://域名/clash 直接获取完整 YAML
  if (urlPath === '/clash') {
    try {
      const clashText = fs.readFileSync(clashPath, 'utf8');
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(clashText);
    } catch (err) {
      res.writeHead(503, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Clash config not ready yet, please try again later.');
    }
    return;
  }

  // Base64 订阅路由；其中包含节点 UUID/密码，不要公开分享。
  if (urlPath === `/${SUB_PATH}`) {
    if (subContent) {
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(subContent);
    } else {
      try {
        const fileContent = fs.readFileSync(subPath, 'utf-8');
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end(fileContent);
      } catch (err) {
        res.writeHead(503, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Subscription content not yet available, please try again later.');
      }
    }
    return;
  }

  // 根路由: /
  if (urlPath === '/') {
    try {
      const filePath = path.join(__dirname, 'index.html');
      const data = await fs.promises.readFile(filePath, 'utf8');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(data);
    } catch (err) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end("Hello world!<br><br>You can access /{SUB_PATH}(Default: /sub) to get your nodes!");
    }
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Not Found');
});

server.listen(PORT, '0.0.0.0', () => {
  alwaysLog(`HTTP 服务已启动：端口 ${PORT}`);
  alwaysLog(`健康检查：/${HEALTH_PATH.replace(/^\/+/, '')}`);
  alwaysLog(`订阅接口：/${SUB_PATH}${ACCESS_TOKEN ? '（已启用访问口令）' : '（公开可访问；建议设置 ACCESS_TOKEN）'}`);
  alwaysLog(`Clash 接口：/clash${ACCESS_TOKEN ? '（已启用访问口令）' : '（公开可访问；建议设置 ACCESS_TOKEN）'}`);
});
