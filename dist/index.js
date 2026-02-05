import * as yi from "os";
import vn, { EOL as Di } from "os";
import "crypto";
import * as Yn from "fs";
import { promises as Ri, existsSync as ki, readFileSync as bi } from "fs";
import "path";
import Jn from "http";
import * as Fi from "https";
import Hn from "https";
import "net";
import Ti from "tls";
import Si from "events";
import "assert";
import Ui from "util";
import He from "node:assert";
import WA from "node:net";
import qA from "node:http";
import tA from "node:stream";
import sA from "node:buffer";
import $e from "node:util";
import Ni from "node:querystring";
import kA from "node:events";
import Mi from "node:diagnostics_channel";
import Li from "node:tls";
import ts from "node:zlib";
import Gi from "node:perf_hooks";
import Vn from "node:util/types";
import Pn from "node:worker_threads";
import vi from "node:url";
import bA from "node:async_hooks";
import Yi from "node:console";
import Ji from "node:dns";
import Hi from "string_decoder";
import "child_process";
import "timers";
function xn(e) {
  return e == null ? "" : typeof e == "string" || e instanceof String ? e : JSON.stringify(e);
}
function Vi(e) {
  return Object.keys(e).length ? {
    title: e.title,
    file: e.file,
    line: e.startLine,
    endLine: e.endLine,
    col: e.startColumn,
    endColumn: e.endColumn
  } : {};
}
function Pi(e, r, t) {
  const o = new xi(e, r, t);
  process.stdout.write(o.toString() + yi.EOL);
}
const Is = "::";
class xi {
  constructor(r, t, o) {
    r || (r = "missing.command"), this.command = r, this.properties = t, this.message = o;
  }
  toString() {
    let r = Is + this.command;
    if (this.properties && Object.keys(this.properties).length > 0) {
      r += " ";
      let t = !0;
      for (const o in this.properties)
        if (this.properties.hasOwnProperty(o)) {
          const A = this.properties[o];
          A && (t ? t = !1 : r += ",", r += `${o}=${_i(A)}`);
        }
    }
    return r += `${Is}${Oi(this.message)}`, r;
  }
}
function Oi(e) {
  return xn(e).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}
function _i(e) {
  return xn(e).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A").replace(/:/g, "%3A").replace(/,/g, "%2C");
}
var Cs = typeof globalThis < "u" ? globalThis : typeof window < "u" ? window : typeof global < "u" ? global : typeof self < "u" ? self : {}, uA = {}, ds;
function Wi() {
  if (ds) return uA;
  ds = 1;
  var e = Ti, r = Jn, t = Hn, o = Si, A = Ui;
  uA.httpOverHttp = n, uA.httpsOverHttp = c, uA.httpOverHttps = g, uA.httpsOverHttps = Q;
  function n(C) {
    var w = new B(C);
    return w.request = r.request, w;
  }
  function c(C) {
    var w = new B(C);
    return w.request = r.request, w.createSocket = i, w.defaultPort = 443, w;
  }
  function g(C) {
    var w = new B(C);
    return w.request = t.request, w;
  }
  function Q(C) {
    var w = new B(C);
    return w.request = t.request, w.createSocket = i, w.defaultPort = 443, w;
  }
  function B(C) {
    var w = this;
    w.options = C || {}, w.proxyOptions = w.options.proxy || {}, w.maxSockets = w.options.maxSockets || r.Agent.defaultMaxSockets, w.requests = [], w.sockets = [], w.on("free", function(b, U, G, M) {
      for (var N = a(U, G, M), d = 0, l = w.requests.length; d < l; ++d) {
        var p = w.requests[d];
        if (p.host === N.host && p.port === N.port) {
          w.requests.splice(d, 1), p.request.onSocket(b);
          return;
        }
      }
      b.destroy(), w.removeSocket(b);
    });
  }
  A.inherits(B, o.EventEmitter), B.prototype.addRequest = function(w, D, b, U) {
    var G = this, M = h({ request: w }, G.options, a(D, b, U));
    if (G.sockets.length >= this.maxSockets) {
      G.requests.push(M);
      return;
    }
    G.createSocket(M, function(N) {
      N.on("free", d), N.on("close", l), N.on("agentRemove", l), w.onSocket(N);
      function d() {
        G.emit("free", N, M);
      }
      function l(p) {
        G.removeSocket(N), N.removeListener("free", d), N.removeListener("close", l), N.removeListener("agentRemove", l);
      }
    });
  }, B.prototype.createSocket = function(w, D) {
    var b = this, U = {};
    b.sockets.push(U);
    var G = h({}, b.proxyOptions, {
      method: "CONNECT",
      path: w.host + ":" + w.port,
      agent: !1,
      headers: {
        host: w.host + ":" + w.port
      }
    });
    w.localAddress && (G.localAddress = w.localAddress), G.proxyAuth && (G.headers = G.headers || {}, G.headers["Proxy-Authorization"] = "Basic " + new Buffer(G.proxyAuth).toString("base64")), u("making CONNECT request");
    var M = b.request(G);
    M.useChunkedEncodingByDefault = !1, M.once("response", N), M.once("upgrade", d), M.once("connect", l), M.once("error", p), M.end();
    function N(s) {
      s.upgrade = !0;
    }
    function d(s, E, f) {
      process.nextTick(function() {
        l(s, E, f);
      });
    }
    function l(s, E, f) {
      if (M.removeAllListeners(), E.removeAllListeners(), s.statusCode !== 200) {
        u(
          "tunneling socket could not be established, statusCode=%d",
          s.statusCode
        ), E.destroy();
        var I = new Error("tunneling socket could not be established, statusCode=" + s.statusCode);
        I.code = "ECONNRESET", w.request.emit("error", I), b.removeSocket(U);
        return;
      }
      if (f.length > 0) {
        u("got illegal response body from proxy"), E.destroy();
        var I = new Error("got illegal response body from proxy");
        I.code = "ECONNRESET", w.request.emit("error", I), b.removeSocket(U);
        return;
      }
      return u("tunneling connection has established"), b.sockets[b.sockets.indexOf(U)] = E, D(E);
    }
    function p(s) {
      M.removeAllListeners(), u(
        `tunneling socket could not be established, cause=%s
`,
        s.message,
        s.stack
      );
      var E = new Error("tunneling socket could not be established, cause=" + s.message);
      E.code = "ECONNRESET", w.request.emit("error", E), b.removeSocket(U);
    }
  }, B.prototype.removeSocket = function(w) {
    var D = this.sockets.indexOf(w);
    if (D !== -1) {
      this.sockets.splice(D, 1);
      var b = this.requests.shift();
      b && this.createSocket(b, function(U) {
        b.request.onSocket(U);
      });
    }
  };
  function i(C, w) {
    var D = this;
    B.prototype.createSocket.call(D, C, function(b) {
      var U = C.request.getHeader("host"), G = h({}, D.options, {
        socket: b,
        servername: U ? U.replace(/:.*$/, "") : C.host
      }), M = e.connect(0, G);
      D.sockets[D.sockets.indexOf(b)] = M, w(M);
    });
  }
  function a(C, w, D) {
    return typeof C == "string" ? {
      host: C,
      port: w,
      localAddress: D
    } : C;
  }
  function h(C) {
    for (var w = 1, D = arguments.length; w < D; ++w) {
      var b = arguments[w];
      if (typeof b == "object")
        for (var U = Object.keys(b), G = 0, M = U.length; G < M; ++G) {
          var N = U[G];
          b[N] !== void 0 && (C[N] = b[N]);
        }
    }
    return C;
  }
  var u;
  return process.env.NODE_DEBUG && /\btunnel\b/.test(process.env.NODE_DEBUG) ? u = function() {
    var C = Array.prototype.slice.call(arguments);
    typeof C[0] == "string" ? C[0] = "TUNNEL: " + C[0] : C.unshift("TUNNEL:"), console.error.apply(console, C);
  } : u = function() {
  }, uA.debug = u, uA;
}
var at, fs;
function On() {
  return fs || (fs = 1, at = Wi()), at;
}
On();
var me = {}, ct, ps;
function Oe() {
  return ps || (ps = 1, ct = {
    kClose: /* @__PURE__ */ Symbol("close"),
    kDestroy: /* @__PURE__ */ Symbol("destroy"),
    kDispatch: /* @__PURE__ */ Symbol("dispatch"),
    kUrl: /* @__PURE__ */ Symbol("url"),
    kWriting: /* @__PURE__ */ Symbol("writing"),
    kResuming: /* @__PURE__ */ Symbol("resuming"),
    kQueue: /* @__PURE__ */ Symbol("queue"),
    kConnect: /* @__PURE__ */ Symbol("connect"),
    kConnecting: /* @__PURE__ */ Symbol("connecting"),
    kKeepAliveDefaultTimeout: /* @__PURE__ */ Symbol("default keep alive timeout"),
    kKeepAliveMaxTimeout: /* @__PURE__ */ Symbol("max keep alive timeout"),
    kKeepAliveTimeoutThreshold: /* @__PURE__ */ Symbol("keep alive timeout threshold"),
    kKeepAliveTimeoutValue: /* @__PURE__ */ Symbol("keep alive timeout"),
    kKeepAlive: /* @__PURE__ */ Symbol("keep alive"),
    kHeadersTimeout: /* @__PURE__ */ Symbol("headers timeout"),
    kBodyTimeout: /* @__PURE__ */ Symbol("body timeout"),
    kServerName: /* @__PURE__ */ Symbol("server name"),
    kLocalAddress: /* @__PURE__ */ Symbol("local address"),
    kHost: /* @__PURE__ */ Symbol("host"),
    kNoRef: /* @__PURE__ */ Symbol("no ref"),
    kBodyUsed: /* @__PURE__ */ Symbol("used"),
    kBody: /* @__PURE__ */ Symbol("abstracted request body"),
    kRunning: /* @__PURE__ */ Symbol("running"),
    kBlocking: /* @__PURE__ */ Symbol("blocking"),
    kPending: /* @__PURE__ */ Symbol("pending"),
    kSize: /* @__PURE__ */ Symbol("size"),
    kBusy: /* @__PURE__ */ Symbol("busy"),
    kQueued: /* @__PURE__ */ Symbol("queued"),
    kFree: /* @__PURE__ */ Symbol("free"),
    kConnected: /* @__PURE__ */ Symbol("connected"),
    kClosed: /* @__PURE__ */ Symbol("closed"),
    kNeedDrain: /* @__PURE__ */ Symbol("need drain"),
    kReset: /* @__PURE__ */ Symbol("reset"),
    kDestroyed: /* @__PURE__ */ Symbol.for("nodejs.stream.destroyed"),
    kResume: /* @__PURE__ */ Symbol("resume"),
    kOnError: /* @__PURE__ */ Symbol("on error"),
    kMaxHeadersSize: /* @__PURE__ */ Symbol("max headers size"),
    kRunningIdx: /* @__PURE__ */ Symbol("running index"),
    kPendingIdx: /* @__PURE__ */ Symbol("pending index"),
    kError: /* @__PURE__ */ Symbol("error"),
    kClients: /* @__PURE__ */ Symbol("clients"),
    kClient: /* @__PURE__ */ Symbol("client"),
    kParser: /* @__PURE__ */ Symbol("parser"),
    kOnDestroyed: /* @__PURE__ */ Symbol("destroy callbacks"),
    kPipelining: /* @__PURE__ */ Symbol("pipelining"),
    kSocket: /* @__PURE__ */ Symbol("socket"),
    kHostHeader: /* @__PURE__ */ Symbol("host header"),
    kConnector: /* @__PURE__ */ Symbol("connector"),
    kStrictContentLength: /* @__PURE__ */ Symbol("strict content length"),
    kMaxRedirections: /* @__PURE__ */ Symbol("maxRedirections"),
    kMaxRequests: /* @__PURE__ */ Symbol("maxRequestsPerClient"),
    kProxy: /* @__PURE__ */ Symbol("proxy agent options"),
    kCounter: /* @__PURE__ */ Symbol("socket request counter"),
    kInterceptors: /* @__PURE__ */ Symbol("dispatch interceptors"),
    kMaxResponseSize: /* @__PURE__ */ Symbol("max response size"),
    kHTTP2Session: /* @__PURE__ */ Symbol("http2Session"),
    kHTTP2SessionState: /* @__PURE__ */ Symbol("http2Session state"),
    kRetryHandlerDefaultRetry: /* @__PURE__ */ Symbol("retry agent default retry"),
    kConstruct: /* @__PURE__ */ Symbol("constructable"),
    kListeners: /* @__PURE__ */ Symbol("listeners"),
    kHTTPContext: /* @__PURE__ */ Symbol("http context"),
    kMaxConcurrentStreams: /* @__PURE__ */ Symbol("max concurrent streams"),
    kNoProxyAgent: /* @__PURE__ */ Symbol("no proxy agent"),
    kHttpProxyAgent: /* @__PURE__ */ Symbol("http proxy agent"),
    kHttpsProxyAgent: /* @__PURE__ */ Symbol("https proxy agent")
  }), ct;
}
var gt, ws;
function Ye() {
  if (ws) return gt;
  ws = 1;
  const e = /* @__PURE__ */ Symbol.for("undici.error.UND_ERR");
  class r extends Error {
    constructor(J) {
      super(J), this.name = "UndiciError", this.code = "UND_ERR";
    }
    static [Symbol.hasInstance](J) {
      return J && J[e] === !0;
    }
    [e] = !0;
  }
  const t = /* @__PURE__ */ Symbol.for("undici.error.UND_ERR_CONNECT_TIMEOUT");
  class o extends r {
    constructor(J) {
      super(J), this.name = "ConnectTimeoutError", this.message = J || "Connect Timeout Error", this.code = "UND_ERR_CONNECT_TIMEOUT";
    }
    static [Symbol.hasInstance](J) {
      return J && J[t] === !0;
    }
    [t] = !0;
  }
  const A = /* @__PURE__ */ Symbol.for("undici.error.UND_ERR_HEADERS_TIMEOUT");
  class n extends r {
    constructor(J) {
      super(J), this.name = "HeadersTimeoutError", this.message = J || "Headers Timeout Error", this.code = "UND_ERR_HEADERS_TIMEOUT";
    }
    static [Symbol.hasInstance](J) {
      return J && J[A] === !0;
    }
    [A] = !0;
  }
  const c = /* @__PURE__ */ Symbol.for("undici.error.UND_ERR_HEADERS_OVERFLOW");
  class g extends r {
    constructor(J) {
      super(J), this.name = "HeadersOverflowError", this.message = J || "Headers Overflow Error", this.code = "UND_ERR_HEADERS_OVERFLOW";
    }
    static [Symbol.hasInstance](J) {
      return J && J[c] === !0;
    }
    [c] = !0;
  }
  const Q = /* @__PURE__ */ Symbol.for("undici.error.UND_ERR_BODY_TIMEOUT");
  class B extends r {
    constructor(J) {
      super(J), this.name = "BodyTimeoutError", this.message = J || "Body Timeout Error", this.code = "UND_ERR_BODY_TIMEOUT";
    }
    static [Symbol.hasInstance](J) {
      return J && J[Q] === !0;
    }
    [Q] = !0;
  }
  const i = /* @__PURE__ */ Symbol.for("undici.error.UND_ERR_RESPONSE_STATUS_CODE");
  class a extends r {
    constructor(J, _, P, Z) {
      super(J), this.name = "ResponseStatusCodeError", this.message = J || "Response Status Code Error", this.code = "UND_ERR_RESPONSE_STATUS_CODE", this.body = Z, this.status = _, this.statusCode = _, this.headers = P;
    }
    static [Symbol.hasInstance](J) {
      return J && J[i] === !0;
    }
    [i] = !0;
  }
  const h = /* @__PURE__ */ Symbol.for("undici.error.UND_ERR_INVALID_ARG");
  class u extends r {
    constructor(J) {
      super(J), this.name = "InvalidArgumentError", this.message = J || "Invalid Argument Error", this.code = "UND_ERR_INVALID_ARG";
    }
    static [Symbol.hasInstance](J) {
      return J && J[h] === !0;
    }
    [h] = !0;
  }
  const C = /* @__PURE__ */ Symbol.for("undici.error.UND_ERR_INVALID_RETURN_VALUE");
  class w extends r {
    constructor(J) {
      super(J), this.name = "InvalidReturnValueError", this.message = J || "Invalid Return Value Error", this.code = "UND_ERR_INVALID_RETURN_VALUE";
    }
    static [Symbol.hasInstance](J) {
      return J && J[C] === !0;
    }
    [C] = !0;
  }
  const D = /* @__PURE__ */ Symbol.for("undici.error.UND_ERR_ABORT");
  class b extends r {
    constructor(J) {
      super(J), this.name = "AbortError", this.message = J || "The operation was aborted", this.code = "UND_ERR_ABORT";
    }
    static [Symbol.hasInstance](J) {
      return J && J[D] === !0;
    }
    [D] = !0;
  }
  const U = /* @__PURE__ */ Symbol.for("undici.error.UND_ERR_ABORTED");
  class G extends b {
    constructor(J) {
      super(J), this.name = "AbortError", this.message = J || "Request aborted", this.code = "UND_ERR_ABORTED";
    }
    static [Symbol.hasInstance](J) {
      return J && J[U] === !0;
    }
    [U] = !0;
  }
  const M = /* @__PURE__ */ Symbol.for("undici.error.UND_ERR_INFO");
  class N extends r {
    constructor(J) {
      super(J), this.name = "InformationalError", this.message = J || "Request information", this.code = "UND_ERR_INFO";
    }
    static [Symbol.hasInstance](J) {
      return J && J[M] === !0;
    }
    [M] = !0;
  }
  const d = /* @__PURE__ */ Symbol.for("undici.error.UND_ERR_REQ_CONTENT_LENGTH_MISMATCH");
  class l extends r {
    constructor(J) {
      super(J), this.name = "RequestContentLengthMismatchError", this.message = J || "Request body length does not match content-length header", this.code = "UND_ERR_REQ_CONTENT_LENGTH_MISMATCH";
    }
    static [Symbol.hasInstance](J) {
      return J && J[d] === !0;
    }
    [d] = !0;
  }
  const p = /* @__PURE__ */ Symbol.for("undici.error.UND_ERR_RES_CONTENT_LENGTH_MISMATCH");
  class s extends r {
    constructor(J) {
      super(J), this.name = "ResponseContentLengthMismatchError", this.message = J || "Response body length does not match content-length header", this.code = "UND_ERR_RES_CONTENT_LENGTH_MISMATCH";
    }
    static [Symbol.hasInstance](J) {
      return J && J[p] === !0;
    }
    [p] = !0;
  }
  const E = /* @__PURE__ */ Symbol.for("undici.error.UND_ERR_DESTROYED");
  class f extends r {
    constructor(J) {
      super(J), this.name = "ClientDestroyedError", this.message = J || "The client is destroyed", this.code = "UND_ERR_DESTROYED";
    }
    static [Symbol.hasInstance](J) {
      return J && J[E] === !0;
    }
    [E] = !0;
  }
  const I = /* @__PURE__ */ Symbol.for("undici.error.UND_ERR_CLOSED");
  class m extends r {
    constructor(J) {
      super(J), this.name = "ClientClosedError", this.message = J || "The client is closed", this.code = "UND_ERR_CLOSED";
    }
    static [Symbol.hasInstance](J) {
      return J && J[I] === !0;
    }
    [I] = !0;
  }
  const y = /* @__PURE__ */ Symbol.for("undici.error.UND_ERR_SOCKET");
  class S extends r {
    constructor(J, _) {
      super(J), this.name = "SocketError", this.message = J || "Socket error", this.code = "UND_ERR_SOCKET", this.socket = _;
    }
    static [Symbol.hasInstance](J) {
      return J && J[y] === !0;
    }
    [y] = !0;
  }
  const T = /* @__PURE__ */ Symbol.for("undici.error.UND_ERR_NOT_SUPPORTED");
  class L extends r {
    constructor(J) {
      super(J), this.name = "NotSupportedError", this.message = J || "Not supported error", this.code = "UND_ERR_NOT_SUPPORTED";
    }
    static [Symbol.hasInstance](J) {
      return J && J[T] === !0;
    }
    [T] = !0;
  }
  const v = /* @__PURE__ */ Symbol.for("undici.error.UND_ERR_BPL_MISSING_UPSTREAM");
  class $ extends r {
    constructor(J) {
      super(J), this.name = "MissingUpstreamError", this.message = J || "No upstream has been added to the BalancedPool", this.code = "UND_ERR_BPL_MISSING_UPSTREAM";
    }
    static [Symbol.hasInstance](J) {
      return J && J[v] === !0;
    }
    [v] = !0;
  }
  const oe = /* @__PURE__ */ Symbol.for("undici.error.UND_ERR_HTTP_PARSER");
  class ge extends Error {
    constructor(J, _, P) {
      super(J), this.name = "HTTPParserError", this.code = _ ? `HPE_${_}` : void 0, this.data = P ? P.toString() : void 0;
    }
    static [Symbol.hasInstance](J) {
      return J && J[oe] === !0;
    }
    [oe] = !0;
  }
  const ae = /* @__PURE__ */ Symbol.for("undici.error.UND_ERR_RES_EXCEEDED_MAX_SIZE");
  class he extends r {
    constructor(J) {
      super(J), this.name = "ResponseExceededMaxSizeError", this.message = J || "Response content exceeded max size", this.code = "UND_ERR_RES_EXCEEDED_MAX_SIZE";
    }
    static [Symbol.hasInstance](J) {
      return J && J[ae] === !0;
    }
    [ae] = !0;
  }
  const Be = /* @__PURE__ */ Symbol.for("undici.error.UND_ERR_REQ_RETRY");
  class Qe extends r {
    constructor(J, _, { headers: P, data: Z }) {
      super(J), this.name = "RequestRetryError", this.message = J || "Request retry error", this.code = "UND_ERR_REQ_RETRY", this.statusCode = _, this.data = Z, this.headers = P;
    }
    static [Symbol.hasInstance](J) {
      return J && J[Be] === !0;
    }
    [Be] = !0;
  }
  const ye = /* @__PURE__ */ Symbol.for("undici.error.UND_ERR_RESPONSE");
  class we extends r {
    constructor(J, _, { headers: P, data: Z }) {
      super(J), this.name = "ResponseError", this.message = J || "Response error", this.code = "UND_ERR_RESPONSE", this.statusCode = _, this.data = Z, this.headers = P;
    }
    static [Symbol.hasInstance](J) {
      return J && J[ye] === !0;
    }
    [ye] = !0;
  }
  const j = /* @__PURE__ */ Symbol.for("undici.error.UND_ERR_PRX_TLS");
  class W extends r {
    constructor(J, _, P) {
      super(_, { cause: J, ...P ?? {} }), this.name = "SecureProxyConnectionError", this.message = _ || "Secure Proxy Connection failed", this.code = "UND_ERR_PRX_TLS", this.cause = J;
    }
    static [Symbol.hasInstance](J) {
      return J && J[j] === !0;
    }
    [j] = !0;
  }
  return gt = {
    AbortError: b,
    HTTPParserError: ge,
    UndiciError: r,
    HeadersTimeoutError: n,
    HeadersOverflowError: g,
    BodyTimeoutError: B,
    RequestContentLengthMismatchError: l,
    ConnectTimeoutError: o,
    ResponseStatusCodeError: a,
    InvalidArgumentError: u,
    InvalidReturnValueError: w,
    RequestAbortedError: G,
    ClientDestroyedError: f,
    ClientClosedError: m,
    InformationalError: N,
    SocketError: S,
    NotSupportedError: L,
    ResponseContentLengthMismatchError: s,
    BalancedPoolMissingUpstreamError: $,
    ResponseExceededMaxSizeError: he,
    RequestRetryError: Qe,
    ResponseError: we,
    SecureProxyConnectionError: W
  }, gt;
}
var lt, ms;
function rs() {
  if (ms) return lt;
  ms = 1;
  const e = {}, r = [
    "Accept",
    "Accept-Encoding",
    "Accept-Language",
    "Accept-Ranges",
    "Access-Control-Allow-Credentials",
    "Access-Control-Allow-Headers",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Origin",
    "Access-Control-Expose-Headers",
    "Access-Control-Max-Age",
    "Access-Control-Request-Headers",
    "Access-Control-Request-Method",
    "Age",
    "Allow",
    "Alt-Svc",
    "Alt-Used",
    "Authorization",
    "Cache-Control",
    "Clear-Site-Data",
    "Connection",
    "Content-Disposition",
    "Content-Encoding",
    "Content-Language",
    "Content-Length",
    "Content-Location",
    "Content-Range",
    "Content-Security-Policy",
    "Content-Security-Policy-Report-Only",
    "Content-Type",
    "Cookie",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Date",
    "Device-Memory",
    "Downlink",
    "ECT",
    "ETag",
    "Expect",
    "Expect-CT",
    "Expires",
    "Forwarded",
    "From",
    "Host",
    "If-Match",
    "If-Modified-Since",
    "If-None-Match",
    "If-Range",
    "If-Unmodified-Since",
    "Keep-Alive",
    "Last-Modified",
    "Link",
    "Location",
    "Max-Forwards",
    "Origin",
    "Permissions-Policy",
    "Pragma",
    "Proxy-Authenticate",
    "Proxy-Authorization",
    "RTT",
    "Range",
    "Referer",
    "Referrer-Policy",
    "Refresh",
    "Retry-After",
    "Sec-WebSocket-Accept",
    "Sec-WebSocket-Extensions",
    "Sec-WebSocket-Key",
    "Sec-WebSocket-Protocol",
    "Sec-WebSocket-Version",
    "Server",
    "Server-Timing",
    "Service-Worker-Allowed",
    "Service-Worker-Navigation-Preload",
    "Set-Cookie",
    "SourceMap",
    "Strict-Transport-Security",
    "Supports-Loading-Mode",
    "TE",
    "Timing-Allow-Origin",
    "Trailer",
    "Transfer-Encoding",
    "Upgrade",
    "Upgrade-Insecure-Requests",
    "User-Agent",
    "Vary",
    "Via",
    "WWW-Authenticate",
    "X-Content-Type-Options",
    "X-DNS-Prefetch-Control",
    "X-Frame-Options",
    "X-Permitted-Cross-Domain-Policies",
    "X-Powered-By",
    "X-Requested-With",
    "X-XSS-Protection"
  ];
  for (let t = 0; t < r.length; ++t) {
    const o = r[t], A = o.toLowerCase();
    e[o] = e[A] = A;
  }
  return Object.setPrototypeOf(e, null), lt = {
    wellknownHeaderNames: r,
    headerNameLowerCasedRecord: e
  }, lt;
}
var Et, ys;
function qi() {
  if (ys) return Et;
  ys = 1;
  const {
    wellknownHeaderNames: e,
    headerNameLowerCasedRecord: r
  } = rs();
  class t {
    /** @type {any} */
    value = null;
    /** @type {null | TstNode} */
    left = null;
    /** @type {null | TstNode} */
    middle = null;
    /** @type {null | TstNode} */
    right = null;
    /** @type {number} */
    code;
    /**
     * @param {string} key
     * @param {any} value
     * @param {number} index
     */
    constructor(c, g, Q) {
      if (Q === void 0 || Q >= c.length)
        throw new TypeError("Unreachable");
      if ((this.code = c.charCodeAt(Q)) > 127)
        throw new TypeError("key must be ascii string");
      c.length !== ++Q ? this.middle = new t(c, g, Q) : this.value = g;
    }
    /**
     * @param {string} key
     * @param {any} value
     */
    add(c, g) {
      const Q = c.length;
      if (Q === 0)
        throw new TypeError("Unreachable");
      let B = 0, i = this;
      for (; ; ) {
        const a = c.charCodeAt(B);
        if (a > 127)
          throw new TypeError("key must be ascii string");
        if (i.code === a)
          if (Q === ++B) {
            i.value = g;
            break;
          } else if (i.middle !== null)
            i = i.middle;
          else {
            i.middle = new t(c, g, B);
            break;
          }
        else if (i.code < a)
          if (i.left !== null)
            i = i.left;
          else {
            i.left = new t(c, g, B);
            break;
          }
        else if (i.right !== null)
          i = i.right;
        else {
          i.right = new t(c, g, B);
          break;
        }
      }
    }
    /**
     * @param {Uint8Array} key
     * @return {TstNode | null}
     */
    search(c) {
      const g = c.length;
      let Q = 0, B = this;
      for (; B !== null && Q < g; ) {
        let i = c[Q];
        for (i <= 90 && i >= 65 && (i |= 32); B !== null; ) {
          if (i === B.code) {
            if (g === ++Q)
              return B;
            B = B.middle;
            break;
          }
          B = B.code < i ? B.left : B.right;
        }
      }
      return null;
    }
  }
  class o {
    /** @type {TstNode | null} */
    node = null;
    /**
     * @param {string} key
     * @param {any} value
     * */
    insert(c, g) {
      this.node === null ? this.node = new t(c, g, 0) : this.node.add(c, g);
    }
    /**
     * @param {Uint8Array} key
     * @return {any}
     */
    lookup(c) {
      return this.node?.search(c)?.value ?? null;
    }
  }
  const A = new o();
  for (let n = 0; n < e.length; ++n) {
    const c = r[e[n]];
    A.insert(c, c);
  }
  return Et = {
    TernarySearchTree: o,
    tree: A
  }, Et;
}
var ut, Ds;
function Ue() {
  if (Ds) return ut;
  Ds = 1;
  const e = He, { kDestroyed: r, kBodyUsed: t, kListeners: o, kBody: A } = Oe(), { IncomingMessage: n } = qA, c = tA, g = WA, { Blob: Q } = sA, B = $e, { stringify: i } = Ni, { EventEmitter: a } = kA, { InvalidArgumentError: h } = Ye(), { headerNameLowerCasedRecord: u } = rs(), { tree: C } = qi(), [w, D] = process.versions.node.split(".").map((R) => Number(R));
  class b {
    constructor(q) {
      this[A] = q, this[t] = !1;
    }
    async *[Symbol.asyncIterator]() {
      e(!this[t], "disturbed"), this[t] = !0, yield* this[A];
    }
  }
  function U(R) {
    return M(R) ? (T(R) === 0 && R.on("data", function() {
      e(!1);
    }), typeof R.readableDidRead != "boolean" && (R[t] = !1, a.prototype.on.call(R, "data", function() {
      this[t] = !0;
    })), R) : R && typeof R.pipeTo == "function" ? new b(R) : R && typeof R != "string" && !ArrayBuffer.isView(R) && S(R) ? new b(R) : R;
  }
  function G() {
  }
  function M(R) {
    return R && typeof R == "object" && typeof R.pipe == "function" && typeof R.on == "function";
  }
  function N(R) {
    if (R === null)
      return !1;
    if (R instanceof Q)
      return !0;
    if (typeof R != "object")
      return !1;
    {
      const q = R[Symbol.toStringTag];
      return (q === "Blob" || q === "File") && ("stream" in R && typeof R.stream == "function" || "arrayBuffer" in R && typeof R.arrayBuffer == "function");
    }
  }
  function d(R, q) {
    if (R.includes("?") || R.includes("#"))
      throw new Error('Query params cannot be passed when url already contains "?" or "#".');
    const ie = i(q);
    return ie && (R += "?" + ie), R;
  }
  function l(R) {
    const q = parseInt(R, 10);
    return q === Number(R) && q >= 0 && q <= 65535;
  }
  function p(R) {
    return R != null && R[0] === "h" && R[1] === "t" && R[2] === "t" && R[3] === "p" && (R[4] === ":" || R[4] === "s" && R[5] === ":");
  }
  function s(R) {
    if (typeof R == "string") {
      if (R = new URL(R), !p(R.origin || R.protocol))
        throw new h("Invalid URL protocol: the URL must start with `http:` or `https:`.");
      return R;
    }
    if (!R || typeof R != "object")
      throw new h("Invalid URL: The URL argument must be a non-null object.");
    if (!(R instanceof URL)) {
      if (R.port != null && R.port !== "" && l(R.port) === !1)
        throw new h("Invalid URL: port must be a valid integer or a string representation of an integer.");
      if (R.path != null && typeof R.path != "string")
        throw new h("Invalid URL path: the path must be a string or null/undefined.");
      if (R.pathname != null && typeof R.pathname != "string")
        throw new h("Invalid URL pathname: the pathname must be a string or null/undefined.");
      if (R.hostname != null && typeof R.hostname != "string")
        throw new h("Invalid URL hostname: the hostname must be a string or null/undefined.");
      if (R.origin != null && typeof R.origin != "string")
        throw new h("Invalid URL origin: the origin must be a string or null/undefined.");
      if (!p(R.origin || R.protocol))
        throw new h("Invalid URL protocol: the URL must start with `http:` or `https:`.");
      const q = R.port != null ? R.port : R.protocol === "https:" ? 443 : 80;
      let ie = R.origin != null ? R.origin : `${R.protocol || ""}//${R.hostname || ""}:${q}`, Ee = R.path != null ? R.path : `${R.pathname || ""}${R.search || ""}`;
      return ie[ie.length - 1] === "/" && (ie = ie.slice(0, ie.length - 1)), Ee && Ee[0] !== "/" && (Ee = `/${Ee}`), new URL(`${ie}${Ee}`);
    }
    if (!p(R.origin || R.protocol))
      throw new h("Invalid URL protocol: the URL must start with `http:` or `https:`.");
    return R;
  }
  function E(R) {
    if (R = s(R), R.pathname !== "/" || R.search || R.hash)
      throw new h("invalid url");
    return R;
  }
  function f(R) {
    if (R[0] === "[") {
      const ie = R.indexOf("]");
      return e(ie !== -1), R.substring(1, ie);
    }
    const q = R.indexOf(":");
    return q === -1 ? R : R.substring(0, q);
  }
  function I(R) {
    if (!R)
      return null;
    e(typeof R == "string");
    const q = f(R);
    return g.isIP(q) ? "" : q;
  }
  function m(R) {
    return JSON.parse(JSON.stringify(R));
  }
  function y(R) {
    return R != null && typeof R[Symbol.asyncIterator] == "function";
  }
  function S(R) {
    return R != null && (typeof R[Symbol.iterator] == "function" || typeof R[Symbol.asyncIterator] == "function");
  }
  function T(R) {
    if (R == null)
      return 0;
    if (M(R)) {
      const q = R._readableState;
      return q && q.objectMode === !1 && q.ended === !0 && Number.isFinite(q.length) ? q.length : null;
    } else {
      if (N(R))
        return R.size != null ? R.size : null;
      if (Qe(R))
        return R.byteLength;
    }
    return null;
  }
  function L(R) {
    return R && !!(R.destroyed || R[r] || c.isDestroyed?.(R));
  }
  function v(R, q) {
    R == null || !M(R) || L(R) || (typeof R.destroy == "function" ? (Object.getPrototypeOf(R).constructor === n && (R.socket = null), R.destroy(q)) : q && queueMicrotask(() => {
      R.emit("error", q);
    }), R.destroyed !== !0 && (R[r] = !0));
  }
  const $ = /timeout=(\d+)/;
  function oe(R) {
    const q = R.toString().match($);
    return q ? parseInt(q[1], 10) * 1e3 : null;
  }
  function ge(R) {
    return typeof R == "string" ? u[R] ?? R.toLowerCase() : C.lookup(R) ?? R.toString("latin1").toLowerCase();
  }
  function ae(R) {
    return C.lookup(R) ?? R.toString("latin1").toLowerCase();
  }
  function he(R, q) {
    q === void 0 && (q = {});
    for (let ie = 0; ie < R.length; ie += 2) {
      const Ee = ge(R[ie]);
      let Ie = q[Ee];
      if (Ie)
        typeof Ie == "string" && (Ie = [Ie], q[Ee] = Ie), Ie.push(R[ie + 1].toString("utf8"));
      else {
        const De = R[ie + 1];
        typeof De == "string" ? q[Ee] = De : q[Ee] = Array.isArray(De) ? De.map((ve) => ve.toString("utf8")) : De.toString("utf8");
      }
    }
    return "content-length" in q && "content-disposition" in q && (q["content-disposition"] = Buffer.from(q["content-disposition"]).toString("latin1")), q;
  }
  function Be(R) {
    const q = R.length, ie = new Array(q);
    let Ee = !1, Ie = -1, De, ve, qe = 0;
    for (let Ze = 0; Ze < R.length; Ze += 2)
      De = R[Ze], ve = R[Ze + 1], typeof De != "string" && (De = De.toString()), typeof ve != "string" && (ve = ve.toString("utf8")), qe = De.length, qe === 14 && De[7] === "-" && (De === "content-length" || De.toLowerCase() === "content-length") ? Ee = !0 : qe === 19 && De[7] === "-" && (De === "content-disposition" || De.toLowerCase() === "content-disposition") && (Ie = Ze + 1), ie[Ze] = De, ie[Ze + 1] = ve;
    return Ee && Ie !== -1 && (ie[Ie] = Buffer.from(ie[Ie]).toString("latin1")), ie;
  }
  function Qe(R) {
    return R instanceof Uint8Array || Buffer.isBuffer(R);
  }
  function ye(R, q, ie) {
    if (!R || typeof R != "object")
      throw new h("handler must be an object");
    if (typeof R.onConnect != "function")
      throw new h("invalid onConnect method");
    if (typeof R.onError != "function")
      throw new h("invalid onError method");
    if (typeof R.onBodySent != "function" && R.onBodySent !== void 0)
      throw new h("invalid onBodySent method");
    if (ie || q === "CONNECT") {
      if (typeof R.onUpgrade != "function")
        throw new h("invalid onUpgrade method");
    } else {
      if (typeof R.onHeaders != "function")
        throw new h("invalid onHeaders method");
      if (typeof R.onData != "function")
        throw new h("invalid onData method");
      if (typeof R.onComplete != "function")
        throw new h("invalid onComplete method");
    }
  }
  function we(R) {
    return !!(R && (c.isDisturbed(R) || R[t]));
  }
  function j(R) {
    return !!(R && c.isErrored(R));
  }
  function W(R) {
    return !!(R && c.isReadable(R));
  }
  function re(R) {
    return {
      localAddress: R.localAddress,
      localPort: R.localPort,
      remoteAddress: R.remoteAddress,
      remotePort: R.remotePort,
      remoteFamily: R.remoteFamily,
      timeout: R.timeout,
      bytesWritten: R.bytesWritten,
      bytesRead: R.bytesRead
    };
  }
  function J(R) {
    let q;
    return new ReadableStream(
      {
        async start() {
          q = R[Symbol.asyncIterator]();
        },
        async pull(ie) {
          const { done: Ee, value: Ie } = await q.next();
          if (Ee)
            queueMicrotask(() => {
              ie.close(), ie.byobRequest?.respond(0);
            });
          else {
            const De = Buffer.isBuffer(Ie) ? Ie : Buffer.from(Ie);
            De.byteLength && ie.enqueue(new Uint8Array(De));
          }
          return ie.desiredSize > 0;
        },
        async cancel(ie) {
          await q.return();
        },
        type: "bytes"
      }
    );
  }
  function _(R) {
    return R && typeof R == "object" && typeof R.append == "function" && typeof R.delete == "function" && typeof R.get == "function" && typeof R.getAll == "function" && typeof R.has == "function" && typeof R.set == "function" && R[Symbol.toStringTag] === "FormData";
  }
  function P(R, q) {
    return "addEventListener" in R ? (R.addEventListener("abort", q, { once: !0 }), () => R.removeEventListener("abort", q)) : (R.addListener("abort", q), () => R.removeListener("abort", q));
  }
  const Z = typeof String.prototype.toWellFormed == "function", se = typeof String.prototype.isWellFormed == "function";
  function le(R) {
    return Z ? `${R}`.toWellFormed() : B.toUSVString(R);
  }
  function ne(R) {
    return se ? `${R}`.isWellFormed() : le(R) === `${R}`;
  }
  function fe(R) {
    switch (R) {
      case 34:
      case 40:
      case 41:
      case 44:
      case 47:
      case 58:
      case 59:
      case 60:
      case 61:
      case 62:
      case 63:
      case 64:
      case 91:
      case 92:
      case 93:
      case 123:
      case 125:
        return !1;
      default:
        return R >= 33 && R <= 126;
    }
  }
  function Me(R) {
    if (R.length === 0)
      return !1;
    for (let q = 0; q < R.length; ++q)
      if (!fe(R.charCodeAt(q)))
        return !1;
    return !0;
  }
  const pe = /[^\t\x20-\x7e\x80-\xff]/;
  function Le(R) {
    return !pe.test(R);
  }
  function ke(R) {
    if (R == null || R === "") return { start: 0, end: null, size: null };
    const q = R ? R.match(/^bytes (\d+)-(\d+)\/(\d+)?$/) : null;
    return q ? {
      start: parseInt(q[1]),
      end: q[2] ? parseInt(q[2]) : null,
      size: q[3] ? parseInt(q[3]) : null
    } : null;
  }
  function be(R, q, ie) {
    return (R[o] ??= []).push([q, ie]), R.on(q, ie), R;
  }
  function de(R) {
    for (const [q, ie] of R[o] ?? [])
      R.removeListener(q, ie);
    R[o] = null;
  }
  function _e(R, q, ie) {
    try {
      q.onError(ie), e(q.aborted);
    } catch (Ee) {
      R.emit("error", Ee);
    }
  }
  const Pe = /* @__PURE__ */ Object.create(null);
  Pe.enumerable = !0;
  const Je = {
    delete: "DELETE",
    DELETE: "DELETE",
    get: "GET",
    GET: "GET",
    head: "HEAD",
    HEAD: "HEAD",
    options: "OPTIONS",
    OPTIONS: "OPTIONS",
    post: "POST",
    POST: "POST",
    put: "PUT",
    PUT: "PUT"
  }, X = {
    ...Je,
    patch: "patch",
    PATCH: "PATCH"
  };
  return Object.setPrototypeOf(Je, null), Object.setPrototypeOf(X, null), ut = {
    kEnumerableProperty: Pe,
    nop: G,
    isDisturbed: we,
    isErrored: j,
    isReadable: W,
    toUSVString: le,
    isUSVString: ne,
    isBlobLike: N,
    parseOrigin: E,
    parseURL: s,
    getServerName: I,
    isStream: M,
    isIterable: S,
    isAsyncIterable: y,
    isDestroyed: L,
    headerNameToString: ge,
    bufferToLowerCasedHeaderName: ae,
    addListener: be,
    removeAllListeners: de,
    errorRequest: _e,
    parseRawHeaders: Be,
    parseHeaders: he,
    parseKeepAliveTimeout: oe,
    destroy: v,
    bodyLength: T,
    deepClone: m,
    ReadableStreamFrom: J,
    isBuffer: Qe,
    validateHandler: ye,
    getSocketInfo: re,
    isFormDataLike: _,
    buildURL: d,
    addAbortListener: P,
    isValidHTTPToken: Me,
    isValidHeaderValue: Le,
    isTokenCharCode: fe,
    parseRangeHeader: ke,
    normalizedMethodRecordsBase: Je,
    normalizedMethodRecords: X,
    isValidPort: l,
    isHttpOrHttpsPrefixed: p,
    nodeMajor: w,
    nodeMinor: D,
    safeHTTPMethods: ["GET", "HEAD", "OPTIONS", "TRACE"],
    wrapRequestBody: U
  }, ut;
}
var Qt, Rs;
function FA() {
  if (Rs) return Qt;
  Rs = 1;
  const e = Mi, r = $e, t = r.debuglog("undici"), o = r.debuglog("fetch"), A = r.debuglog("websocket");
  let n = !1;
  const c = {
    // Client
    beforeConnect: e.channel("undici:client:beforeConnect"),
    connected: e.channel("undici:client:connected"),
    connectError: e.channel("undici:client:connectError"),
    sendHeaders: e.channel("undici:client:sendHeaders"),
    // Request
    create: e.channel("undici:request:create"),
    bodySent: e.channel("undici:request:bodySent"),
    headers: e.channel("undici:request:headers"),
    trailers: e.channel("undici:request:trailers"),
    error: e.channel("undici:request:error"),
    // WebSocket
    open: e.channel("undici:websocket:open"),
    close: e.channel("undici:websocket:close"),
    socketError: e.channel("undici:websocket:socket_error"),
    ping: e.channel("undici:websocket:ping"),
    pong: e.channel("undici:websocket:pong")
  };
  if (t.enabled || o.enabled) {
    const g = o.enabled ? o : t;
    e.channel("undici:client:beforeConnect").subscribe((Q) => {
      const {
        connectParams: { version: B, protocol: i, port: a, host: h }
      } = Q;
      g(
        "connecting to %s using %s%s",
        `${h}${a ? `:${a}` : ""}`,
        i,
        B
      );
    }), e.channel("undici:client:connected").subscribe((Q) => {
      const {
        connectParams: { version: B, protocol: i, port: a, host: h }
      } = Q;
      g(
        "connected to %s using %s%s",
        `${h}${a ? `:${a}` : ""}`,
        i,
        B
      );
    }), e.channel("undici:client:connectError").subscribe((Q) => {
      const {
        connectParams: { version: B, protocol: i, port: a, host: h },
        error: u
      } = Q;
      g(
        "connection to %s using %s%s errored - %s",
        `${h}${a ? `:${a}` : ""}`,
        i,
        B,
        u.message
      );
    }), e.channel("undici:client:sendHeaders").subscribe((Q) => {
      const {
        request: { method: B, path: i, origin: a }
      } = Q;
      g("sending request to %s %s/%s", B, a, i);
    }), e.channel("undici:request:headers").subscribe((Q) => {
      const {
        request: { method: B, path: i, origin: a },
        response: { statusCode: h }
      } = Q;
      g(
        "received response to %s %s/%s - HTTP %d",
        B,
        a,
        i,
        h
      );
    }), e.channel("undici:request:trailers").subscribe((Q) => {
      const {
        request: { method: B, path: i, origin: a }
      } = Q;
      g("trailers received from %s %s/%s", B, a, i);
    }), e.channel("undici:request:error").subscribe((Q) => {
      const {
        request: { method: B, path: i, origin: a },
        error: h
      } = Q;
      g(
        "request to %s %s/%s errored - %s",
        B,
        a,
        i,
        h.message
      );
    }), n = !0;
  }
  if (A.enabled) {
    if (!n) {
      const g = t.enabled ? t : A;
      e.channel("undici:client:beforeConnect").subscribe((Q) => {
        const {
          connectParams: { version: B, protocol: i, port: a, host: h }
        } = Q;
        g(
          "connecting to %s%s using %s%s",
          h,
          a ? `:${a}` : "",
          i,
          B
        );
      }), e.channel("undici:client:connected").subscribe((Q) => {
        const {
          connectParams: { version: B, protocol: i, port: a, host: h }
        } = Q;
        g(
          "connected to %s%s using %s%s",
          h,
          a ? `:${a}` : "",
          i,
          B
        );
      }), e.channel("undici:client:connectError").subscribe((Q) => {
        const {
          connectParams: { version: B, protocol: i, port: a, host: h },
          error: u
        } = Q;
        g(
          "connection to %s%s using %s%s errored - %s",
          h,
          a ? `:${a}` : "",
          i,
          B,
          u.message
        );
      }), e.channel("undici:client:sendHeaders").subscribe((Q) => {
        const {
          request: { method: B, path: i, origin: a }
        } = Q;
        g("sending request to %s %s/%s", B, a, i);
      });
    }
    e.channel("undici:websocket:open").subscribe((g) => {
      const {
        address: { address: Q, port: B }
      } = g;
      A("connection opened %s%s", Q, B ? `:${B}` : "");
    }), e.channel("undici:websocket:close").subscribe((g) => {
      const { websocket: Q, code: B, reason: i } = g;
      A(
        "closed connection to %s - %s %s",
        Q.url,
        B,
        i
      );
    }), e.channel("undici:websocket:socket_error").subscribe((g) => {
      A("connection errored - %s", g.message);
    }), e.channel("undici:websocket:ping").subscribe((g) => {
      A("ping received");
    }), e.channel("undici:websocket:pong").subscribe((g) => {
      A("pong received");
    });
  }
  return Qt = {
    channels: c
  }, Qt;
}
var Bt, ks;
function zi() {
  if (ks) return Bt;
  ks = 1;
  const {
    InvalidArgumentError: e,
    NotSupportedError: r
  } = Ye(), t = He, {
    isValidHTTPToken: o,
    isValidHeaderValue: A,
    isStream: n,
    destroy: c,
    isBuffer: g,
    isFormDataLike: Q,
    isIterable: B,
    isBlobLike: i,
    buildURL: a,
    validateHandler: h,
    getServerName: u,
    normalizedMethodRecords: C
  } = Ue(), { channels: w } = FA(), { headerNameLowerCasedRecord: D } = rs(), b = /[^\u0021-\u00ff]/, U = /* @__PURE__ */ Symbol("handler");
  class G {
    constructor(d, {
      path: l,
      method: p,
      body: s,
      headers: E,
      query: f,
      idempotent: I,
      blocking: m,
      upgrade: y,
      headersTimeout: S,
      bodyTimeout: T,
      reset: L,
      throwOnError: v,
      expectContinue: $,
      servername: oe
    }, ge) {
      if (typeof l != "string")
        throw new e("path must be a string");
      if (l[0] !== "/" && !(l.startsWith("http://") || l.startsWith("https://")) && p !== "CONNECT")
        throw new e("path must be an absolute URL or start with a slash");
      if (b.test(l))
        throw new e("invalid request path");
      if (typeof p != "string")
        throw new e("method must be a string");
      if (C[p] === void 0 && !o(p))
        throw new e("invalid request method");
      if (y && typeof y != "string")
        throw new e("upgrade must be a string");
      if (S != null && (!Number.isFinite(S) || S < 0))
        throw new e("invalid headersTimeout");
      if (T != null && (!Number.isFinite(T) || T < 0))
        throw new e("invalid bodyTimeout");
      if (L != null && typeof L != "boolean")
        throw new e("invalid reset");
      if ($ != null && typeof $ != "boolean")
        throw new e("invalid expectContinue");
      if (this.headersTimeout = S, this.bodyTimeout = T, this.throwOnError = v === !0, this.method = p, this.abort = null, s == null)
        this.body = null;
      else if (n(s)) {
        this.body = s;
        const ae = this.body._readableState;
        (!ae || !ae.autoDestroy) && (this.endHandler = function() {
          c(this);
        }, this.body.on("end", this.endHandler)), this.errorHandler = (he) => {
          this.abort ? this.abort(he) : this.error = he;
        }, this.body.on("error", this.errorHandler);
      } else if (g(s))
        this.body = s.byteLength ? s : null;
      else if (ArrayBuffer.isView(s))
        this.body = s.buffer.byteLength ? Buffer.from(s.buffer, s.byteOffset, s.byteLength) : null;
      else if (s instanceof ArrayBuffer)
        this.body = s.byteLength ? Buffer.from(s) : null;
      else if (typeof s == "string")
        this.body = s.length ? Buffer.from(s) : null;
      else if (Q(s) || B(s) || i(s))
        this.body = s;
      else
        throw new e("body must be a string, a Buffer, a Readable stream, an iterable, or an async iterable");
      if (this.completed = !1, this.aborted = !1, this.upgrade = y || null, this.path = f ? a(l, f) : l, this.origin = d, this.idempotent = I ?? (p === "HEAD" || p === "GET"), this.blocking = m ?? !1, this.reset = L ?? null, this.host = null, this.contentLength = null, this.contentType = null, this.headers = [], this.expectContinue = $ ?? !1, Array.isArray(E)) {
        if (E.length % 2 !== 0)
          throw new e("headers array must be even");
        for (let ae = 0; ae < E.length; ae += 2)
          M(this, E[ae], E[ae + 1]);
      } else if (E && typeof E == "object")
        if (E[Symbol.iterator])
          for (const ae of E) {
            if (!Array.isArray(ae) || ae.length !== 2)
              throw new e("headers must be in key-value pair format");
            M(this, ae[0], ae[1]);
          }
        else {
          const ae = Object.keys(E);
          for (let he = 0; he < ae.length; ++he)
            M(this, ae[he], E[ae[he]]);
        }
      else if (E != null)
        throw new e("headers must be an object or an array");
      h(ge, p, y), this.servername = oe || u(this.host), this[U] = ge, w.create.hasSubscribers && w.create.publish({ request: this });
    }
    onBodySent(d) {
      if (this[U].onBodySent)
        try {
          return this[U].onBodySent(d);
        } catch (l) {
          this.abort(l);
        }
    }
    onRequestSent() {
      if (w.bodySent.hasSubscribers && w.bodySent.publish({ request: this }), this[U].onRequestSent)
        try {
          return this[U].onRequestSent();
        } catch (d) {
          this.abort(d);
        }
    }
    onConnect(d) {
      if (t(!this.aborted), t(!this.completed), this.error)
        d(this.error);
      else
        return this.abort = d, this[U].onConnect(d);
    }
    onResponseStarted() {
      return this[U].onResponseStarted?.();
    }
    onHeaders(d, l, p, s) {
      t(!this.aborted), t(!this.completed), w.headers.hasSubscribers && w.headers.publish({ request: this, response: { statusCode: d, headers: l, statusText: s } });
      try {
        return this[U].onHeaders(d, l, p, s);
      } catch (E) {
        this.abort(E);
      }
    }
    onData(d) {
      t(!this.aborted), t(!this.completed);
      try {
        return this[U].onData(d);
      } catch (l) {
        return this.abort(l), !1;
      }
    }
    onUpgrade(d, l, p) {
      return t(!this.aborted), t(!this.completed), this[U].onUpgrade(d, l, p);
    }
    onComplete(d) {
      this.onFinally(), t(!this.aborted), this.completed = !0, w.trailers.hasSubscribers && w.trailers.publish({ request: this, trailers: d });
      try {
        return this[U].onComplete(d);
      } catch (l) {
        this.onError(l);
      }
    }
    onError(d) {
      if (this.onFinally(), w.error.hasSubscribers && w.error.publish({ request: this, error: d }), !this.aborted)
        return this.aborted = !0, this[U].onError(d);
    }
    onFinally() {
      this.errorHandler && (this.body.off("error", this.errorHandler), this.errorHandler = null), this.endHandler && (this.body.off("end", this.endHandler), this.endHandler = null);
    }
    addHeader(d, l) {
      return M(this, d, l), this;
    }
  }
  function M(N, d, l) {
    if (l && typeof l == "object" && !Array.isArray(l))
      throw new e(`invalid ${d} header`);
    if (l === void 0)
      return;
    let p = D[d];
    if (p === void 0 && (p = d.toLowerCase(), D[p] === void 0 && !o(p)))
      throw new e("invalid header key");
    if (Array.isArray(l)) {
      const s = [];
      for (let E = 0; E < l.length; E++)
        if (typeof l[E] == "string") {
          if (!A(l[E]))
            throw new e(`invalid ${d} header`);
          s.push(l[E]);
        } else if (l[E] === null)
          s.push("");
        else {
          if (typeof l[E] == "object")
            throw new e(`invalid ${d} header`);
          s.push(`${l[E]}`);
        }
      l = s;
    } else if (typeof l == "string") {
      if (!A(l))
        throw new e(`invalid ${d} header`);
    } else l === null ? l = "" : l = `${l}`;
    if (N.host === null && p === "host") {
      if (typeof l != "string")
        throw new e("invalid host header");
      N.host = l;
    } else if (N.contentLength === null && p === "content-length") {
      if (N.contentLength = parseInt(l, 10), !Number.isFinite(N.contentLength))
        throw new e("invalid content-length header");
    } else if (N.contentType === null && p === "content-type")
      N.contentType = l, N.headers.push(d, l);
    else {
      if (p === "transfer-encoding" || p === "keep-alive" || p === "upgrade")
        throw new e(`invalid ${p} header`);
      if (p === "connection") {
        const s = typeof l == "string" ? l.toLowerCase() : null;
        if (s !== "close" && s !== "keep-alive")
          throw new e("invalid connection header");
        s === "close" && (N.reset = !0);
      } else {
        if (p === "expect")
          throw new r("expect header not supported");
        N.headers.push(d, l);
      }
    }
  }
  return Bt = G, Bt;
}
var ht, bs;
function zA() {
  if (bs) return ht;
  bs = 1;
  const e = kA;
  class r extends e {
    dispatch() {
      throw new Error("not implemented");
    }
    close() {
      throw new Error("not implemented");
    }
    destroy() {
      throw new Error("not implemented");
    }
    compose(...A) {
      const n = Array.isArray(A[0]) ? A[0] : A;
      let c = this.dispatch.bind(this);
      for (const g of n)
        if (g != null) {
          if (typeof g != "function")
            throw new TypeError(`invalid interceptor, expected function received ${typeof g}`);
          if (c = g(c), c == null || typeof c != "function" || c.length !== 2)
            throw new TypeError("invalid interceptor");
        }
      return new t(this, c);
    }
  }
  class t extends r {
    #e = null;
    #A = null;
    constructor(A, n) {
      super(), this.#e = A, this.#A = n;
    }
    dispatch(...A) {
      this.#A(...A);
    }
    close(...A) {
      return this.#e.close(...A);
    }
    destroy(...A) {
      return this.#e.destroy(...A);
    }
  }
  return ht = r, ht;
}
var It, Fs;
function TA() {
  if (Fs) return It;
  Fs = 1;
  const e = zA(), {
    ClientDestroyedError: r,
    ClientClosedError: t,
    InvalidArgumentError: o
  } = Ye(), { kDestroy: A, kClose: n, kClosed: c, kDestroyed: g, kDispatch: Q, kInterceptors: B } = Oe(), i = /* @__PURE__ */ Symbol("onDestroyed"), a = /* @__PURE__ */ Symbol("onClosed"), h = /* @__PURE__ */ Symbol("Intercepted Dispatch");
  class u extends e {
    constructor() {
      super(), this[g] = !1, this[i] = null, this[c] = !1, this[a] = [];
    }
    get destroyed() {
      return this[g];
    }
    get closed() {
      return this[c];
    }
    get interceptors() {
      return this[B];
    }
    set interceptors(w) {
      if (w) {
        for (let D = w.length - 1; D >= 0; D--)
          if (typeof this[B][D] != "function")
            throw new o("interceptor must be an function");
      }
      this[B] = w;
    }
    close(w) {
      if (w === void 0)
        return new Promise((b, U) => {
          this.close((G, M) => G ? U(G) : b(M));
        });
      if (typeof w != "function")
        throw new o("invalid callback");
      if (this[g]) {
        queueMicrotask(() => w(new r(), null));
        return;
      }
      if (this[c]) {
        this[a] ? this[a].push(w) : queueMicrotask(() => w(null, null));
        return;
      }
      this[c] = !0, this[a].push(w);
      const D = () => {
        const b = this[a];
        this[a] = null;
        for (let U = 0; U < b.length; U++)
          b[U](null, null);
      };
      this[n]().then(() => this.destroy()).then(() => {
        queueMicrotask(D);
      });
    }
    destroy(w, D) {
      if (typeof w == "function" && (D = w, w = null), D === void 0)
        return new Promise((U, G) => {
          this.destroy(w, (M, N) => M ? (
            /* istanbul ignore next: should never error */
            G(M)
          ) : U(N));
        });
      if (typeof D != "function")
        throw new o("invalid callback");
      if (this[g]) {
        this[i] ? this[i].push(D) : queueMicrotask(() => D(null, null));
        return;
      }
      w || (w = new r()), this[g] = !0, this[i] = this[i] || [], this[i].push(D);
      const b = () => {
        const U = this[i];
        this[i] = null;
        for (let G = 0; G < U.length; G++)
          U[G](null, null);
      };
      this[A](w).then(() => {
        queueMicrotask(b);
      });
    }
    [h](w, D) {
      if (!this[B] || this[B].length === 0)
        return this[h] = this[Q], this[Q](w, D);
      let b = this[Q].bind(this);
      for (let U = this[B].length - 1; U >= 0; U--)
        b = this[B][U](b);
      return this[h] = b, b(w, D);
    }
    dispatch(w, D) {
      if (!D || typeof D != "object")
        throw new o("handler must be an object");
      try {
        if (!w || typeof w != "object")
          throw new o("opts must be an object.");
        if (this[g] || this[i])
          throw new r();
        if (this[c])
          throw new t();
        return this[h](w, D);
      } catch (b) {
        if (typeof D.onError != "function")
          throw new o("invalid onError method");
        return D.onError(b), !1;
      }
    }
  }
  return It = u, It;
}
var Ct, Ts;
function _n() {
  if (Ts) return Ct;
  Ts = 1;
  let e = 0;
  const r = 1e3, t = (r >> 1) - 1;
  let o;
  const A = /* @__PURE__ */ Symbol("kFastTimer"), n = [], c = -2, g = -1, Q = 0, B = 1;
  function i() {
    e += t;
    let u = 0, C = n.length;
    for (; u < C; ) {
      const w = n[u];
      w._state === Q ? (w._idleStart = e - t, w._state = B) : w._state === B && e >= w._idleStart + w._idleTimeout && (w._state = g, w._idleStart = -1, w._onTimeout(w._timerArg)), w._state === g ? (w._state = c, --C !== 0 && (n[u] = n[C])) : ++u;
    }
    n.length = C, n.length !== 0 && a();
  }
  function a() {
    o ? o.refresh() : (clearTimeout(o), o = setTimeout(i, t), o.unref && o.unref());
  }
  class h {
    [A] = !0;
    /**
     * The state of the timer, which can be one of the following:
     * - NOT_IN_LIST (-2)
     * - TO_BE_CLEARED (-1)
     * - PENDING (0)
     * - ACTIVE (1)
     *
     * @type {-2|-1|0|1}
     * @private
     */
    _state = c;
    /**
     * The number of milliseconds to wait before calling the callback.
     *
     * @type {number}
     * @private
     */
    _idleTimeout = -1;
    /**
     * The time in milliseconds when the timer was started. This value is used to
     * calculate when the timer should expire.
     *
     * @type {number}
     * @default -1
     * @private
     */
    _idleStart = -1;
    /**
     * The function to be executed when the timer expires.
     * @type {Function}
     * @private
     */
    _onTimeout;
    /**
     * The argument to be passed to the callback when the timer expires.
     *
     * @type {*}
     * @private
     */
    _timerArg;
    /**
     * @constructor
     * @param {Function} callback A function to be executed after the timer
     * expires.
     * @param {number} delay The time, in milliseconds that the timer should wait
     * before the specified function or code is executed.
     * @param {*} arg
     */
    constructor(C, w, D) {
      this._onTimeout = C, this._idleTimeout = w, this._timerArg = D, this.refresh();
    }
    /**
     * Sets the timer's start time to the current time, and reschedules the timer
     * to call its callback at the previously specified duration adjusted to the
     * current time.
     * Using this on a timer that has already called its callback will reactivate
     * the timer.
     *
     * @returns {void}
     */
    refresh() {
      this._state === c && n.push(this), (!o || n.length === 1) && a(), this._state = Q;
    }
    /**
     * The `clear` method cancels the timer, preventing it from executing.
     *
     * @returns {void}
     * @private
     */
    clear() {
      this._state = g, this._idleStart = -1;
    }
  }
  return Ct = {
    /**
     * The setTimeout() method sets a timer which executes a function once the
     * timer expires.
     * @param {Function} callback A function to be executed after the timer
     * expires.
     * @param {number} delay The time, in milliseconds that the timer should
     * wait before the specified function or code is executed.
     * @param {*} [arg] An optional argument to be passed to the callback function
     * when the timer expires.
     * @returns {NodeJS.Timeout|FastTimer}
     */
    setTimeout(u, C, w) {
      return C <= r ? setTimeout(u, C, w) : new h(u, C, w);
    },
    /**
     * The clearTimeout method cancels an instantiated Timer previously created
     * by calling setTimeout.
     *
     * @param {NodeJS.Timeout|FastTimer} timeout
     */
    clearTimeout(u) {
      u[A] ? u.clear() : clearTimeout(u);
    },
    /**
     * The setFastTimeout() method sets a fastTimer which executes a function once
     * the timer expires.
     * @param {Function} callback A function to be executed after the timer
     * expires.
     * @param {number} delay The time, in milliseconds that the timer should
     * wait before the specified function or code is executed.
     * @param {*} [arg] An optional argument to be passed to the callback function
     * when the timer expires.
     * @returns {FastTimer}
     */
    setFastTimeout(u, C, w) {
      return new h(u, C, w);
    },
    /**
     * The clearTimeout method cancels an instantiated FastTimer previously
     * created by calling setFastTimeout.
     *
     * @param {FastTimer} timeout
     */
    clearFastTimeout(u) {
      u.clear();
    },
    /**
     * The now method returns the value of the internal fast timer clock.
     *
     * @returns {number}
     */
    now() {
      return e;
    },
    /**
     * Trigger the onTick function to process the fastTimers array.
     * Exported for testing purposes only.
     * Marking as deprecated to discourage any use outside of testing.
     * @deprecated
     * @param {number} [delay=0] The delay in milliseconds to add to the now value.
     */
    tick(u = 0) {
      e += u - r + 1, i(), i();
    },
    /**
     * Reset FastTimers.
     * Exported for testing purposes only.
     * Marking as deprecated to discourage any use outside of testing.
     * @deprecated
     */
    reset() {
      e = 0, n.length = 0, clearTimeout(o), o = null;
    },
    /**
     * Exporting for testing purposes only.
     * Marking as deprecated to discourage any use outside of testing.
     * @deprecated
     */
    kFastTimer: A
  }, Ct;
}
var dt, Ss;
function ZA() {
  if (Ss) return dt;
  Ss = 1;
  const e = WA, r = He, t = Ue(), { InvalidArgumentError: o, ConnectTimeoutError: A } = Ye(), n = _n();
  function c() {
  }
  let g, Q;
  Cs.FinalizationRegistry && !(process.env.NODE_V8_COVERAGE || process.env.UNDICI_NO_FG) ? Q = class {
    constructor(u) {
      this._maxCachedSessions = u, this._sessionCache = /* @__PURE__ */ new Map(), this._sessionRegistry = new Cs.FinalizationRegistry((C) => {
        if (this._sessionCache.size < this._maxCachedSessions)
          return;
        const w = this._sessionCache.get(C);
        w !== void 0 && w.deref() === void 0 && this._sessionCache.delete(C);
      });
    }
    get(u) {
      const C = this._sessionCache.get(u);
      return C ? C.deref() : null;
    }
    set(u, C) {
      this._maxCachedSessions !== 0 && (this._sessionCache.set(u, new WeakRef(C)), this._sessionRegistry.register(C, u));
    }
  } : Q = class {
    constructor(u) {
      this._maxCachedSessions = u, this._sessionCache = /* @__PURE__ */ new Map();
    }
    get(u) {
      return this._sessionCache.get(u);
    }
    set(u, C) {
      if (this._maxCachedSessions !== 0) {
        if (this._sessionCache.size >= this._maxCachedSessions) {
          const { value: w } = this._sessionCache.keys().next();
          this._sessionCache.delete(w);
        }
        this._sessionCache.set(u, C);
      }
    }
  };
  function B({ allowH2: h, maxCachedSessions: u, socketPath: C, timeout: w, session: D, ...b }) {
    if (u != null && (!Number.isInteger(u) || u < 0))
      throw new o("maxCachedSessions must be a positive integer or zero");
    const U = { path: C, ...b }, G = new Q(u ?? 100);
    return w = w ?? 1e4, h = h ?? !1, function({ hostname: N, host: d, protocol: l, port: p, servername: s, localAddress: E, httpSocket: f }, I) {
      let m;
      if (l === "https:") {
        g || (g = Li), s = s || U.servername || t.getServerName(d) || null;
        const S = s || N;
        r(S);
        const T = D || G.get(S) || null;
        p = p || 443, m = g.connect({
          highWaterMark: 16384,
          // TLS in node can't have bigger HWM anyway...
          ...U,
          servername: s,
          session: T,
          localAddress: E,
          // TODO(HTTP/2): Add support for h2c
          ALPNProtocols: h ? ["http/1.1", "h2"] : ["http/1.1"],
          socket: f,
          // upgrade socket connection
          port: p,
          host: N
        }), m.on("session", function(L) {
          G.set(S, L);
        });
      } else
        r(!f, "httpSocket can only be sent on TLS update"), p = p || 80, m = e.connect({
          highWaterMark: 64 * 1024,
          // Same as nodejs fs streams.
          ...U,
          localAddress: E,
          port: p,
          host: N
        });
      if (U.keepAlive == null || U.keepAlive) {
        const S = U.keepAliveInitialDelay === void 0 ? 6e4 : U.keepAliveInitialDelay;
        m.setKeepAlive(!0, S);
      }
      const y = i(new WeakRef(m), { timeout: w, hostname: N, port: p });
      return m.setNoDelay(!0).once(l === "https:" ? "secureConnect" : "connect", function() {
        if (queueMicrotask(y), I) {
          const S = I;
          I = null, S(null, this);
        }
      }).on("error", function(S) {
        if (queueMicrotask(y), I) {
          const T = I;
          I = null, T(S);
        }
      }), m;
    };
  }
  const i = process.platform === "win32" ? (h, u) => {
    if (!u.timeout)
      return c;
    let C = null, w = null;
    const D = n.setFastTimeout(() => {
      C = setImmediate(() => {
        w = setImmediate(() => a(h.deref(), u));
      });
    }, u.timeout);
    return () => {
      n.clearFastTimeout(D), clearImmediate(C), clearImmediate(w);
    };
  } : (h, u) => {
    if (!u.timeout)
      return c;
    let C = null;
    const w = n.setFastTimeout(() => {
      C = setImmediate(() => {
        a(h.deref(), u);
      });
    }, u.timeout);
    return () => {
      n.clearFastTimeout(w), clearImmediate(C);
    };
  };
  function a(h, u) {
    if (h == null)
      return;
    let C = "Connect Timeout Error";
    Array.isArray(h.autoSelectFamilyAttemptedAddresses) ? C += ` (attempted addresses: ${h.autoSelectFamilyAttemptedAddresses.join(", ")},` : C += ` (attempted address: ${u.hostname}:${u.port},`, C += ` timeout: ${u.timeout}ms)`, t.destroy(h, new A(C));
  }
  return dt = B, dt;
}
var ft = {}, yA = {}, Us;
function Zi() {
  if (Us) return yA;
  Us = 1, Object.defineProperty(yA, "__esModule", { value: !0 }), yA.enumToMap = void 0;
  function e(r) {
    const t = {};
    return Object.keys(r).forEach((o) => {
      const A = r[o];
      typeof A == "number" && (t[o] = A);
    }), t;
  }
  return yA.enumToMap = e, yA;
}
var Ns;
function Ki() {
  return Ns || (Ns = 1, (function(e) {
    Object.defineProperty(e, "__esModule", { value: !0 }), e.SPECIAL_HEADERS = e.HEADER_STATE = e.MINOR = e.MAJOR = e.CONNECTION_TOKEN_CHARS = e.HEADER_CHARS = e.TOKEN = e.STRICT_TOKEN = e.HEX = e.URL_CHAR = e.STRICT_URL_CHAR = e.USERINFO_CHARS = e.MARK = e.ALPHANUM = e.NUM = e.HEX_MAP = e.NUM_MAP = e.ALPHA = e.FINISH = e.H_METHOD_MAP = e.METHOD_MAP = e.METHODS_RTSP = e.METHODS_ICE = e.METHODS_HTTP = e.METHODS = e.LENIENT_FLAGS = e.FLAGS = e.TYPE = e.ERROR = void 0;
    const r = Zi();
    (function(A) {
      A[A.OK = 0] = "OK", A[A.INTERNAL = 1] = "INTERNAL", A[A.STRICT = 2] = "STRICT", A[A.LF_EXPECTED = 3] = "LF_EXPECTED", A[A.UNEXPECTED_CONTENT_LENGTH = 4] = "UNEXPECTED_CONTENT_LENGTH", A[A.CLOSED_CONNECTION = 5] = "CLOSED_CONNECTION", A[A.INVALID_METHOD = 6] = "INVALID_METHOD", A[A.INVALID_URL = 7] = "INVALID_URL", A[A.INVALID_CONSTANT = 8] = "INVALID_CONSTANT", A[A.INVALID_VERSION = 9] = "INVALID_VERSION", A[A.INVALID_HEADER_TOKEN = 10] = "INVALID_HEADER_TOKEN", A[A.INVALID_CONTENT_LENGTH = 11] = "INVALID_CONTENT_LENGTH", A[A.INVALID_CHUNK_SIZE = 12] = "INVALID_CHUNK_SIZE", A[A.INVALID_STATUS = 13] = "INVALID_STATUS", A[A.INVALID_EOF_STATE = 14] = "INVALID_EOF_STATE", A[A.INVALID_TRANSFER_ENCODING = 15] = "INVALID_TRANSFER_ENCODING", A[A.CB_MESSAGE_BEGIN = 16] = "CB_MESSAGE_BEGIN", A[A.CB_HEADERS_COMPLETE = 17] = "CB_HEADERS_COMPLETE", A[A.CB_MESSAGE_COMPLETE = 18] = "CB_MESSAGE_COMPLETE", A[A.CB_CHUNK_HEADER = 19] = "CB_CHUNK_HEADER", A[A.CB_CHUNK_COMPLETE = 20] = "CB_CHUNK_COMPLETE", A[A.PAUSED = 21] = "PAUSED", A[A.PAUSED_UPGRADE = 22] = "PAUSED_UPGRADE", A[A.PAUSED_H2_UPGRADE = 23] = "PAUSED_H2_UPGRADE", A[A.USER = 24] = "USER";
    })(e.ERROR || (e.ERROR = {})), (function(A) {
      A[A.BOTH = 0] = "BOTH", A[A.REQUEST = 1] = "REQUEST", A[A.RESPONSE = 2] = "RESPONSE";
    })(e.TYPE || (e.TYPE = {})), (function(A) {
      A[A.CONNECTION_KEEP_ALIVE = 1] = "CONNECTION_KEEP_ALIVE", A[A.CONNECTION_CLOSE = 2] = "CONNECTION_CLOSE", A[A.CONNECTION_UPGRADE = 4] = "CONNECTION_UPGRADE", A[A.CHUNKED = 8] = "CHUNKED", A[A.UPGRADE = 16] = "UPGRADE", A[A.CONTENT_LENGTH = 32] = "CONTENT_LENGTH", A[A.SKIPBODY = 64] = "SKIPBODY", A[A.TRAILING = 128] = "TRAILING", A[A.TRANSFER_ENCODING = 512] = "TRANSFER_ENCODING";
    })(e.FLAGS || (e.FLAGS = {})), (function(A) {
      A[A.HEADERS = 1] = "HEADERS", A[A.CHUNKED_LENGTH = 2] = "CHUNKED_LENGTH", A[A.KEEP_ALIVE = 4] = "KEEP_ALIVE";
    })(e.LENIENT_FLAGS || (e.LENIENT_FLAGS = {}));
    var t;
    (function(A) {
      A[A.DELETE = 0] = "DELETE", A[A.GET = 1] = "GET", A[A.HEAD = 2] = "HEAD", A[A.POST = 3] = "POST", A[A.PUT = 4] = "PUT", A[A.CONNECT = 5] = "CONNECT", A[A.OPTIONS = 6] = "OPTIONS", A[A.TRACE = 7] = "TRACE", A[A.COPY = 8] = "COPY", A[A.LOCK = 9] = "LOCK", A[A.MKCOL = 10] = "MKCOL", A[A.MOVE = 11] = "MOVE", A[A.PROPFIND = 12] = "PROPFIND", A[A.PROPPATCH = 13] = "PROPPATCH", A[A.SEARCH = 14] = "SEARCH", A[A.UNLOCK = 15] = "UNLOCK", A[A.BIND = 16] = "BIND", A[A.REBIND = 17] = "REBIND", A[A.UNBIND = 18] = "UNBIND", A[A.ACL = 19] = "ACL", A[A.REPORT = 20] = "REPORT", A[A.MKACTIVITY = 21] = "MKACTIVITY", A[A.CHECKOUT = 22] = "CHECKOUT", A[A.MERGE = 23] = "MERGE", A[A["M-SEARCH"] = 24] = "M-SEARCH", A[A.NOTIFY = 25] = "NOTIFY", A[A.SUBSCRIBE = 26] = "SUBSCRIBE", A[A.UNSUBSCRIBE = 27] = "UNSUBSCRIBE", A[A.PATCH = 28] = "PATCH", A[A.PURGE = 29] = "PURGE", A[A.MKCALENDAR = 30] = "MKCALENDAR", A[A.LINK = 31] = "LINK", A[A.UNLINK = 32] = "UNLINK", A[A.SOURCE = 33] = "SOURCE", A[A.PRI = 34] = "PRI", A[A.DESCRIBE = 35] = "DESCRIBE", A[A.ANNOUNCE = 36] = "ANNOUNCE", A[A.SETUP = 37] = "SETUP", A[A.PLAY = 38] = "PLAY", A[A.PAUSE = 39] = "PAUSE", A[A.TEARDOWN = 40] = "TEARDOWN", A[A.GET_PARAMETER = 41] = "GET_PARAMETER", A[A.SET_PARAMETER = 42] = "SET_PARAMETER", A[A.REDIRECT = 43] = "REDIRECT", A[A.RECORD = 44] = "RECORD", A[A.FLUSH = 45] = "FLUSH";
    })(t = e.METHODS || (e.METHODS = {})), e.METHODS_HTTP = [
      t.DELETE,
      t.GET,
      t.HEAD,
      t.POST,
      t.PUT,
      t.CONNECT,
      t.OPTIONS,
      t.TRACE,
      t.COPY,
      t.LOCK,
      t.MKCOL,
      t.MOVE,
      t.PROPFIND,
      t.PROPPATCH,
      t.SEARCH,
      t.UNLOCK,
      t.BIND,
      t.REBIND,
      t.UNBIND,
      t.ACL,
      t.REPORT,
      t.MKACTIVITY,
      t.CHECKOUT,
      t.MERGE,
      t["M-SEARCH"],
      t.NOTIFY,
      t.SUBSCRIBE,
      t.UNSUBSCRIBE,
      t.PATCH,
      t.PURGE,
      t.MKCALENDAR,
      t.LINK,
      t.UNLINK,
      t.PRI,
      // TODO(indutny): should we allow it with HTTP?
      t.SOURCE
    ], e.METHODS_ICE = [
      t.SOURCE
    ], e.METHODS_RTSP = [
      t.OPTIONS,
      t.DESCRIBE,
      t.ANNOUNCE,
      t.SETUP,
      t.PLAY,
      t.PAUSE,
      t.TEARDOWN,
      t.GET_PARAMETER,
      t.SET_PARAMETER,
      t.REDIRECT,
      t.RECORD,
      t.FLUSH,
      // For AirPlay
      t.GET,
      t.POST
    ], e.METHOD_MAP = r.enumToMap(t), e.H_METHOD_MAP = {}, Object.keys(e.METHOD_MAP).forEach((A) => {
      /^H/.test(A) && (e.H_METHOD_MAP[A] = e.METHOD_MAP[A]);
    }), (function(A) {
      A[A.SAFE = 0] = "SAFE", A[A.SAFE_WITH_CB = 1] = "SAFE_WITH_CB", A[A.UNSAFE = 2] = "UNSAFE";
    })(e.FINISH || (e.FINISH = {})), e.ALPHA = [];
    for (let A = 65; A <= 90; A++)
      e.ALPHA.push(String.fromCharCode(A)), e.ALPHA.push(String.fromCharCode(A + 32));
    e.NUM_MAP = {
      0: 0,
      1: 1,
      2: 2,
      3: 3,
      4: 4,
      5: 5,
      6: 6,
      7: 7,
      8: 8,
      9: 9
    }, e.HEX_MAP = {
      0: 0,
      1: 1,
      2: 2,
      3: 3,
      4: 4,
      5: 5,
      6: 6,
      7: 7,
      8: 8,
      9: 9,
      A: 10,
      B: 11,
      C: 12,
      D: 13,
      E: 14,
      F: 15,
      a: 10,
      b: 11,
      c: 12,
      d: 13,
      e: 14,
      f: 15
    }, e.NUM = [
      "0",
      "1",
      "2",
      "3",
      "4",
      "5",
      "6",
      "7",
      "8",
      "9"
    ], e.ALPHANUM = e.ALPHA.concat(e.NUM), e.MARK = ["-", "_", ".", "!", "~", "*", "'", "(", ")"], e.USERINFO_CHARS = e.ALPHANUM.concat(e.MARK).concat(["%", ";", ":", "&", "=", "+", "$", ","]), e.STRICT_URL_CHAR = [
      "!",
      '"',
      "$",
      "%",
      "&",
      "'",
      "(",
      ")",
      "*",
      "+",
      ",",
      "-",
      ".",
      "/",
      ":",
      ";",
      "<",
      "=",
      ">",
      "@",
      "[",
      "\\",
      "]",
      "^",
      "_",
      "`",
      "{",
      "|",
      "}",
      "~"
    ].concat(e.ALPHANUM), e.URL_CHAR = e.STRICT_URL_CHAR.concat(["	", "\f"]);
    for (let A = 128; A <= 255; A++)
      e.URL_CHAR.push(A);
    e.HEX = e.NUM.concat(["a", "b", "c", "d", "e", "f", "A", "B", "C", "D", "E", "F"]), e.STRICT_TOKEN = [
      "!",
      "#",
      "$",
      "%",
      "&",
      "'",
      "*",
      "+",
      "-",
      ".",
      "^",
      "_",
      "`",
      "|",
      "~"
    ].concat(e.ALPHANUM), e.TOKEN = e.STRICT_TOKEN.concat([" "]), e.HEADER_CHARS = ["	"];
    for (let A = 32; A <= 255; A++)
      A !== 127 && e.HEADER_CHARS.push(A);
    e.CONNECTION_TOKEN_CHARS = e.HEADER_CHARS.filter((A) => A !== 44), e.MAJOR = e.NUM_MAP, e.MINOR = e.MAJOR;
    var o;
    (function(A) {
      A[A.GENERAL = 0] = "GENERAL", A[A.CONNECTION = 1] = "CONNECTION", A[A.CONTENT_LENGTH = 2] = "CONTENT_LENGTH", A[A.TRANSFER_ENCODING = 3] = "TRANSFER_ENCODING", A[A.UPGRADE = 4] = "UPGRADE", A[A.CONNECTION_KEEP_ALIVE = 5] = "CONNECTION_KEEP_ALIVE", A[A.CONNECTION_CLOSE = 6] = "CONNECTION_CLOSE", A[A.CONNECTION_UPGRADE = 7] = "CONNECTION_UPGRADE", A[A.TRANSFER_ENCODING_CHUNKED = 8] = "TRANSFER_ENCODING_CHUNKED";
    })(o = e.HEADER_STATE || (e.HEADER_STATE = {})), e.SPECIAL_HEADERS = {
      connection: o.CONNECTION,
      "content-length": o.CONTENT_LENGTH,
      "proxy-connection": o.CONNECTION,
      "transfer-encoding": o.TRANSFER_ENCODING,
      upgrade: o.UPGRADE
    };
  })(ft)), ft;
}
var pt, Ms;
function Ls() {
  if (Ms) return pt;
  Ms = 1;
  const { Buffer: e } = sA;
  return pt = e.from("AGFzbQEAAAABJwdgAX8Bf2ADf39/AX9gAX8AYAJ/fwBgBH9/f38Bf2AAAGADf39/AALLAQgDZW52GHdhc21fb25faGVhZGVyc19jb21wbGV0ZQAEA2VudhV3YXNtX29uX21lc3NhZ2VfYmVnaW4AAANlbnYLd2FzbV9vbl91cmwAAQNlbnYOd2FzbV9vbl9zdGF0dXMAAQNlbnYUd2FzbV9vbl9oZWFkZXJfZmllbGQAAQNlbnYUd2FzbV9vbl9oZWFkZXJfdmFsdWUAAQNlbnYMd2FzbV9vbl9ib2R5AAEDZW52GHdhc21fb25fbWVzc2FnZV9jb21wbGV0ZQAAAy0sBQYAAAIAAAAAAAACAQIAAgICAAADAAAAAAMDAwMBAQEBAQEBAQEAAAIAAAAEBQFwARISBQMBAAIGCAF/AUGA1AQLB9EFIgZtZW1vcnkCAAtfaW5pdGlhbGl6ZQAIGV9faW5kaXJlY3RfZnVuY3Rpb25fdGFibGUBAAtsbGh0dHBfaW5pdAAJGGxsaHR0cF9zaG91bGRfa2VlcF9hbGl2ZQAvDGxsaHR0cF9hbGxvYwALBm1hbGxvYwAxC2xsaHR0cF9mcmVlAAwEZnJlZQAMD2xsaHR0cF9nZXRfdHlwZQANFWxsaHR0cF9nZXRfaHR0cF9tYWpvcgAOFWxsaHR0cF9nZXRfaHR0cF9taW5vcgAPEWxsaHR0cF9nZXRfbWV0aG9kABAWbGxodHRwX2dldF9zdGF0dXNfY29kZQAREmxsaHR0cF9nZXRfdXBncmFkZQASDGxsaHR0cF9yZXNldAATDmxsaHR0cF9leGVjdXRlABQUbGxodHRwX3NldHRpbmdzX2luaXQAFQ1sbGh0dHBfZmluaXNoABYMbGxodHRwX3BhdXNlABcNbGxodHRwX3Jlc3VtZQAYG2xsaHR0cF9yZXN1bWVfYWZ0ZXJfdXBncmFkZQAZEGxsaHR0cF9nZXRfZXJybm8AGhdsbGh0dHBfZ2V0X2Vycm9yX3JlYXNvbgAbF2xsaHR0cF9zZXRfZXJyb3JfcmVhc29uABwUbGxodHRwX2dldF9lcnJvcl9wb3MAHRFsbGh0dHBfZXJybm9fbmFtZQAeEmxsaHR0cF9tZXRob2RfbmFtZQAfEmxsaHR0cF9zdGF0dXNfbmFtZQAgGmxsaHR0cF9zZXRfbGVu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PgtBhwEMPQtBiAEMPAtBiQEMOwtBigEMOgtBiwEMOQtBjAEMOAtBjQEMNwtBjgEMNgtBjwEMNQtBkAEMNAtBkQEMMwtBkgEMMgtBkwEMMQtBlAEMMAtBlQEMLwtBlgEMLgtBlwEMLQtBmAEMLAtBmQEMKwtBmgEMKgtBmwEMKQtBnAEMKAtBnQEMJwtBngEMJgtBnwEMJQtBoAEMJAtBoQEMIwtBogEMIgtBowEMIQtBpAEMIAtBpQEMHwtBpgEMHgtBpwEMHQtBqAEMHAtBqQEMGwtBqgEMGgtBqwEMGQtBrAEMGAtBrQEMFwtBrgEMFgtBAQwVC0GvAQwUC0GwAQwTC0GxAQwSC0GzAQwRC0GyAQwQC0G0AQwPC0G1AQwOC0G2AQwNC0G3AQwMC0G4AQwLC0G5AQwKC0G6AQwJC0G7AQwIC0HGAQwHC0G8AQwGC0G9AQwFC0G+AQwEC0G/AQwDC0HAAQwCC0HCAQwBC0HBAQshAwNAAkACQAJAAkACQAJAAkACQAJAIAICfwJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJ/AkACQAJAAkACQAJAAkACQAJAAkACQAJAAkAgAgJ/AkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACfwJAAkACfwJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkAC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iQEhAwykAgtBASABLQAAQd8ARw1nGiABQQFqIQEMXgtBigEhAyABIARGDaICIAIoAgAiACAEIAFraiEFIAEgAGtBAWohBgNAIAEtAAAgAEGMzwBqLQAARw1kIABBAUYN+gEgAEEBaiEAIAQgAUEBaiIBRw0ACyACIAU2AgAMogILQYsBIQMgASAERg2hAiACKAIAIgAgBCABa2ohBSABIABrQQJqIQYCQANAIAEtAAAgAEGOzwBqLQAARw1kIABBAkYNASAAQQFqIQAgBCABQQFqIgFHDQALIAIgBTYCAAyiAgsgAkEANgIAIAZBAWohAUECDGULQYwBIQMgASAERg2gAiACKAIAIgAgBCABa2ohBSABIABrQQFqIQYCQANAIAEtAAAgAEHwzwBqLQAARw1jIABBAUYNASAAQQFqIQAgBCABQQFqIgFHDQALIAIgBTYCAAyhAgsgAkEANgIAIAZBAWohAUEfDGQLQY0BIQMgASAERg2fAiACKAIAIgAgBCABa2ohBSABIABrQQFqIQYCQANAIAEtAAAgAEHyzwBqLQAARw1iIABBAUYNASAAQQFqIQAgBCABQQFqIgFHDQALIAIgBTYCAAygAgsgAkEANgIAIAZBAWohAUEJDGMLIAEgBEYEQEGOASEDDJ8CCwJAAkAgAS0AAEHJAGsOBwBiYmJiYgFiCyABQQFqIQFB+AAhAwyGAgsgAUEBaiEBQfkAIQMMhQILQY8BIQMgASAERg2dAiACKAIAIgAgBCABa2ohBSABIABrQQVqIQYCQANAIAEtAAAgAEGRzwBqLQAARw1gIABBBUYNASAAQQFqIQAgBCABQQFqIgFHDQALIAIgBTYCAAyeAgsgAkEANgIAIAZBAWohAUEYDGELQZABIQMgASAERg2cAiACKAIAIgAgBCABa2ohBSABIABrQQJqIQYCQANAIAEtAAAgAEGXzwBqLQAARw1fIABBAkYNASAAQQFqIQAgBCABQQFqIgFHDQALIAIgBTYCAAydAgsgAkEANgIAIAZBAWohAUEXDGALQZEBIQMgASAERg2bAiACKAIAIgAgBCABa2ohBSABIABrQQZqIQYCQANAIAEtAAAgAEGazwBqLQAARw1eIABBBkYNASAAQQFqIQAgBCABQQFqIgFHDQALIAIgBTYCAAycAgsgAkEANgIAIAZBAWohAUEV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JSIARQ0RIAJB5QA2AhwgAiABNgIUIAIgADYCDEEAIQMMtAELIAIoAgQhACACQQA2AgQgAiAAIAEQJSIARQ0gIAJB0wA2AhwgAiABNgIUIAIgADYCDEEAIQMMswELIAIoAgQhACACQQA2AgQgAiAAIAEQJSIARQ0iIAJB0gA2AhwgAiABNgIUIAIgADYCDEEAIQMMsgELIAIoAgQhACACQQA2AgQgAiAAIAEQJSIARQ0OIAJB5QA2AhwgAiABNgIUIAIgADYCDEEAIQMMsQELIAIoAgQhACACQQA2AgQgAiAAIAEQJSIARQ0dIAJB0wA2AhwgAiABNgIUIAIgADYCDEEAIQMMsAELIAIoAgQhACACQQA2AgQgAiAAIAEQJSIARQ0fIAJB0gA2AhwgAiABNgIUIAIgADYCDEEAIQMMrwELIABBP0cNASABQQFqCyEBQQUhAwyUAQtBACEDIAJBADYCHCACIAE2AhQgAkH9EjYCECACQQc2AgwMrAELIAJBADYCHCACIAE2AhQgAkHcCDYCECACQQc2AgxBACEDDKsBCyACKAIEIQAgAkEANgIEIAIgACABECUiAEUNByACQeUANgIcIAIgATYCFCACIAA2AgxBACEDDKoBCyACKAIEIQAgAkEANgIEIAIgACABECUiAEUNFiACQdMANgIcIAIgATYCFCACIAA2AgxBACEDDKkBCyACKAIEIQAgAkEANgIEIAIgACABECUiAEUNGCACQdIANgIcIAIgATYCFCACIAA2AgxBACEDDKgBCyACQQA2AhwgAiABNgIUIAJBxgo2AhAgAkEHNgIMQQAhAwynAQsgAigCBCEAIAJBADYCBCACIAAgARAlIgBFDQMgAkHlADYCHCACIAE2AhQgAiAANgIMQQAhAwymAQsgAigCBCEAIAJBADYCBCACIAAgARAlIgBFDRIgAkHTADYCHCACIAE2AhQgAiAANgIMQQAhAwylAQsgAigCBCEAIAJBADYCBCACIAAgARAlIgBFDRQgAkHSADYCHCACIAE2AhQgAiAANgIMQQAhAwykAQsgAigCBCEAIAJBADYCBCACIAAgARAlIgBFDQAgAkHlADYCHCACIAE2AhQgAiAANgIMQQAhAwyjAQtB1QAhAwyJAQsgAEEVRwRAIAJBADYCHCACIAE2AhQgAkG5DTYCECACQRo2AgxB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AkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAIABB5ABrDvQDY2IAAWFhYWFhYQIDBAVhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhBgcICQoLDA0OD2FhYWFhEGFhYWFhYWFhYWFhEWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYRITFBUWFxgZGhthYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2YTc4OTphYWFhYWFhYTthYWE8YWFhYT0+P2FhYWFhYWFhQGFhQWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYUJDREVGR0hJSktMTU5PUFFSU2FhYWFhYWFhVFVWV1hZWlthXF1hYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFeYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhX2BhC0HhJw8LQaQhDwtByywPC0H+MQ8LQcAkDwtBqyQPC0GNKA8LQeImDwtBgDAPC0G5Lw8LQdckDwtB7x8PC0HhHw8LQfofDwtB8iAPC0GoLw8LQa4yDwtBiDAPC0HsJw8LQYIiDwtBjh0PC0HQLg8LQcojDwtBxTIPC0HfHA8LQdIcDwtBxCAPC0HXIA8LQaIfDwtB7S4PC0GrMA8LQdQlDwtBzC4PC0H6Lg8LQfwrDwtB0jAPC0HxHQ8LQbsgDwtB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CABB3AgLii1JbnZhbGlkIGNoYXIgaW4gdXJsIHF1ZXJ5AFNwYW4gY2FsbGJhY2sgZXJyb3IgaW4gb25fYm9keQBDb250ZW50LUxlbmd0aCBvdmVyZmxvdwBDaHVuayBzaXplIG92ZXJmbG93AFJlc3BvbnNlIG92ZXJmbG93AEludmFsaWQgbWV0aG9kIGZvciBIVFRQL3gueCByZXF1ZXN0AEludmFsaWQgbWV0aG9kIGZvciBSVFNQL3gueCByZXF1ZXN0AEV4cGVjdGVkIFNPVVJDRSBtZXRob2QgZm9yIElDRS94LnggcmVxdWVzdABJbnZhbGlkIGNoYXIgaW4gdXJsIGZyYWdtZW50IHN0YXJ0AEV4cGVjdGVkIGRvdABTcGFuIGNhbGxiYWNrIGVycm9yIGluIG9uX3N0YXR1cwBJbnZhbGlkIHJlc3BvbnNlIHN0YXR1cwBJbnZhbGlkIGNoYXJhY3RlciBpbiBjaHVuayBleHRlbnNpb25zAFVzZXIgY2FsbGJhY2sgZXJyb3IAYG9uX3Jlc2V0YCBjYWxsYmFjayBlcnJvcgBgb25fY2h1bmtfaGVhZGVyYCBjYWxsYmFjayBlcnJvcgBgb25fbWVzc2FnZV9iZWdpbmAgY2FsbGJhY2sgZXJyb3IAYG9uX2NodW5rX2V4dGVuc2lvbl92YWx1ZWAgY2FsbGJhY2sgZXJyb3IAYG9uX3N0YXR1c19jb21wbGV0ZWAgY2FsbGJhY2sgZXJyb3IAYG9uX3ZlcnNpb25fY29tcGxldGVgIGNhbGxiYWNrIGVycm9yAGBvbl91cmxfY29tcGxldGVgIGNhbGxiYWNrIGVycm9yAGBvbl9jaHVua19jb21wbGV0ZWAgY2FsbGJhY2sgZXJyb3IAYG9uX2hlYWRlcl92YWx1ZV9jb21wbGV0ZWAgY2FsbGJhY2sgZXJyb3IAYG9uX21lc3NhZ2VfY29tcGxldGVgIGNhbGxiYWNrIGVycm9yAGBvbl9tZXRob2RfY29tcGxldGVgIGNhbGxiYWNrIGVycm9yAGBvbl9oZWFkZXJfZmllbGRfY29tcGxldGVgIGNhbGxiYWNrIGVycm9yAGBvbl9jaHVua19leHRlbnNpb25fbmFtZWAgY2FsbGJhY2sgZXJyb3IAVW5leHBlY3RlZCBjaGFyIGluIHVybCBzZXJ2ZXIASW52YWxpZCBoZWFkZXIgdmFsdWUgY2hhcgBJbnZhbGlkIGhlYWRlciBmaWVsZCBjaGFyAFNwYW4gY2FsbGJhY2sgZXJyb3IgaW4gb25fdmVyc2lvbgBJbnZhbGlkIG1pbm9yIHZlcnNpb24ASW52YWxpZCBtYWpvciB2ZXJzaW9uAEV4cGVjdGVkIHNwYWNlIGFmdGVyIHZlcnNpb24ARXhwZWN0ZWQgQ1JMRiBhZnRlciB2ZXJzaW9uAEludmFsaWQgSFRUUCB2ZXJzaW9uAEludmFsaWQgaGVhZGVyIHRva2VuAFNwYW4gY2FsbGJhY2sgZXJyb3IgaW4gb25fdXJsAEludmFsaWQgY2hhcmFjdGVycyBpbiB1cmwAVW5leHBlY3RlZCBzdGFydCBjaGFyIGluIHVybABEb3VibGUgQCBpbiB1cmwARW1wdHkgQ29udGVudC1MZW5ndGgASW52YWxpZCBjaGFyYWN0ZXIgaW4gQ29udGVudC1MZW5ndGgARHVwbGljYXRlIENvbnRlbnQtTGVuZ3RoAEludmFsaWQgY2hhciBpbiB1cmwgcGF0aABDb250ZW50LUxlbmd0aCBjYW4ndCBiZSBwcmVzZW50IHdpdGggVHJhbnNmZXItRW5jb2RpbmcASW52YWxpZCBjaGFyYWN0ZXIgaW4gY2h1bmsgc2l6ZQBTcGFuIGNhbGxiYWNrIGVycm9yIGluIG9uX2hlYWRlcl92YWx1ZQBTcGFuIGNhbGxiYWNrIGVycm9yIGluIG9uX2NodW5rX2V4dGVuc2lvbl92YWx1ZQBJbnZhbGlkIGNoYXJhY3RlciBpbiBjaHVuayBleHRlbnNpb25zIHZhbHVlAE1pc3NpbmcgZXhwZWN0ZWQgTEYgYWZ0ZXIgaGVhZGVyIHZhbHVlAEludmFsaWQgYFRyYW5zZmVyLUVuY29kaW5nYCBoZWFkZXIgdmFsdWUASW52YWxpZCBjaGFyYWN0ZXIgaW4gY2h1bmsgZXh0ZW5zaW9ucyBxdW90ZSB2YWx1ZQBJbnZhbGlkIGNoYXJhY3RlciBpbiBjaHVuayBleHRlbnNpb25zIHF1b3RlZCB2YWx1ZQBQYXVzZWQgYnkgb25faGVhZGVyc19jb21wbGV0ZQBJbnZhbGlkIEVPRiBzdGF0ZQBvbl9yZXNldCBwYXVzZQBvbl9jaHVua19oZWFkZXIgcGF1c2UAb25fbWVzc2FnZV9iZWdpbiBwYXVzZQBvbl9jaHVua19leHRlbnNpb25fdmFsdWUgcGF1c2UAb25fc3RhdHVzX2NvbXBsZXRlIHBhdXNlAG9uX3ZlcnNpb25fY29tcGxldGUgcGF1c2UAb25fdXJsX2NvbXBsZXRlIHBhdXNlAG9uX2NodW5rX2NvbXBsZXRlIHBhdXNlAG9uX2hlYWRlcl92YWx1ZV9jb21wbGV0ZSBwYXVzZQBvbl9tZXNzYWdlX2NvbXBsZXRlIHBhdXNlAG9uX21ldGhvZF9jb21wbGV0ZSBwYXVzZQBvbl9oZWFkZXJfZmllbGRfY29tcGxldGUgcGF1c2UAb25fY2h1bmtfZXh0ZW5zaW9uX25hbWUgcGF1c2UAVW5leHBlY3RlZCBzcGFjZSBhZnRlciBzdGFydCBsaW5lAFNwYW4gY2FsbGJhY2sgZXJyb3IgaW4gb25fY2h1bmtfZXh0ZW5zaW9uX25hbWUASW52YWxpZCBjaGFyYWN0ZXIgaW4gY2h1bmsgZXh0ZW5zaW9ucyBuYW1lAFBhdXNlIG9uIENPTk5FQ1QvVXBncmFkZQBQYXVzZSBvbiBQUkkvVXBncmFkZQBFeHBlY3RlZCBIVFRQLzIgQ29ubmVjdGlvbiBQcmVmYWNlAFNwYW4gY2FsbGJhY2sgZXJyb3IgaW4gb25fbWV0aG9kAEV4cGVjdGVkIHNwYWNlIGFmdGVyIG1ldGhvZABTcGFuIGNhbGxiYWNrIGVycm9yIGluIG9uX2hlYWRlcl9maWVsZABQYXVzZWQASW52YWxpZCB3b3JkIGVuY291bnRlcmVkAEludmFsaWQgbWV0aG9kIGVuY291bnRlcmVkAFVuZXhwZWN0ZWQgY2hhciBpbiB1cmwgc2NoZW1hAFJlcXVlc3QgaGFzIGludmFsaWQgYFRyYW5zZmVyLUVuY29kaW5nYABTV0lUQ0hfUFJPWFkAVVNFX1BST1hZAE1LQUNUSVZJVFkAVU5QUk9DRVNTQUJMRV9FTlRJVFkAQ09QWQBNT1ZFRF9QRVJNQU5FTlRMWQBUT09fRUFSTFkATk9USUZZAEZBSUxFRF9ERVBFTkRFTkNZAEJBRF9HQVRFV0FZAFBMQVkAUFVUAENIRUNLT1VUAEdBVEVXQVlfVElNRU9VVABSRVFVRVNUX1RJTUVPVVQATkVUV09SS19DT05ORUNUX1RJTUVPVVQAQ09OTkVDVElPTl9USU1FT1VUAExPR0lOX1RJTUVPVVQATkVUV09SS19SRUFEX1RJTUVPVVQAUE9TVABNSVNESVJFQ1RFRF9SRVFVRVNUAENMSUVOVF9DTE9TRURfUkVRVUVTVABDTElFTlRfQ0xPU0VEX0xPQURfQkFMQU5DRURfUkVRVUVTVABCQURfUkVRVUVTVABIVFRQX1JFUVVFU1RfU0VOVF9UT19IVFRQU19QT1JUAFJFUE9SVABJTV9BX1RFQVBPVABSRVNFVF9DT05URU5UAE5PX0NPTlRFTlQAUEFSVElBTF9DT05URU5UAEhQRV9JTlZBTElEX0NPTlNUQU5UAEhQRV9DQl9SRVNFVABHRVQASFBFX1NUUklDVABDT05GTElDVABURU1QT1JBUllfUkVESVJFQ1QAUEVSTUFORU5UX1JFRElSRUNUAENPTk5FQ1QATVVMVElfU1RBVFVTAEhQRV9JTlZBTElEX1NUQVRVUwBUT09fTUFOWV9SRVFVRVNUUwBFQVJMWV9ISU5UUwBVTkFWQUlMQUJMRV9GT1JfTEVHQUxfUkVBU09OUwBPUFRJT05TAFNXSVRDSElOR19QUk9UT0NPTFMAVkFSSUFOVF9BTFNPX05FR09USUFURVMATVVMVElQTEVfQ0hPSUNFUwBJTlRFUk5BTF9TRVJWRVJfRVJST1IAV0VCX1NFUlZFUl9VTktOT1dOX0VSUk9SAFJBSUxHVU5fRVJST1IASURFTlRJVFlfUFJPVklERVJfQVVUSEVOVElDQVRJT05fRVJST1IAU1NMX0NFUlRJRklDQVRFX0VSUk9SAElOVkFMSURfWF9GT1JXQVJERURfRk9SAFNFVF9QQVJBTUVURVIAR0VUX1BBUkFNRVRFUgBIUEVfVVNFUgBTRUVfT1RIRVIASFBFX0NCX0NIVU5LX0hFQURFUgBNS0NBTEVOREFSAFNFVFVQAFdFQl9TRVJWRVJfSVNfRE9XTgBURUFSRE9XTgBIUEVfQ0xPU0VEX0NPTk5FQ1RJT04ASEVVUklTVElDX0VYUElSQVRJT04ARElTQ09OTkVDVEVEX09QRVJBVElPTgBOT05fQVVUSE9SSVRBVElWRV9JTkZPUk1BVElPTgBIUEVfSU5WQUxJRF9WRVJTSU9OAEhQRV9DQl9NRVNTQUdFX0JFR0lOAFNJVEVfSVNfRlJPWkVOAEhQRV9JTlZBTElEX0hFQURFUl9UT0tFTgBJTlZBTElEX1RPS0VOAEZPUkJJRERFTgBFTkhBTkNFX1lPVVJfQ0FMTQBIUEVfSU5WQUxJRF9VUkwAQkxPQ0tFRF9CWV9QQVJFTlRBTF9DT05UUk9MAE1LQ09MAEFDTABIUEVfSU5URVJOQUwAUkVRVUVTVF9IRUFERVJfRklFTERTX1RPT19MQVJHRV9VTk9GRklDSUFMAEhQRV9PSwBVTkxJTksAVU5MT0NLAFBSSQBSRVRSWV9XSVRIAEhQRV9JTlZBTElEX0NPTlRFTlRfTEVOR1RIAEhQRV9VTkVYUEVDVEVEX0NPTlRFTlRfTEVOR1RIAEZMVVNIAFBST1BQQVRDSABNLVNFQVJDSABVUklfVE9PX0xPTkcAUFJPQ0VTU0lORwBNSVNDRUxMQU5FT1VTX1BFUlNJU1RFTlRfV0FSTklORwBNSVNDRUxMQU5FT1VTX1dBUk5JTkcASFBFX0lOVkFMSURfVFJBTlNGRVJfRU5DT0RJTkcARXhwZWN0ZWQgQ1JMRgBIUEVfSU5WQUxJRF9DSFVOS19TSVpFAE1PVkUAQ09OVElOVUUASFBFX0NCX1NUQVRVU19DT01QTEVURQBIUEVfQ0JfSEVBREVSU19DT01QTEVURQBIUEVfQ0JfVkVSU0lPTl9DT01QTEVURQBIUEVfQ0JfVVJMX0NPTVBMRVRFAEhQRV9DQl9DSFVOS19DT01QTEVURQBIUEVfQ0JfSEVBREVSX1ZBTFVFX0NPTVBMRVRFAEhQRV9DQl9DSFVOS19FWFRFTlNJT05fVkFMVUVfQ09NUExFVEUASFBFX0NCX0NIVU5LX0VYVEVOU0lPTl9OQU1FX0NPTVBMRVRFAEhQRV9DQl9NRVNTQUdFX0NPTVBMRVRFAEhQRV9DQl9NRVRIT0RfQ09NUExFVEUASFBFX0NCX0hFQURFUl9GSUVMRF9DT01QTEVURQBERUxFVEUASFBFX0lOVkFMSURfRU9GX1NUQVRFAElOVkFMSURfU1NMX0NFUlRJRklDQVRFAFBBVVNFAE5PX1JFU1BPTlNFAFVOU1VQUE9SVEVEX01FRElBX1RZUEUAR09ORQBOT1RfQUNDRVBUQUJMRQBTRVJWSUNFX1VOQVZBSUxBQkxFAFJBTkdFX05PVF9TQVRJU0ZJQUJMRQBPUklHSU5fSVNfVU5SRUFDSEFCTEUAUkVTUE9OU0VfSVNfU1RBTEUAUFVSR0UATUVSR0UAUkVRVUVTVF9IRUFERVJfRklFTERTX1RPT19MQVJHRQBSRVFVRVNUX0hFQURFUl9UT09fTEFSR0UAUEFZTE9BRF9UT09fTEFSR0UASU5TVUZGSUNJRU5UX1NUT1JBR0UASFBFX1BBVVNFRF9VUEdSQURFAEhQRV9QQVVTRURfSDJfVVBHUkFERQBTT1VSQ0UAQU5OT1VOQ0UAVFJBQ0UASFBFX1VORVhQRUNURURfU1BBQ0UAREVTQ1JJQkUAVU5TVUJTQ1JJQkUAUkVDT1JEAEhQRV9JTlZBTElEX01FVEhPRABOT1RfRk9VTkQAUFJPUEZJTkQAVU5CSU5EAFJFQklORABVTkFVVEhPUklaRUQATUVUSE9EX05PVF9BTExPV0VEAEhUVFBfVkVSU0lPTl9OT1RfU1VQUE9SVEVEAEFMUkVBRFlfUkVQT1JURUQAQUNDRVBURUQATk9UX0lNUExFTUVOVEVEAExPT1BfREVURUNURUQASFBFX0NSX0VYUEVDVEVEAEhQRV9MRl9FWFBFQ1RFRABDUkVBVEVEAElNX1VTRUQASFBFX1BBVVNFRABUSU1FT1VUX09DQ1VSRUQAUEFZTUVOVF9SRVFVSVJFRABQUkVDT05ESVRJT05fUkVRVUlSRUQAUFJPWFlfQVVUSEVOVElDQVRJT05fUkVRVUlSRUQATkVUV09SS19BVVRIRU5USUNBVElPTl9SRVFVSVJFRABMRU5HVEhfUkVRVUlSRUQAU1NMX0NFUlRJRklDQVRFX1JFUVVJUkVEAFVQR1JBREVfUkVRVUlSRUQAUEFHRV9FWFBJUkVEAFBSRUNPTkRJVElPTl9GQUlMRUQARVhQRUNUQVRJT05fRkFJTEVEAFJFVkFMSURBVElPTl9GQUlMRUQAU1NMX0hBTkRTSEFLRV9GQUlMRUQATE9DS0VEAFRSQU5TRk9STUFUSU9OX0FQUExJRUQATk9UX01PRElGSUVEAE5PVF9FWFRFTkRFRABCQU5EV0lEVEhfTElNSVRfRVhDRUVERUQAU0lURV9JU19PVkVSTE9BREVEAEhFQUQARXhwZWN0ZWQgSFRUUC8AAF4TAAAmEwAAMBAAAPAXAACdEwAAFRIAADkXAADwEgAAChAAAHUSAACtEgAAghMAAE8UAAB/EAAAoBUAACMUAACJEgAAixQAAE0VAADUEQAAzxQAABAYAADJFgAA3BYAAMERAADgFwAAuxQAAHQUAAB8FQAA5RQAAAgXAAAfEAAAZRUAAKMUAAAoFQAAAhUAAJkVAAAsEAAAixkAAE8PAADUDgAAahAAAM4QAAACFwAAiQ4AAG4TAAAcEwAAZhQAAFYXAADBEwAAzRMAAGwTAABoFwAAZhcAAF8XAAAiEwAAzg8AAGkOAADYDgAAYxYAAMsTAACqDgAAKBcAACYXAADFEwAAXRYAAOgRAABnEwAAZRMAAPIWAABzEwAAHRcAAPkWAADzEQAAzw4AAM4VAAAMEgAAsxEAAKURAABhEAAAMhcAALsTAEH5NQsBAQBBkDYL4AEBAQIBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQBB/TcLAQEAQZE4C14CAwICAgICAAACAgACAgACAgICAgICAgICAAQAAAAAAAICAgICAgICAgICAgICAgICAgICAgICAgICAAAAAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAAgACAEH9OQsBAQBBkToLXgIAAgICAgIAAAICAAICAAICAgICAgICAgIAAwAEAAAAAgICAgICAgICAgICAgICAgICAgICAgICAgIAAAACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgACAAIAQfA7Cw1sb3NlZWVwLWFsaXZlAEGJPAsBAQBBoDwL4AEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQBBiT4LAQEAQaA+C+cBAQEBAQEBAQEBAQEBAgEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQFjaHVua2VkAEGwwAALXwEBAAEBAQEBAAABAQABAQABAQEBAQEBAQEBAAAAAAAAAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAAAAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAAQABAEGQwgALIWVjdGlvbmVudC1sZW5ndGhvbnJveHktY29ubmVjdGlvbgBBwMIACy1yYW5zZmVyLWVuY29kaW5ncGdyYWRlDQoNCg0KU00NCg0KVFRQL0NFL1RTUC8AQfnCAAsFAQIAAQMAQZDDAAvgAQQBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAEH5xAALBQECAAEDAEGQxQAL4AEEAQEFAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQBB+cYACwQBAAABAEGRxwAL3wEBAQABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAEH6yAALBAEAAAIAQZDJAAtfAwQAAAQEBAQEBAQEBAQEBQQEBAQEBAQEBAQEBAAEAAYHBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAAQABAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAAAAQAQfrKAAsEAQAAAQBBkMsACwEBAEGqywALQQIAAAAAAAADAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwAAAAAAAAMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAEH6zAALBAEAAAEAQZDNAAsBAQBBms0ACwYCAAAAAAIAQbHNAAs6AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMAAAAAAAADAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwBB8M4AC5YBTk9VTkNFRUNLT1VUTkVDVEVURUNSSUJFTFVTSEVURUFEU0VBUkNIUkdFQ1RJVklUWUxFTkRBUlZFT1RJRllQVElPTlNDSFNFQVlTVEFUQ0hHRU9SRElSRUNUT1JUUkNIUEFSQU1FVEVSVVJDRUJTQ1JJQkVBUkRPV05BQ0VJTkROS0NLVUJTQ1JJQkVIVFRQL0FEVFAv", "base64"), pt;
}
var wt, Gs;
function Xi() {
  if (Gs) return wt;
  Gs = 1;
  const { Buffer: e } = sA;
  return wt = e.from("AGFzbQEAAAABJwdgAX8Bf2ADf39/AX9gAX8AYAJ/fwBgBH9/f38Bf2AAAGADf39/AALLAQgDZW52GHdhc21fb25faGVhZGVyc19jb21wbGV0ZQAEA2VudhV3YXNtX29uX21lc3NhZ2VfYmVnaW4AAANlbnYLd2FzbV9vbl91cmwAAQNlbnYOd2FzbV9vbl9zdGF0dXMAAQNlbnYUd2FzbV9vbl9oZWFkZXJfZmllbGQAAQNlbnYUd2FzbV9vbl9oZWFkZXJfdmFsdWUAAQNlbnYMd2FzbV9vbl9ib2R5AAEDZW52GHdhc21fb25fbWVzc2FnZV9jb21wbGV0ZQAAAy0sBQYAAAIAAAAAAAACAQIAAgICAAADAAAAAAMDAwMBAQEBAQEBAQEAAAIAAAAEBQFwARISBQMBAAIGCAF/AUGA1AQLB9EFIgZtZW1vcnkCAAtfaW5pdGlhbGl6ZQAIGV9faW5kaXJlY3RfZnVuY3Rpb25fdGFibGUBAAtsbGh0dHBfaW5pdAAJGGxsaHR0cF9zaG91bGRfa2VlcF9hbGl2ZQAvDGxsaHR0cF9hbGxvYwALBm1hbGxvYwAxC2xsaHR0cF9mcmVlAAwEZnJlZQAMD2xsaHR0cF9nZXRfdHlwZQANFWxsaHR0cF9nZXRfaHR0cF9tYWpvcgAOFWxsaHR0cF9nZXRfaHR0cF9taW5vcgAPEWxsaHR0cF9nZXRfbWV0aG9kABAWbGxodHRwX2dldF9zdGF0dXNfY29kZQAREmxsaHR0cF9nZXRfdXBncmFkZQASDGxsaHR0cF9yZXNldAATDmxsaHR0cF9leGVjdXRlABQUbGxodHRwX3NldHRpbmdzX2luaXQAFQ1sbGh0dHBfZmluaXNoABYMbGxodHRwX3BhdXNlABcNbGxodHRwX3Jlc3VtZQAYG2xsaHR0cF9yZXN1bWVfYWZ0ZXJfdXBncmFkZQAZEGxsaHR0cF9nZXRfZXJybm8AGhdsbGh0dHBfZ2V0X2Vycm9yX3JlYXNvbgAbF2xsaHR0cF9zZXRfZXJyb3JfcmVhc29uABwUbGxodHRwX2dldF9lcnJvcl9wb3MAHRFsbGh0dHBfZXJybm9fbmFtZQAeEmxsaHR0cF9tZXRob2RfbmFtZQAfEmxsaHR0cF9zdGF0dXNfbmFtZQAgGmxsaHR0cF9zZXRfbGVu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PgtBhwEMPQtBiAEMPAtBiQEMOwtBigEMOgtBiwEMOQtBjAEMOAtBjQEMNwtBjgEMNgtBjwEMNQtBkAEMNAtBkQEMMwtBkgEMMgtBkwEMMQtBlAEMMAtBlQEMLwtBlgEMLgtBlwEMLQtBmAEMLAtBmQEMKwtBmgEMKgtBmwEMKQtBnAEMKAtBnQEMJwtBngEMJgtBnwEMJQtBoAEMJAtBoQEMIwtBogEMIgtBowEMIQtBpAEMIAtBpQEMHwtBpgEMHgtBpwEMHQtBqAEMHAtBqQEMGwtBqgEMGgtBqwEMGQtBrAEMGAtBrQEMFwtBrgEMFgtBAQwVC0GvAQwUC0GwAQwTC0GxAQwSC0GzAQwRC0GyAQwQC0G0AQwPC0G1AQwOC0G2AQwNC0G3AQwMC0G4AQwLC0G5AQwKC0G6AQwJC0G7AQwIC0HGAQwHC0G8AQwGC0G9AQwFC0G+AQwEC0G/AQwDC0HAAQwCC0HCAQwBC0HBAQshAwNAAkACQAJAAkACQAJAAkACQAJAIAICfwJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJ/AkACQAJAAkACQAJAAkACQAJAAkACQAJAAkAgAgJ/AkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACfwJAAkACfwJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkAC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iQEhAwykAgtBASABLQAAQd8ARw1nGiABQQFqIQEMXgtBigEhAyABIARGDaICIAIoAgAiACAEIAFraiEFIAEgAGtBAWohBgNAIAEtAAAgAEGMzwBqLQAARw1kIABBAUYN+gEgAEEBaiEAIAQgAUEBaiIBRw0ACyACIAU2AgAMogILQYsBIQMgASAERg2hAiACKAIAIgAgBCABa2ohBSABIABrQQJqIQYCQANAIAEtAAAgAEGOzwBqLQAARw1kIABBAkYNASAAQQFqIQAgBCABQQFqIgFHDQALIAIgBTYCAAyiAgsgAkEANgIAIAZBAWohAUECDGULQYwBIQMgASAERg2gAiACKAIAIgAgBCABa2ohBSABIABrQQFqIQYCQANAIAEtAAAgAEHwzwBqLQAARw1jIABBAUYNASAAQQFqIQAgBCABQQFqIgFHDQALIAIgBTYCAAyhAgsgAkEANgIAIAZBAWohAUEfDGQLQY0BIQMgASAERg2fAiACKAIAIgAgBCABa2ohBSABIABrQQFqIQYCQANAIAEtAAAgAEHyzwBqLQAARw1iIABBAUYNASAAQQFqIQAgBCABQQFqIgFHDQALIAIgBTYCAAygAgsgAkEANgIAIAZBAWohAUEJDGMLIAEgBEYEQEGOASEDDJ8CCwJAAkAgAS0AAEHJAGsOBwBiYmJiYgFiCyABQQFqIQFB+AAhAwyGAgsgAUEBaiEBQfkAIQMMhQILQY8BIQMgASAERg2dAiACKAIAIgAgBCABa2ohBSABIABrQQVqIQYCQANAIAEtAAAgAEGRzwBqLQAARw1gIABBBUYNASAAQQFqIQAgBCABQQFqIgFHDQALIAIgBTYCAAyeAgsgAkEANgIAIAZBAWohAUEYDGELQZABIQMgASAERg2cAiACKAIAIgAgBCABa2ohBSABIABrQQJqIQYCQANAIAEtAAAgAEGXzwBqLQAARw1fIABBAkYNASAAQQFqIQAgBCABQQFqIgFHDQALIAIgBTYCAAydAgsgAkEANgIAIAZBAWohAUEXDGALQZEBIQMgASAERg2bAiACKAIAIgAgBCABa2ohBSABIABrQQZqIQYCQANAIAEtAAAgAEGazwBqLQAARw1eIABBBkYNASAAQQFqIQAgBCABQQFqIgFHDQALIAIgBTYCAAycAgsgAkEANgIAIAZBAWohAUEV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JSIARQ0RIAJB5QA2AhwgAiABNgIUIAIgADYCDEEAIQMMtAELIAIoAgQhACACQQA2AgQgAiAAIAEQJSIARQ0gIAJB0wA2AhwgAiABNgIUIAIgADYCDEEAIQMMswELIAIoAgQhACACQQA2AgQgAiAAIAEQJSIARQ0iIAJB0gA2AhwgAiABNgIUIAIgADYCDEEAIQMMsgELIAIoAgQhACACQQA2AgQgAiAAIAEQJSIARQ0OIAJB5QA2AhwgAiABNgIUIAIgADYCDEEAIQMMsQELIAIoAgQhACACQQA2AgQgAiAAIAEQJSIARQ0dIAJB0wA2AhwgAiABNgIUIAIgADYCDEEAIQMMsAELIAIoAgQhACACQQA2AgQgAiAAIAEQJSIARQ0fIAJB0gA2AhwgAiABNgIUIAIgADYCDEEAIQMMrwELIABBP0cNASABQQFqCyEBQQUhAwyUAQtBACEDIAJBADYCHCACIAE2AhQgAkH9EjYCECACQQc2AgwMrAELIAJBADYCHCACIAE2AhQgAkHcCDYCECACQQc2AgxBACEDDKsBCyACKAIEIQAgAkEANgIEIAIgACABECUiAEUNByACQeUANgIcIAIgATYCFCACIAA2AgxBACEDDKoBCyACKAIEIQAgAkEANgIEIAIgACABECUiAEUNFiACQdMANgIcIAIgATYCFCACIAA2AgxBACEDDKkBCyACKAIEIQAgAkEANgIEIAIgACABECUiAEUNGCACQdIANgIcIAIgATYCFCACIAA2AgxBACEDDKgBCyACQQA2AhwgAiABNgIUIAJBxgo2AhAgAkEHNgIMQQAhAwynAQsgAigCBCEAIAJBADYCBCACIAAgARAlIgBFDQMgAkHlADYCHCACIAE2AhQgAiAANgIMQQAhAwymAQsgAigCBCEAIAJBADYCBCACIAAgARAlIgBFDRIgAkHTADYCHCACIAE2AhQgAiAANgIMQQAhAwylAQsgAigCBCEAIAJBADYCBCACIAAgARAlIgBFDRQgAkHSADYCHCACIAE2AhQgAiAANgIMQQAhAwykAQsgAigCBCEAIAJBADYCBCACIAAgARAlIgBFDQAgAkHlADYCHCACIAE2AhQgAiAANgIMQQAhAwyjAQtB1QAhAwyJAQsgAEEVRwRAIAJBADYCHCACIAE2AhQgAkG5DTYCECACQRo2AgxB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AkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAIABB5ABrDvQDY2IAAWFhYWFhYQIDBAVhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhBgcICQoLDA0OD2FhYWFhEGFhYWFhYWFhYWFhEWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYRITFBUWFxgZGhthYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2YTc4OTphYWFhYWFhYTthYWE8YWFhYT0+P2FhYWFhYWFhQGFhQWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYUJDREVGR0hJSktMTU5PUFFSU2FhYWFhYWFhVFVWV1hZWlthXF1hYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFeYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhX2BhC0HhJw8LQaQhDwtByywPC0H+MQ8LQcAkDwtBqyQPC0GNKA8LQeImDwtBgDAPC0G5Lw8LQdckDwtB7x8PC0HhHw8LQfofDwtB8iAPC0GoLw8LQa4yDwtBiDAPC0HsJw8LQYIiDwtBjh0PC0HQLg8LQcojDwtBxTIPC0HfHA8LQdIcDwtBxCAPC0HXIA8LQaIfDwtB7S4PC0GrMA8LQdQlDwtBzC4PC0H6Lg8LQfwrDwtB0jAPC0HxHQ8LQbsgDwtB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AAADAEGUCAsFBAAAAAUAQaQICwkGAAAABwAAAAgAQdwIC4otSW52YWxpZCBjaGFyIGluIHVybCBxdWVyeQBTcGFuIGNhbGxiYWNrIGVycm9yIGluIG9uX2JvZHkAQ29udGVudC1MZW5ndGggb3ZlcmZsb3cAQ2h1bmsgc2l6ZSBvdmVyZmxvdwBSZXNwb25zZSBvdmVyZmxvdwBJbnZhbGlkIG1ldGhvZCBmb3IgSFRUUC94LnggcmVxdWVzdABJbnZhbGlkIG1ldGhvZCBmb3IgUlRTUC94LnggcmVxdWVzdABFeHBlY3RlZCBTT1VSQ0UgbWV0aG9kIGZvciBJQ0UveC54IHJlcXVlc3QASW52YWxpZCBjaGFyIGluIHVybCBmcmFnbWVudCBzdGFydABFeHBlY3RlZCBkb3QAU3BhbiBjYWxsYmFjayBlcnJvciBpbiBvbl9zdGF0dXMASW52YWxpZCByZXNwb25zZSBzdGF0dXMASW52YWxpZCBjaGFyYWN0ZXIgaW4gY2h1bmsgZXh0ZW5zaW9ucwBVc2VyIGNhbGxiYWNrIGVycm9yAGBvbl9yZXNldGAgY2FsbGJhY2sgZXJyb3IAYG9uX2NodW5rX2hlYWRlcmAgY2FsbGJhY2sgZXJyb3IAYG9uX21lc3NhZ2VfYmVnaW5gIGNhbGxiYWNrIGVycm9yAGBvbl9jaHVua19leHRlbnNpb25fdmFsdWVgIGNhbGxiYWNrIGVycm9yAGBvbl9zdGF0dXNfY29tcGxldGVgIGNhbGxiYWNrIGVycm9yAGBvbl92ZXJzaW9uX2NvbXBsZXRlYCBjYWxsYmFjayBlcnJvcgBgb25fdXJsX2NvbXBsZXRlYCBjYWxsYmFjayBlcnJvcgBgb25fY2h1bmtfY29tcGxldGVgIGNhbGxiYWNrIGVycm9yAGBvbl9oZWFkZXJfdmFsdWVfY29tcGxldGVgIGNhbGxiYWNrIGVycm9yAGBvbl9tZXNzYWdlX2NvbXBsZXRlYCBjYWxsYmFjayBlcnJvcgBgb25fbWV0aG9kX2NvbXBsZXRlYCBjYWxsYmFjayBlcnJvcgBgb25faGVhZGVyX2ZpZWxkX2NvbXBsZXRlYCBjYWxsYmFjayBlcnJvcgBgb25fY2h1bmtfZXh0ZW5zaW9uX25hbWVgIGNhbGxiYWNrIGVycm9yAFVuZXhwZWN0ZWQgY2hhciBpbiB1cmwgc2VydmVyAEludmFsaWQgaGVhZGVyIHZhbHVlIGNoYXIASW52YWxpZCBoZWFkZXIgZmllbGQgY2hhcgBTcGFuIGNhbGxiYWNrIGVycm9yIGluIG9uX3ZlcnNpb24ASW52YWxpZCBtaW5vciB2ZXJzaW9uAEludmFsaWQgbWFqb3IgdmVyc2lvbgBFeHBlY3RlZCBzcGFjZSBhZnRlciB2ZXJzaW9uAEV4cGVjdGVkIENSTEYgYWZ0ZXIgdmVyc2lvbgBJbnZhbGlkIEhUVFAgdmVyc2lvbgBJbnZhbGlkIGhlYWRlciB0b2tlbgBTcGFuIGNhbGxiYWNrIGVycm9yIGluIG9uX3VybABJbnZhbGlkIGNoYXJhY3RlcnMgaW4gdXJsAFVuZXhwZWN0ZWQgc3RhcnQgY2hhciBpbiB1cmwARG91YmxlIEAgaW4gdXJsAEVtcHR5IENvbnRlbnQtTGVuZ3RoAEludmFsaWQgY2hhcmFjdGVyIGluIENvbnRlbnQtTGVuZ3RoAER1cGxpY2F0ZSBDb250ZW50LUxlbmd0aABJbnZhbGlkIGNoYXIgaW4gdXJsIHBhdGgAQ29udGVudC1MZW5ndGggY2FuJ3QgYmUgcHJlc2VudCB3aXRoIFRyYW5zZmVyLUVuY29kaW5nAEludmFsaWQgY2hhcmFjdGVyIGluIGNodW5rIHNpemUAU3BhbiBjYWxsYmFjayBlcnJvciBpbiBvbl9oZWFkZXJfdmFsdWUAU3BhbiBjYWxsYmFjayBlcnJvciBpbiBvbl9jaHVua19leHRlbnNpb25fdmFsdWUASW52YWxpZCBjaGFyYWN0ZXIgaW4gY2h1bmsgZXh0ZW5zaW9ucyB2YWx1ZQBNaXNzaW5nIGV4cGVjdGVkIExGIGFmdGVyIGhlYWRlciB2YWx1ZQBJbnZhbGlkIGBUcmFuc2Zlci1FbmNvZGluZ2AgaGVhZGVyIHZhbHVlAEludmFsaWQgY2hhcmFjdGVyIGluIGNodW5rIGV4dGVuc2lvbnMgcXVvdGUgdmFsdWUASW52YWxpZCBjaGFyYWN0ZXIgaW4gY2h1bmsgZXh0ZW5zaW9ucyBxdW90ZWQgdmFsdWUAUGF1c2VkIGJ5IG9uX2hlYWRlcnNfY29tcGxldGUASW52YWxpZCBFT0Ygc3RhdGUAb25fcmVzZXQgcGF1c2UAb25fY2h1bmtfaGVhZGVyIHBhdXNlAG9uX21lc3NhZ2VfYmVnaW4gcGF1c2UAb25fY2h1bmtfZXh0ZW5zaW9uX3ZhbHVlIHBhdXNlAG9uX3N0YXR1c19jb21wbGV0ZSBwYXVzZQBvbl92ZXJzaW9uX2NvbXBsZXRlIHBhdXNlAG9uX3VybF9jb21wbGV0ZSBwYXVzZQBvbl9jaHVua19jb21wbGV0ZSBwYXVzZQBvbl9oZWFkZXJfdmFsdWVfY29tcGxldGUgcGF1c2UAb25fbWVzc2FnZV9jb21wbGV0ZSBwYXVzZQBvbl9tZXRob2RfY29tcGxldGUgcGF1c2UAb25faGVhZGVyX2ZpZWxkX2NvbXBsZXRlIHBhdXNlAG9uX2NodW5rX2V4dGVuc2lvbl9uYW1lIHBhdXNlAFVuZXhwZWN0ZWQgc3BhY2UgYWZ0ZXIgc3RhcnQgbGluZQBTcGFuIGNhbGxiYWNrIGVycm9yIGluIG9uX2NodW5rX2V4dGVuc2lvbl9uYW1lAEludmFsaWQgY2hhcmFjdGVyIGluIGNodW5rIGV4dGVuc2lvbnMgbmFtZQBQYXVzZSBvbiBDT05ORUNUL1VwZ3JhZGUAUGF1c2Ugb24gUFJJL1VwZ3JhZGUARXhwZWN0ZWQgSFRUUC8yIENvbm5lY3Rpb24gUHJlZmFjZQBTcGFuIGNhbGxiYWNrIGVycm9yIGluIG9uX21ldGhvZABFeHBlY3RlZCBzcGFjZSBhZnRlciBtZXRob2QAU3BhbiBjYWxsYmFjayBlcnJvciBpbiBvbl9oZWFkZXJfZmllbGQAUGF1c2VkAEludmFsaWQgd29yZCBlbmNvdW50ZXJlZABJbnZhbGlkIG1ldGhvZCBlbmNvdW50ZXJlZABVbmV4cGVjdGVkIGNoYXIgaW4gdXJsIHNjaGVtYQBSZXF1ZXN0IGhhcyBpbnZhbGlkIGBUcmFuc2Zlci1FbmNvZGluZ2AAU1dJVENIX1BST1hZAFVTRV9QUk9YWQBNS0FDVElWSVRZAFVOUFJPQ0VTU0FCTEVfRU5USVRZAENPUFkATU9WRURfUEVSTUFORU5UTFkAVE9PX0VBUkxZAE5PVElGWQBGQUlMRURfREVQRU5ERU5DWQBCQURfR0FURVdBWQBQTEFZAFBVVABDSEVDS09VVABHQVRFV0FZX1RJTUVPVVQAUkVRVUVTVF9USU1FT1VUAE5FVFdPUktfQ09OTkVDVF9USU1FT1VUAENPTk5FQ1RJT05fVElNRU9VVABMT0dJTl9USU1FT1VUAE5FVFdPUktfUkVBRF9USU1FT1VUAFBPU1QATUlTRElSRUNURURfUkVRVUVTVABDTElFTlRfQ0xPU0VEX1JFUVVFU1QAQ0xJRU5UX0NMT1NFRF9MT0FEX0JBTEFOQ0VEX1JFUVVFU1QAQkFEX1JFUVVFU1QASFRUUF9SRVFVRVNUX1NFTlRfVE9fSFRUUFNfUE9SVABSRVBPUlQASU1fQV9URUFQT1QAUkVTRVRfQ09OVEVOVABOT19DT05URU5UAFBBUlRJQUxfQ09OVEVOVABIUEVfSU5WQUxJRF9DT05TVEFOVABIUEVfQ0JfUkVTRVQAR0VUAEhQRV9TVFJJQ1QAQ09ORkxJQ1QAVEVNUE9SQVJZX1JFRElSRUNUAFBFUk1BTkVOVF9SRURJUkVDVABDT05ORUNUAE1VTFRJX1NUQVRVUwBIUEVfSU5WQUxJRF9TVEFUVVMAVE9PX01BTllfUkVRVUVTVFMARUFSTFlfSElOVFMAVU5BVkFJTEFCTEVfRk9SX0xFR0FMX1JFQVNPTlMAT1BUSU9OUwBTV0lUQ0hJTkdfUFJPVE9DT0xTAFZBUklBTlRfQUxTT19ORUdPVElBVEVTAE1VTFRJUExFX0NIT0lDRVMASU5URVJOQUxfU0VSVkVSX0VSUk9SAFdFQl9TRVJWRVJfVU5LTk9XTl9FUlJPUgBSQUlMR1VOX0VSUk9SAElERU5USVRZX1BST1ZJREVSX0FVVEhFTlRJQ0FUSU9OX0VSUk9SAFNTTF9DRVJUSUZJQ0FURV9FUlJPUgBJTlZBTElEX1hfRk9SV0FSREVEX0ZPUgBTRVRfUEFSQU1FVEVSAEdFVF9QQVJBTUVURVIASFBFX1VTRVIAU0VFX09USEVSAEhQRV9DQl9DSFVOS19IRUFERVIATUtDQUxFTkRBUgBTRVRVUABXRUJfU0VSVkVSX0lTX0RPV04AVEVBUkRPV04ASFBFX0NMT1NFRF9DT05ORUNUSU9OAEhFVVJJU1RJQ19FWFBJUkFUSU9OAERJU0NPTk5FQ1RFRF9PUEVSQVRJT04ATk9OX0FVVEhPUklUQVRJVkVfSU5GT1JNQVRJT04ASFBFX0lOVkFMSURfVkVSU0lPTgBIUEVfQ0JfTUVTU0FHRV9CRUdJTgBTSVRFX0lTX0ZST1pFTgBIUEVfSU5WQUxJRF9IRUFERVJfVE9LRU4ASU5WQUxJRF9UT0tFTgBGT1JCSURERU4ARU5IQU5DRV9ZT1VSX0NBTE0ASFBFX0lOVkFMSURfVVJMAEJMT0NLRURfQllfUEFSRU5UQUxfQ09OVFJPTABNS0NPTABBQ0wASFBFX0lOVEVSTkFMAFJFUVVFU1RfSEVBREVSX0ZJRUxEU19UT09fTEFSR0VfVU5PRkZJQ0lBTABIUEVfT0sAVU5MSU5LAFVOTE9DSwBQUkkAUkVUUllfV0lUSABIUEVfSU5WQUxJRF9DT05URU5UX0xFTkdUSABIUEVfVU5FWFBFQ1RFRF9DT05URU5UX0xFTkdUSABGTFVTSABQUk9QUEFUQ0gATS1TRUFSQ0gAVVJJX1RPT19MT05HAFBST0NFU1NJTkcATUlTQ0VMTEFORU9VU19QRVJTSVNURU5UX1dBUk5JTkcATUlTQ0VMTEFORU9VU19XQVJOSU5HAEhQRV9JTlZBTElEX1RSQU5TRkVSX0VOQ09ESU5HAEV4cGVjdGVkIENSTEYASFBFX0lOVkFMSURfQ0hVTktfU0laRQBNT1ZFAENPTlRJTlVFAEhQRV9DQl9TVEFUVVNfQ09NUExFVEUASFBFX0NCX0hFQURFUlNfQ09NUExFVEUASFBFX0NCX1ZFUlNJT05fQ09NUExFVEUASFBFX0NCX1VSTF9DT01QTEVURQBIUEVfQ0JfQ0hVTktfQ09NUExFVEUASFBFX0NCX0hFQURFUl9WQUxVRV9DT01QTEVURQBIUEVfQ0JfQ0hVTktfRVhURU5TSU9OX1ZBTFVFX0NPTVBMRVRFAEhQRV9DQl9DSFVOS19FWFRFTlNJT05fTkFNRV9DT01QTEVURQBIUEVfQ0JfTUVTU0FHRV9DT01QTEVURQBIUEVfQ0JfTUVUSE9EX0NPTVBMRVRFAEhQRV9DQl9IRUFERVJfRklFTERfQ09NUExFVEUAREVMRVRFAEhQRV9JTlZBTElEX0VPRl9TVEFURQBJTlZBTElEX1NTTF9DRVJUSUZJQ0FURQBQQVVTRQBOT19SRVNQT05TRQBVTlNVUFBPUlRFRF9NRURJQV9UWVBFAEdPTkUATk9UX0FDQ0VQVEFCTEUAU0VSVklDRV9VTkFWQUlMQUJMRQBSQU5HRV9OT1RfU0FUSVNGSUFCTEUAT1JJR0lOX0lTX1VOUkVBQ0hBQkxFAFJFU1BPTlNFX0lTX1NUQUxFAFBVUkdFAE1FUkdFAFJFUVVFU1RfSEVBREVSX0ZJRUxEU19UT09fTEFSR0UAUkVRVUVTVF9IRUFERVJfVE9PX0xBUkdFAFBBWUxPQURfVE9PX0xBUkdFAElOU1VGRklDSUVOVF9TVE9SQUdFAEhQRV9QQVVTRURfVVBHUkFERQBIUEVfUEFVU0VEX0gyX1VQR1JBREUAU09VUkNFAEFOTk9VTkNFAFRSQUNFAEhQRV9VTkVYUEVDVEVEX1NQQUNFAERFU0NSSUJFAFVOU1VCU0NSSUJFAFJFQ09SRABIUEVfSU5WQUxJRF9NRVRIT0QATk9UX0ZPVU5EAFBST1BGSU5EAFVOQklORABSRUJJTkQAVU5BVVRIT1JJWkVEAE1FVEhPRF9OT1RfQUxMT1dFRABIVFRQX1ZFUlNJT05fTk9UX1NVUFBPUlRFRABBTFJFQURZX1JFUE9SVEVEAEFDQ0VQVEVEAE5PVF9JTVBMRU1FTlRFRABMT09QX0RFVEVDVEVEAEhQRV9DUl9FWFBFQ1RFRABIUEVfTEZfRVhQRUNURUQAQ1JFQVRFRABJTV9VU0VEAEhQRV9QQVVTRUQAVElNRU9VVF9PQ0NVUkVEAFBBWU1FTlRfUkVRVUlSRUQAUFJFQ09ORElUSU9OX1JFUVVJUkVEAFBST1hZX0FVVEhFTlRJQ0FUSU9OX1JFUVVJUkVEAE5FVFdPUktfQVVUSEVOVElDQVRJT05fUkVRVUlSRUQATEVOR1RIX1JFUVVJUkVEAFNTTF9DRVJUSUZJQ0FURV9SRVFVSVJFRABVUEdSQURFX1JFUVVJUkVEAFBBR0VfRVhQSVJFRABQUkVDT05ESVRJT05fRkFJTEVEAEVYUEVDVEFUSU9OX0ZBSUxFRABSRVZBTElEQVRJT05fRkFJTEVEAFNTTF9IQU5EU0hBS0VfRkFJTEVEAExPQ0tFRABUUkFOU0ZPUk1BVElPTl9BUFBMSUVEAE5PVF9NT0RJRklFRABOT1RfRVhURU5ERUQAQkFORFdJRFRIX0xJTUlUX0VYQ0VFREVEAFNJVEVfSVNfT1ZFUkxPQURFRABIRUFEAEV4cGVjdGVkIEhUVFAvAABeEwAAJhMAADAQAADwFwAAnRMAABUSAAA5FwAA8BIAAAoQAAB1EgAArRIAAIITAABPFAAAfxAAAKAVAAAjFAAAiRIAAIsUAABNFQAA1BEAAM8UAAAQGAAAyRYAANwWAADBEQAA4BcAALsUAAB0FAAAfBUAAOUUAAAIFwAAHxAAAGUVAACjFAAAKBUAAAIVAACZFQAALBAAAIsZAABPDwAA1A4AAGoQAADOEAAAAhcAAIkOAABuEwAAHBMAAGYUAABWFwAAwRMAAM0TAABsEwAAaBcAAGYXAABfFwAAIhMAAM4PAABpDgAA2A4AAGMWAADLEwAAqg4AACgXAAAmFwAAxRMAAF0WAADoEQAAZxMAAGUTAADyFgAAcxMAAB0XAAD5FgAA8xEAAM8OAADOFQAADBIAALMRAAClEQAAYRAAADIXAAC7EwBB+TULAQEAQZA2C+ABAQECAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAQf03CwEBAEGROAteAgMCAgICAgAAAgIAAgIAAgICAgICAgICAgAEAAAAAAACAgICAgICAgICAgICAgICAgICAgICAgICAgAAAAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAAIAAgBB/TkLAQEAQZE6C14CAAICAgICAAACAgACAgACAgICAgICAgICAAMABAAAAAICAgICAgICAgICAgICAgICAgICAgICAgICAAAAAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAAgACAEHwOwsNbG9zZWVlcC1hbGl2ZQBBiTwLAQEAQaA8C+ABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAQYk+CwEBAEGgPgvnAQEBAQEBAQEBAQEBAQIBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBY2h1bmtlZABBsMAAC18BAQABAQEBAQAAAQEAAQEAAQEBAQEBAQEBAQAAAAAAAAABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQAAAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAEAAQBBkMIACyFlY3Rpb25lbnQtbGVuZ3Rob25yb3h5LWNvbm5lY3Rpb24AQcDCAAstcmFuc2Zlci1lbmNvZGluZ3BncmFkZQ0KDQoNClNNDQoNClRUUC9DRS9UU1AvAEH5wgALBQECAAEDAEGQwwAL4AEEAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQBB+cQACwUBAgABAwBBkMUAC+ABBAEBBQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAQfnGAAsEAQAAAQBBkccAC98BAQEAAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQBB+sgACwQBAAACAEGQyQALXwMEAAAEBAQEBAQEBAQEBAUEBAQEBAQEBAQEBAQABAAGBwQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAEAAQABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQAAAAEAEH6ygALBAEAAAEAQZDLAAsBAQBBqssAC0ECAAAAAAAAAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMAAAAAAAADAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwBB+swACwQBAAABAEGQzQALAQEAQZrNAAsGAgAAAAACAEGxzQALOgMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAAAAAAAAAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMAQfDOAAuWAU5PVU5DRUVDS09VVE5FQ1RFVEVDUklCRUxVU0hFVEVBRFNFQVJDSFJHRUNUSVZJVFlMRU5EQVJWRU9USUZZUFRJT05TQ0hTRUFZU1RBVENIR0VPUkRJUkVDVE9SVFJDSFBBUkFNRVRFUlVSQ0VCU0NSSUJFQVJET1dOQUNFSU5ETktDS1VCU0NSSUJFSFRUUC9BRFRQLw==", "base64"), wt;
}
var mt, vs;
function KA() {
  if (vs) return mt;
  vs = 1;
  const e = (
    /** @type {const} */
    ["GET", "HEAD", "POST"]
  ), r = new Set(e), t = (
    /** @type {const} */
    [101, 204, 205, 304]
  ), o = (
    /** @type {const} */
    [301, 302, 303, 307, 308]
  ), A = new Set(o), n = (
    /** @type {const} */
    [
      "1",
      "7",
      "9",
      "11",
      "13",
      "15",
      "17",
      "19",
      "20",
      "21",
      "22",
      "23",
      "25",
      "37",
      "42",
      "43",
      "53",
      "69",
      "77",
      "79",
      "87",
      "95",
      "101",
      "102",
      "103",
      "104",
      "109",
      "110",
      "111",
      "113",
      "115",
      "117",
      "119",
      "123",
      "135",
      "137",
      "139",
      "143",
      "161",
      "179",
      "389",
      "427",
      "465",
      "512",
      "513",
      "514",
      "515",
      "526",
      "530",
      "531",
      "532",
      "540",
      "548",
      "554",
      "556",
      "563",
      "587",
      "601",
      "636",
      "989",
      "990",
      "993",
      "995",
      "1719",
      "1720",
      "1723",
      "2049",
      "3659",
      "4045",
      "4190",
      "5060",
      "5061",
      "6000",
      "6566",
      "6665",
      "6666",
      "6667",
      "6668",
      "6669",
      "6679",
      "6697",
      "10080"
    ]
  ), c = new Set(n), g = (
    /** @type {const} */
    [
      "",
      "no-referrer",
      "no-referrer-when-downgrade",
      "same-origin",
      "origin",
      "strict-origin",
      "origin-when-cross-origin",
      "strict-origin-when-cross-origin",
      "unsafe-url"
    ]
  ), Q = new Set(g), B = (
    /** @type {const} */
    ["follow", "manual", "error"]
  ), i = (
    /** @type {const} */
    ["GET", "HEAD", "OPTIONS", "TRACE"]
  ), a = new Set(i), h = (
    /** @type {const} */
    ["navigate", "same-origin", "no-cors", "cors"]
  ), u = (
    /** @type {const} */
    ["omit", "same-origin", "include"]
  ), C = (
    /** @type {const} */
    [
      "default",
      "no-store",
      "reload",
      "no-cache",
      "force-cache",
      "only-if-cached"
    ]
  ), w = (
    /** @type {const} */
    [
      "content-encoding",
      "content-language",
      "content-location",
      "content-type",
      // See https://github.com/nodejs/undici/issues/2021
      // 'Content-Length' is a forbidden header name, which is typically
      // removed in the Headers implementation. However, undici doesn't
      // filter out headers, so we add it here.
      "content-length"
    ]
  ), D = (
    /** @type {const} */
    [
      "half"
    ]
  ), b = (
    /** @type {const} */
    ["CONNECT", "TRACE", "TRACK"]
  ), U = new Set(b), G = (
    /** @type {const} */
    [
      "audio",
      "audioworklet",
      "font",
      "image",
      "manifest",
      "paintworklet",
      "script",
      "style",
      "track",
      "video",
      "xslt",
      ""
    ]
  ), M = new Set(G);
  return mt = {
    subresource: G,
    forbiddenMethods: b,
    requestBodyHeader: w,
    referrerPolicy: g,
    requestRedirect: B,
    requestMode: h,
    requestCredentials: u,
    requestCache: C,
    redirectStatus: o,
    corsSafeListedMethods: e,
    nullBodyStatus: t,
    safeMethods: i,
    badPorts: n,
    requestDuplex: D,
    subresourceSet: M,
    badPortsSet: c,
    redirectStatusSet: A,
    corsSafeListedMethodsSet: r,
    safeMethodsSet: a,
    forbiddenMethodsSet: U,
    referrerPolicySet: Q
  }, mt;
}
var yt, Ys;
function Wn() {
  if (Ys) return yt;
  Ys = 1;
  const e = /* @__PURE__ */ Symbol.for("undici.globalOrigin.1");
  function r() {
    return globalThis[e];
  }
  function t(o) {
    if (o === void 0) {
      Object.defineProperty(globalThis, e, {
        value: void 0,
        writable: !0,
        enumerable: !1,
        configurable: !1
      });
      return;
    }
    const A = new URL(o);
    if (A.protocol !== "http:" && A.protocol !== "https:")
      throw new TypeError(`Only http & https urls are allowed, received ${A.protocol}`);
    Object.defineProperty(globalThis, e, {
      value: A,
      writable: !0,
      enumerable: !1,
      configurable: !1
    });
  }
  return yt = {
    getGlobalOrigin: r,
    setGlobalOrigin: t
  }, yt;
}
var Dt, Js;
function eA() {
  if (Js) return Dt;
  Js = 1;
  const e = He, r = new TextEncoder(), t = /^[!#$%&'*+\-.^_|~A-Za-z0-9]+$/, o = /[\u000A\u000D\u0009\u0020]/, A = /[\u0009\u000A\u000C\u000D\u0020]/g, n = /^[\u0009\u0020-\u007E\u0080-\u00FF]+$/;
  function c(s) {
    e(s.protocol === "data:");
    let E = g(s, !0);
    E = E.slice(5);
    const f = { position: 0 };
    let I = B(
      ",",
      E,
      f
    );
    const m = I.length;
    if (I = N(I, !0, !0), f.position >= E.length)
      return "failure";
    f.position++;
    const y = E.slice(m + 1);
    let S = i(y);
    if (/;(\u0020){0,}base64$/i.test(I)) {
      const L = l(S);
      if (S = w(L), S === "failure")
        return "failure";
      I = I.slice(0, -6), I = I.replace(/(\u0020)+$/, ""), I = I.slice(0, -1);
    }
    I.startsWith(";") && (I = "text/plain" + I);
    let T = C(I);
    return T === "failure" && (T = C("text/plain;charset=US-ASCII")), { mimeType: T, body: S };
  }
  function g(s, E = !1) {
    if (!E)
      return s.href;
    const f = s.href, I = s.hash.length, m = I === 0 ? f : f.substring(0, f.length - I);
    return !I && f.endsWith("#") ? m.slice(0, -1) : m;
  }
  function Q(s, E, f) {
    let I = "";
    for (; f.position < E.length && s(E[f.position]); )
      I += E[f.position], f.position++;
    return I;
  }
  function B(s, E, f) {
    const I = E.indexOf(s, f.position), m = f.position;
    return I === -1 ? (f.position = E.length, E.slice(m)) : (f.position = I, E.slice(m, f.position));
  }
  function i(s) {
    const E = r.encode(s);
    return u(E);
  }
  function a(s) {
    return s >= 48 && s <= 57 || s >= 65 && s <= 70 || s >= 97 && s <= 102;
  }
  function h(s) {
    return (
      // 0-9
      s >= 48 && s <= 57 ? s - 48 : (s & 223) - 55
    );
  }
  function u(s) {
    const E = s.length, f = new Uint8Array(E);
    let I = 0;
    for (let m = 0; m < E; ++m) {
      const y = s[m];
      y !== 37 ? f[I++] = y : y === 37 && !(a(s[m + 1]) && a(s[m + 2])) ? f[I++] = 37 : (f[I++] = h(s[m + 1]) << 4 | h(s[m + 2]), m += 2);
    }
    return E === I ? f : f.subarray(0, I);
  }
  function C(s) {
    s = G(s, !0, !0);
    const E = { position: 0 }, f = B(
      "/",
      s,
      E
    );
    if (f.length === 0 || !t.test(f) || E.position > s.length)
      return "failure";
    E.position++;
    let I = B(
      ";",
      s,
      E
    );
    if (I = G(I, !1, !0), I.length === 0 || !t.test(I))
      return "failure";
    const m = f.toLowerCase(), y = I.toLowerCase(), S = {
      type: m,
      subtype: y,
      /** @type {Map<string, string>} */
      parameters: /* @__PURE__ */ new Map(),
      // https://mimesniff.spec.whatwg.org/#mime-type-essence
      essence: `${m}/${y}`
    };
    for (; E.position < s.length; ) {
      E.position++, Q(
        // https://fetch.spec.whatwg.org/#http-whitespace
        (v) => o.test(v),
        s,
        E
      );
      let T = Q(
        (v) => v !== ";" && v !== "=",
        s,
        E
      );
      if (T = T.toLowerCase(), E.position < s.length) {
        if (s[E.position] === ";")
          continue;
        E.position++;
      }
      if (E.position > s.length)
        break;
      let L = null;
      if (s[E.position] === '"')
        L = D(s, E, !0), B(
          ";",
          s,
          E
        );
      else if (L = B(
        ";",
        s,
        E
      ), L = G(L, !1, !0), L.length === 0)
        continue;
      T.length !== 0 && t.test(T) && (L.length === 0 || n.test(L)) && !S.parameters.has(T) && S.parameters.set(T, L);
    }
    return S;
  }
  function w(s) {
    s = s.replace(A, "");
    let E = s.length;
    if (E % 4 === 0 && s.charCodeAt(E - 1) === 61 && (--E, s.charCodeAt(E - 1) === 61 && --E), E % 4 === 1 || /[^+/0-9A-Za-z]/.test(s.length === E ? s : s.substring(0, E)))
      return "failure";
    const f = Buffer.from(s, "base64");
    return new Uint8Array(f.buffer, f.byteOffset, f.byteLength);
  }
  function D(s, E, f) {
    const I = E.position;
    let m = "";
    for (e(s[E.position] === '"'), E.position++; m += Q(
      (S) => S !== '"' && S !== "\\",
      s,
      E
    ), !(E.position >= s.length); ) {
      const y = s[E.position];
      if (E.position++, y === "\\") {
        if (E.position >= s.length) {
          m += "\\";
          break;
        }
        m += s[E.position], E.position++;
      } else {
        e(y === '"');
        break;
      }
    }
    return f ? m : s.slice(I, E.position);
  }
  function b(s) {
    e(s !== "failure");
    const { parameters: E, essence: f } = s;
    let I = f;
    for (let [m, y] of E.entries())
      I += ";", I += m, I += "=", t.test(y) || (y = y.replace(/(\\|")/g, "\\$1"), y = '"' + y, y += '"'), I += y;
    return I;
  }
  function U(s) {
    return s === 13 || s === 10 || s === 9 || s === 32;
  }
  function G(s, E = !0, f = !0) {
    return d(s, E, f, U);
  }
  function M(s) {
    return s === 13 || s === 10 || s === 9 || s === 12 || s === 32;
  }
  function N(s, E = !0, f = !0) {
    return d(s, E, f, M);
  }
  function d(s, E, f, I) {
    let m = 0, y = s.length - 1;
    if (E)
      for (; m < s.length && I(s.charCodeAt(m)); ) m++;
    if (f)
      for (; y > 0 && I(s.charCodeAt(y)); ) y--;
    return m === 0 && y === s.length - 1 ? s : s.slice(m, y + 1);
  }
  function l(s) {
    const E = s.length;
    if (65535 > E)
      return String.fromCharCode.apply(null, s);
    let f = "", I = 0, m = 65535;
    for (; I < E; )
      I + m > E && (m = E - I), f += String.fromCharCode.apply(null, s.subarray(I, I += m));
    return f;
  }
  function p(s) {
    switch (s.essence) {
      case "application/ecmascript":
      case "application/javascript":
      case "application/x-ecmascript":
      case "application/x-javascript":
      case "text/ecmascript":
      case "text/javascript":
      case "text/javascript1.0":
      case "text/javascript1.1":
      case "text/javascript1.2":
      case "text/javascript1.3":
      case "text/javascript1.4":
      case "text/javascript1.5":
      case "text/jscript":
      case "text/livescript":
      case "text/x-ecmascript":
      case "text/x-javascript":
        return "text/javascript";
      case "application/json":
      case "text/json":
        return "application/json";
      case "image/svg+xml":
        return "image/svg+xml";
      case "text/xml":
      case "application/xml":
        return "application/xml";
    }
    return s.subtype.endsWith("+json") ? "application/json" : s.subtype.endsWith("+xml") ? "application/xml" : "";
  }
  return Dt = {
    dataURLProcessor: c,
    URLSerializer: g,
    collectASequenceOfCodePoints: Q,
    collectASequenceOfCodePointsFast: B,
    stringPercentDecode: i,
    parseMIMEType: C,
    collectAnHTTPQuotedString: D,
    serializeAMimeType: b,
    removeChars: d,
    removeHTTPWhitespace: G,
    minimizeSupportedMimeType: p,
    HTTP_TOKEN_CODEPOINTS: t,
    isomorphicDecode: l
  }, Dt;
}
var Rt, Hs;
function Xe() {
  if (Hs) return Rt;
  Hs = 1;
  const { types: e, inspect: r } = $e, { markAsUncloneable: t } = Pn, { toUSVString: o } = Ue(), A = {};
  return A.converters = {}, A.util = {}, A.errors = {}, A.errors.exception = function(n) {
    return new TypeError(`${n.header}: ${n.message}`);
  }, A.errors.conversionFailed = function(n) {
    const c = n.types.length === 1 ? "" : " one of", g = `${n.argument} could not be converted to${c}: ${n.types.join(", ")}.`;
    return A.errors.exception({
      header: n.prefix,
      message: g
    });
  }, A.errors.invalidArgument = function(n) {
    return A.errors.exception({
      header: n.prefix,
      message: `"${n.value}" is an invalid ${n.type}.`
    });
  }, A.brandCheck = function(n, c, g) {
    if (g?.strict !== !1) {
      if (!(n instanceof c)) {
        const Q = new TypeError("Illegal invocation");
        throw Q.code = "ERR_INVALID_THIS", Q;
      }
    } else if (n?.[Symbol.toStringTag] !== c.prototype[Symbol.toStringTag]) {
      const Q = new TypeError("Illegal invocation");
      throw Q.code = "ERR_INVALID_THIS", Q;
    }
  }, A.argumentLengthCheck = function({ length: n }, c, g) {
    if (n < c)
      throw A.errors.exception({
        message: `${c} argument${c !== 1 ? "s" : ""} required, but${n ? " only" : ""} ${n} found.`,
        header: g
      });
  }, A.illegalConstructor = function() {
    throw A.errors.exception({
      header: "TypeError",
      message: "Illegal constructor"
    });
  }, A.util.Type = function(n) {
    switch (typeof n) {
      case "undefined":
        return "Undefined";
      case "boolean":
        return "Boolean";
      case "string":
        return "String";
      case "symbol":
        return "Symbol";
      case "number":
        return "Number";
      case "bigint":
        return "BigInt";
      case "function":
      case "object":
        return n === null ? "Null" : "Object";
    }
  }, A.util.markAsUncloneable = t || (() => {
  }), A.util.ConvertToInt = function(n, c, g, Q) {
    let B, i;
    c === 64 ? (B = Math.pow(2, 53) - 1, g === "unsigned" ? i = 0 : i = Math.pow(-2, 53) + 1) : g === "unsigned" ? (i = 0, B = Math.pow(2, c) - 1) : (i = Math.pow(-2, c) - 1, B = Math.pow(2, c - 1) - 1);
    let a = Number(n);
    if (a === 0 && (a = 0), Q?.enforceRange === !0) {
      if (Number.isNaN(a) || a === Number.POSITIVE_INFINITY || a === Number.NEGATIVE_INFINITY)
        throw A.errors.exception({
          header: "Integer conversion",
          message: `Could not convert ${A.util.Stringify(n)} to an integer.`
        });
      if (a = A.util.IntegerPart(a), a < i || a > B)
        throw A.errors.exception({
          header: "Integer conversion",
          message: `Value must be between ${i}-${B}, got ${a}.`
        });
      return a;
    }
    return !Number.isNaN(a) && Q?.clamp === !0 ? (a = Math.min(Math.max(a, i), B), Math.floor(a) % 2 === 0 ? a = Math.floor(a) : a = Math.ceil(a), a) : Number.isNaN(a) || a === 0 && Object.is(0, a) || a === Number.POSITIVE_INFINITY || a === Number.NEGATIVE_INFINITY ? 0 : (a = A.util.IntegerPart(a), a = a % Math.pow(2, c), g === "signed" && a >= Math.pow(2, c) - 1 ? a - Math.pow(2, c) : a);
  }, A.util.IntegerPart = function(n) {
    const c = Math.floor(Math.abs(n));
    return n < 0 ? -1 * c : c;
  }, A.util.Stringify = function(n) {
    switch (A.util.Type(n)) {
      case "Symbol":
        return `Symbol(${n.description})`;
      case "Object":
        return r(n);
      case "String":
        return `"${n}"`;
      default:
        return `${n}`;
    }
  }, A.sequenceConverter = function(n) {
    return (c, g, Q, B) => {
      if (A.util.Type(c) !== "Object")
        throw A.errors.exception({
          header: g,
          message: `${Q} (${A.util.Stringify(c)}) is not iterable.`
        });
      const i = typeof B == "function" ? B() : c?.[Symbol.iterator]?.(), a = [];
      let h = 0;
      if (i === void 0 || typeof i.next != "function")
        throw A.errors.exception({
          header: g,
          message: `${Q} is not iterable.`
        });
      for (; ; ) {
        const { done: u, value: C } = i.next();
        if (u)
          break;
        a.push(n(C, g, `${Q}[${h++}]`));
      }
      return a;
    };
  }, A.recordConverter = function(n, c) {
    return (g, Q, B) => {
      if (A.util.Type(g) !== "Object")
        throw A.errors.exception({
          header: Q,
          message: `${B} ("${A.util.Type(g)}") is not an Object.`
        });
      const i = {};
      if (!e.isProxy(g)) {
        const h = [...Object.getOwnPropertyNames(g), ...Object.getOwnPropertySymbols(g)];
        for (const u of h) {
          const C = n(u, Q, B), w = c(g[u], Q, B);
          i[C] = w;
        }
        return i;
      }
      const a = Reflect.ownKeys(g);
      for (const h of a)
        if (Reflect.getOwnPropertyDescriptor(g, h)?.enumerable) {
          const C = n(h, Q, B), w = c(g[h], Q, B);
          i[C] = w;
        }
      return i;
    };
  }, A.interfaceConverter = function(n) {
    return (c, g, Q, B) => {
      if (B?.strict !== !1 && !(c instanceof n))
        throw A.errors.exception({
          header: g,
          message: `Expected ${Q} ("${A.util.Stringify(c)}") to be an instance of ${n.name}.`
        });
      return c;
    };
  }, A.dictionaryConverter = function(n) {
    return (c, g, Q) => {
      const B = A.util.Type(c), i = {};
      if (B === "Null" || B === "Undefined")
        return i;
      if (B !== "Object")
        throw A.errors.exception({
          header: g,
          message: `Expected ${c} to be one of: Null, Undefined, Object.`
        });
      for (const a of n) {
        const { key: h, defaultValue: u, required: C, converter: w } = a;
        if (C === !0 && !Object.hasOwn(c, h))
          throw A.errors.exception({
            header: g,
            message: `Missing required key "${h}".`
          });
        let D = c[h];
        const b = Object.hasOwn(a, "defaultValue");
        if (b && D !== null && (D ??= u()), C || b || D !== void 0) {
          if (D = w(D, g, `${Q}.${h}`), a.allowedValues && !a.allowedValues.includes(D))
            throw A.errors.exception({
              header: g,
              message: `${D} is not an accepted type. Expected one of ${a.allowedValues.join(", ")}.`
            });
          i[h] = D;
        }
      }
      return i;
    };
  }, A.nullableConverter = function(n) {
    return (c, g, Q) => c === null ? c : n(c, g, Q);
  }, A.converters.DOMString = function(n, c, g, Q) {
    if (n === null && Q?.legacyNullToEmptyString)
      return "";
    if (typeof n == "symbol")
      throw A.errors.exception({
        header: c,
        message: `${g} is a symbol, which cannot be converted to a DOMString.`
      });
    return String(n);
  }, A.converters.ByteString = function(n, c, g) {
    const Q = A.converters.DOMString(n, c, g);
    for (let B = 0; B < Q.length; B++)
      if (Q.charCodeAt(B) > 255)
        throw new TypeError(
          `Cannot convert argument to a ByteString because the character at index ${B} has a value of ${Q.charCodeAt(B)} which is greater than 255.`
        );
    return Q;
  }, A.converters.USVString = o, A.converters.boolean = function(n) {
    return !!n;
  }, A.converters.any = function(n) {
    return n;
  }, A.converters["long long"] = function(n, c, g) {
    return A.util.ConvertToInt(n, 64, "signed", void 0, c, g);
  }, A.converters["unsigned long long"] = function(n, c, g) {
    return A.util.ConvertToInt(n, 64, "unsigned", void 0, c, g);
  }, A.converters["unsigned long"] = function(n, c, g) {
    return A.util.ConvertToInt(n, 32, "unsigned", void 0, c, g);
  }, A.converters["unsigned short"] = function(n, c, g, Q) {
    return A.util.ConvertToInt(n, 16, "unsigned", Q, c, g);
  }, A.converters.ArrayBuffer = function(n, c, g, Q) {
    if (A.util.Type(n) !== "Object" || !e.isAnyArrayBuffer(n))
      throw A.errors.conversionFailed({
        prefix: c,
        argument: `${g} ("${A.util.Stringify(n)}")`,
        types: ["ArrayBuffer"]
      });
    if (Q?.allowShared === !1 && e.isSharedArrayBuffer(n))
      throw A.errors.exception({
        header: "ArrayBuffer",
        message: "SharedArrayBuffer is not allowed."
      });
    if (n.resizable || n.growable)
      throw A.errors.exception({
        header: "ArrayBuffer",
        message: "Received a resizable ArrayBuffer."
      });
    return n;
  }, A.converters.TypedArray = function(n, c, g, Q, B) {
    if (A.util.Type(n) !== "Object" || !e.isTypedArray(n) || n.constructor.name !== c.name)
      throw A.errors.conversionFailed({
        prefix: g,
        argument: `${Q} ("${A.util.Stringify(n)}")`,
        types: [c.name]
      });
    if (B?.allowShared === !1 && e.isSharedArrayBuffer(n.buffer))
      throw A.errors.exception({
        header: "ArrayBuffer",
        message: "SharedArrayBuffer is not allowed."
      });
    if (n.buffer.resizable || n.buffer.growable)
      throw A.errors.exception({
        header: "ArrayBuffer",
        message: "Received a resizable ArrayBuffer."
      });
    return n;
  }, A.converters.DataView = function(n, c, g, Q) {
    if (A.util.Type(n) !== "Object" || !e.isDataView(n))
      throw A.errors.exception({
        header: c,
        message: `${g} is not a DataView.`
      });
    if (Q?.allowShared === !1 && e.isSharedArrayBuffer(n.buffer))
      throw A.errors.exception({
        header: "ArrayBuffer",
        message: "SharedArrayBuffer is not allowed."
      });
    if (n.buffer.resizable || n.buffer.growable)
      throw A.errors.exception({
        header: "ArrayBuffer",
        message: "Received a resizable ArrayBuffer."
      });
    return n;
  }, A.converters.BufferSource = function(n, c, g, Q) {
    if (e.isAnyArrayBuffer(n))
      return A.converters.ArrayBuffer(n, c, g, { ...Q, allowShared: !1 });
    if (e.isTypedArray(n))
      return A.converters.TypedArray(n, n.constructor, c, g, { ...Q, allowShared: !1 });
    if (e.isDataView(n))
      return A.converters.DataView(n, c, g, { ...Q, allowShared: !1 });
    throw A.errors.conversionFailed({
      prefix: c,
      argument: `${g} ("${A.util.Stringify(n)}")`,
      types: ["BufferSource"]
    });
  }, A.converters["sequence<ByteString>"] = A.sequenceConverter(
    A.converters.ByteString
  ), A.converters["sequence<sequence<ByteString>>"] = A.sequenceConverter(
    A.converters["sequence<ByteString>"]
  ), A.converters["record<ByteString, ByteString>"] = A.recordConverter(
    A.converters.ByteString,
    A.converters.ByteString
  ), Rt = {
    webidl: A
  }, Rt;
}
var kt, Vs;
function rA() {
  if (Vs) return kt;
  Vs = 1;
  const { Transform: e } = tA, r = ts, { redirectStatusSet: t, referrerPolicySet: o, badPortsSet: A } = KA(), { getGlobalOrigin: n } = Wn(), { collectASequenceOfCodePoints: c, collectAnHTTPQuotedString: g, removeChars: Q, parseMIMEType: B } = eA(), { performance: i } = Gi, { isBlobLike: a, ReadableStreamFrom: h, isValidHTTPToken: u, normalizedMethodRecordsBase: C } = Ue(), w = He, { isUint8Array: D } = Vn, { webidl: b } = Xe();
  let U = [], G;
  try {
    G = require("node:crypto");
    const F = ["sha256", "sha384", "sha512"];
    U = G.getHashes().filter((O) => F.includes(O));
  } catch {
  }
  function M(F) {
    const O = F.urlList, k = O.length;
    return k === 0 ? null : O[k - 1].toString();
  }
  function N(F, O) {
    if (!t.has(F.status))
      return null;
    let k = F.headersList.get("location", !0);
    return k !== null && m(k) && (d(k) || (k = l(k)), k = new URL(k, M(F))), k && !k.hash && (k.hash = O), k;
  }
  function d(F) {
    for (let O = 0; O < F.length; ++O) {
      const k = F.charCodeAt(O);
      if (k > 126 || // Non-US-ASCII + DEL
      k < 32)
        return !1;
    }
    return !0;
  }
  function l(F) {
    return Buffer.from(F, "binary").toString("utf8");
  }
  function p(F) {
    return F.urlList[F.urlList.length - 1];
  }
  function s(F) {
    const O = p(F);
    return Ie(O) && A.has(O.port) ? "blocked" : "allowed";
  }
  function E(F) {
    return F instanceof Error || F?.constructor?.name === "Error" || F?.constructor?.name === "DOMException";
  }
  function f(F) {
    for (let O = 0; O < F.length; ++O) {
      const k = F.charCodeAt(O);
      if (!(k === 9 || // HTAB
      k >= 32 && k <= 126 || // SP / VCHAR
      k >= 128 && k <= 255))
        return !1;
    }
    return !0;
  }
  const I = u;
  function m(F) {
    return (F[0] === "	" || F[0] === " " || F[F.length - 1] === "	" || F[F.length - 1] === " " || F.includes(`
`) || F.includes("\r") || F.includes("\0")) === !1;
  }
  function y(F, O) {
    const { headersList: k } = O, V = (k.get("referrer-policy", !0) ?? "").split(",");
    let H = "";
    if (V.length > 0)
      for (let x = V.length; x !== 0; x--) {
        const te = V[x - 1].trim();
        if (o.has(te)) {
          H = te;
          break;
        }
      }
    H !== "" && (F.referrerPolicy = H);
  }
  function S() {
    return "allowed";
  }
  function T() {
    return "success";
  }
  function L() {
    return "success";
  }
  function v(F) {
    let O = null;
    O = F.mode, F.headersList.set("sec-fetch-mode", O, !0);
  }
  function $(F) {
    let O = F.origin;
    if (!(O === "client" || O === void 0)) {
      if (F.responseTainting === "cors" || F.mode === "websocket")
        F.headersList.append("origin", O, !0);
      else if (F.method !== "GET" && F.method !== "HEAD") {
        switch (F.referrerPolicy) {
          case "no-referrer":
            O = null;
            break;
          case "no-referrer-when-downgrade":
          case "strict-origin":
          case "strict-origin-when-cross-origin":
            F.origin && Ee(F.origin) && !Ee(p(F)) && (O = null);
            break;
          case "same-origin":
            le(F, p(F)) || (O = null);
            break;
        }
        F.headersList.append("origin", O, !0);
      }
    }
  }
  function oe(F, O) {
    return F;
  }
  function ge(F, O, k) {
    return !F?.startTime || F.startTime < O ? {
      domainLookupStartTime: O,
      domainLookupEndTime: O,
      connectionStartTime: O,
      connectionEndTime: O,
      secureConnectionStartTime: O,
      ALPNNegotiatedProtocol: F?.ALPNNegotiatedProtocol
    } : {
      domainLookupStartTime: oe(F.domainLookupStartTime),
      domainLookupEndTime: oe(F.domainLookupEndTime),
      connectionStartTime: oe(F.connectionStartTime),
      connectionEndTime: oe(F.connectionEndTime),
      secureConnectionStartTime: oe(F.secureConnectionStartTime),
      ALPNNegotiatedProtocol: F.ALPNNegotiatedProtocol
    };
  }
  function ae(F) {
    return oe(i.now());
  }
  function he(F) {
    return {
      startTime: F.startTime ?? 0,
      redirectStartTime: 0,
      redirectEndTime: 0,
      postRedirectStartTime: F.startTime ?? 0,
      finalServiceWorkerStartTime: 0,
      finalNetworkResponseStartTime: 0,
      finalNetworkRequestStartTime: 0,
      endTime: 0,
      encodedBodySize: 0,
      decodedBodySize: 0,
      finalConnectionTimingInfo: null
    };
  }
  function Be() {
    return {
      referrerPolicy: "strict-origin-when-cross-origin"
    };
  }
  function Qe(F) {
    return {
      referrerPolicy: F.referrerPolicy
    };
  }
  function ye(F) {
    const O = F.referrerPolicy;
    w(O);
    let k = null;
    if (F.referrer === "client") {
      const z = n();
      if (!z || z.origin === "null")
        return "no-referrer";
      k = new URL(z);
    } else F.referrer instanceof URL && (k = F.referrer);
    let V = we(k);
    const H = we(k, !0);
    V.toString().length > 4096 && (V = H);
    const x = le(F, V), te = j(V) && !j(F.url);
    switch (O) {
      case "origin":
        return H ?? we(k, !0);
      case "unsafe-url":
        return V;
      case "same-origin":
        return x ? H : "no-referrer";
      case "origin-when-cross-origin":
        return x ? V : H;
      case "strict-origin-when-cross-origin": {
        const z = p(F);
        return le(V, z) ? V : j(V) && !j(z) ? "no-referrer" : H;
      }
      // eslint-disable-line
      /**
       * 1. If referrerURL is a potentially trustworthy URL and
       * request’s current URL is not a potentially trustworthy URL,
       * then return no referrer.
       * 2. Return referrerOrigin
      */
      default:
        return te ? "no-referrer" : H;
    }
  }
  function we(F, O) {
    return w(F instanceof URL), F = new URL(F), F.protocol === "file:" || F.protocol === "about:" || F.protocol === "blank:" ? "no-referrer" : (F.username = "", F.password = "", F.hash = "", O && (F.pathname = "", F.search = ""), F);
  }
  function j(F) {
    if (!(F instanceof URL))
      return !1;
    if (F.href === "about:blank" || F.href === "about:srcdoc" || F.protocol === "data:" || F.protocol === "file:") return !0;
    return O(F.origin);
    function O(k) {
      if (k == null || k === "null") return !1;
      const V = new URL(k);
      return !!(V.protocol === "https:" || V.protocol === "wss:" || /^127(?:\.[0-9]+){0,2}\.[0-9]+$|^\[(?:0*:)*?:?0*1\]$/.test(V.hostname) || V.hostname === "localhost" || V.hostname.includes("localhost.") || V.hostname.endsWith(".localhost"));
    }
  }
  function W(F, O) {
    if (G === void 0)
      return !0;
    const k = J(O);
    if (k === "no metadata" || k.length === 0)
      return !0;
    const V = _(k), H = P(k, V);
    for (const x of H) {
      const te = x.algo, z = x.hash;
      let ce = G.createHash(te).update(F).digest("base64");
      if (ce[ce.length - 1] === "=" && (ce[ce.length - 2] === "=" ? ce = ce.slice(0, -2) : ce = ce.slice(0, -1)), Z(ce, z))
        return !0;
    }
    return !1;
  }
  const re = /(?<algo>sha256|sha384|sha512)-((?<hash>[A-Za-z0-9+/]+|[A-Za-z0-9_-]+)={0,2}(?:\s|$)( +[!-~]*)?)?/i;
  function J(F) {
    const O = [];
    let k = !0;
    for (const V of F.split(" ")) {
      k = !1;
      const H = re.exec(V);
      if (H === null || H.groups === void 0 || H.groups.algo === void 0)
        continue;
      const x = H.groups.algo.toLowerCase();
      U.includes(x) && O.push(H.groups);
    }
    return k === !0 ? "no metadata" : O;
  }
  function _(F) {
    let O = F[0].algo;
    if (O[3] === "5")
      return O;
    for (let k = 1; k < F.length; ++k) {
      const V = F[k];
      if (V.algo[3] === "5") {
        O = "sha512";
        break;
      } else {
        if (O[3] === "3")
          continue;
        V.algo[3] === "3" && (O = "sha384");
      }
    }
    return O;
  }
  function P(F, O) {
    if (F.length === 1)
      return F;
    let k = 0;
    for (let V = 0; V < F.length; ++V)
      F[V].algo === O && (F[k++] = F[V]);
    return F.length = k, F;
  }
  function Z(F, O) {
    if (F.length !== O.length)
      return !1;
    for (let k = 0; k < F.length; ++k)
      if (F[k] !== O[k]) {
        if (F[k] === "+" && O[k] === "-" || F[k] === "/" && O[k] === "_")
          continue;
        return !1;
      }
    return !0;
  }
  function se(F) {
  }
  function le(F, O) {
    return F.origin === O.origin && F.origin === "null" || F.protocol === O.protocol && F.hostname === O.hostname && F.port === O.port;
  }
  function ne() {
    let F, O;
    return { promise: new Promise((V, H) => {
      F = V, O = H;
    }), resolve: F, reject: O };
  }
  function fe(F) {
    return F.controller.state === "aborted";
  }
  function Me(F) {
    return F.controller.state === "aborted" || F.controller.state === "terminated";
  }
  function pe(F) {
    return C[F.toLowerCase()] ?? F;
  }
  function Le(F) {
    const O = JSON.stringify(F);
    if (O === void 0)
      throw new TypeError("Value is not JSON serializable");
    return w(typeof O == "string"), O;
  }
  const ke = Object.getPrototypeOf(Object.getPrototypeOf([][Symbol.iterator]()));
  function be(F, O, k = 0, V = 1) {
    class H {
      /** @type {any} */
      #e;
      /** @type {'key' | 'value' | 'key+value'} */
      #A;
      /** @type {number} */
      #s;
      /**
       * @see https://webidl.spec.whatwg.org/#dfn-default-iterator-object
       * @param {unknown} target
       * @param {'key' | 'value' | 'key+value'} kind
       */
      constructor(te, z) {
        this.#e = te, this.#A = z, this.#s = 0;
      }
      next() {
        if (typeof this != "object" || this === null || !(#e in this))
          throw new TypeError(
            `'next' called on an object that does not implement interface ${F} Iterator.`
          );
        const te = this.#s, z = this.#e[O], ce = z.length;
        if (te >= ce)
          return {
            value: void 0,
            done: !0
          };
        const { [k]: Fe, [V]: Ge } = z[te];
        this.#s = te + 1;
        let Ne;
        switch (this.#A) {
          case "key":
            Ne = Fe;
            break;
          case "value":
            Ne = Ge;
            break;
          case "key+value":
            Ne = [Fe, Ge];
            break;
        }
        return {
          value: Ne,
          done: !1
        };
      }
    }
    return delete H.prototype.constructor, Object.setPrototypeOf(H.prototype, ke), Object.defineProperties(H.prototype, {
      [Symbol.toStringTag]: {
        writable: !1,
        enumerable: !1,
        configurable: !0,
        value: `${F} Iterator`
      },
      next: { writable: !0, enumerable: !0, configurable: !0 }
    }), function(x, te) {
      return new H(x, te);
    };
  }
  function de(F, O, k, V = 0, H = 1) {
    const x = be(F, k, V, H), te = {
      keys: {
        writable: !0,
        enumerable: !0,
        configurable: !0,
        value: function() {
          return b.brandCheck(this, O), x(this, "key");
        }
      },
      values: {
        writable: !0,
        enumerable: !0,
        configurable: !0,
        value: function() {
          return b.brandCheck(this, O), x(this, "value");
        }
      },
      entries: {
        writable: !0,
        enumerable: !0,
        configurable: !0,
        value: function() {
          return b.brandCheck(this, O), x(this, "key+value");
        }
      },
      forEach: {
        writable: !0,
        enumerable: !0,
        configurable: !0,
        value: function(ce, Fe = globalThis) {
          if (b.brandCheck(this, O), b.argumentLengthCheck(arguments, 1, `${F}.forEach`), typeof ce != "function")
            throw new TypeError(
              `Failed to execute 'forEach' on '${F}': parameter 1 is not of type 'Function'.`
            );
          for (const { 0: Ge, 1: Ne } of x(this, "key+value"))
            ce.call(Fe, Ne, Ge, this);
        }
      }
    };
    return Object.defineProperties(O.prototype, {
      ...te,
      [Symbol.iterator]: {
        writable: !0,
        enumerable: !1,
        configurable: !0,
        value: te.entries.value
      }
    });
  }
  async function _e(F, O, k) {
    const V = O, H = k;
    let x;
    try {
      x = F.stream.getReader();
    } catch (te) {
      H(te);
      return;
    }
    try {
      V(await q(x));
    } catch (te) {
      H(te);
    }
  }
  function Pe(F) {
    return F instanceof ReadableStream || F[Symbol.toStringTag] === "ReadableStream" && typeof F.tee == "function";
  }
  function Je(F) {
    try {
      F.close(), F.byobRequest?.respond(0);
    } catch (O) {
      if (!O.message.includes("Controller is already closed") && !O.message.includes("ReadableStream is already closed"))
        throw O;
    }
  }
  const X = /[^\x00-\xFF]/;
  function R(F) {
    return w(!X.test(F)), F;
  }
  async function q(F) {
    const O = [];
    let k = 0;
    for (; ; ) {
      const { done: V, value: H } = await F.read();
      if (V)
        return Buffer.concat(O, k);
      if (!D(H))
        throw new TypeError("Received non-Uint8Array chunk");
      O.push(H), k += H.length;
    }
  }
  function ie(F) {
    w("protocol" in F);
    const O = F.protocol;
    return O === "about:" || O === "blob:" || O === "data:";
  }
  function Ee(F) {
    return typeof F == "string" && F[5] === ":" && F[0] === "h" && F[1] === "t" && F[2] === "t" && F[3] === "p" && F[4] === "s" || F.protocol === "https:";
  }
  function Ie(F) {
    w("protocol" in F);
    const O = F.protocol;
    return O === "http:" || O === "https:";
  }
  function De(F, O) {
    const k = F;
    if (!k.startsWith("bytes"))
      return "failure";
    const V = { position: 5 };
    if (O && c(
      (ce) => ce === "	" || ce === " ",
      k,
      V
    ), k.charCodeAt(V.position) !== 61)
      return "failure";
    V.position++, O && c(
      (ce) => ce === "	" || ce === " ",
      k,
      V
    );
    const H = c(
      (ce) => {
        const Fe = ce.charCodeAt(0);
        return Fe >= 48 && Fe <= 57;
      },
      k,
      V
    ), x = H.length ? Number(H) : null;
    if (O && c(
      (ce) => ce === "	" || ce === " ",
      k,
      V
    ), k.charCodeAt(V.position) !== 45)
      return "failure";
    V.position++, O && c(
      (ce) => ce === "	" || ce === " ",
      k,
      V
    );
    const te = c(
      (ce) => {
        const Fe = ce.charCodeAt(0);
        return Fe >= 48 && Fe <= 57;
      },
      k,
      V
    ), z = te.length ? Number(te) : null;
    return V.position < k.length || z === null && x === null || x > z ? "failure" : { rangeStartValue: x, rangeEndValue: z };
  }
  function ve(F, O, k) {
    let V = "bytes ";
    return V += R(`${F}`), V += "-", V += R(`${O}`), V += "/", V += R(`${k}`), V;
  }
  class qe extends e {
    #e;
    /** @param {zlib.ZlibOptions} [zlibOptions] */
    constructor(O) {
      super(), this.#e = O;
    }
    _transform(O, k, V) {
      if (!this._inflateStream) {
        if (O.length === 0) {
          V();
          return;
        }
        this._inflateStream = (O[0] & 15) === 8 ? r.createInflate(this.#e) : r.createInflateRaw(this.#e), this._inflateStream.on("data", this.push.bind(this)), this._inflateStream.on("end", () => this.push(null)), this._inflateStream.on("error", (H) => this.destroy(H));
      }
      this._inflateStream.write(O, k, V);
    }
    _final(O) {
      this._inflateStream && (this._inflateStream.end(), this._inflateStream = null), O();
    }
  }
  function Ze(F) {
    return new qe(F);
  }
  function Ce(F) {
    let O = null, k = null, V = null;
    const H = ee("content-type", F);
    if (H === null)
      return "failure";
    for (const x of H) {
      const te = B(x);
      te === "failure" || te.essence === "*/*" || (V = te, V.essence !== k ? (O = null, V.parameters.has("charset") && (O = V.parameters.get("charset")), k = V.essence) : !V.parameters.has("charset") && O !== null && V.parameters.set("charset", O));
    }
    return V ?? "failure";
  }
  function Y(F) {
    const O = F, k = { position: 0 }, V = [];
    let H = "";
    for (; k.position < O.length; ) {
      if (H += c(
        (x) => x !== '"' && x !== ",",
        O,
        k
      ), k.position < O.length)
        if (O.charCodeAt(k.position) === 34) {
          if (H += g(
            O,
            k
          ), k.position < O.length)
            continue;
        } else
          w(O.charCodeAt(k.position) === 44), k.position++;
      H = Q(H, !0, !0, (x) => x === 9 || x === 32), V.push(H), H = "";
    }
    return V;
  }
  function ee(F, O) {
    const k = O.get(F, !0);
    return k === null ? null : Y(k);
  }
  const K = new TextDecoder();
  function Ae(F) {
    return F.length === 0 ? "" : (F[0] === 239 && F[1] === 187 && F[2] === 191 && (F = F.subarray(3)), K.decode(F));
  }
  class ue {
    get baseUrl() {
      return n();
    }
    get origin() {
      return this.baseUrl?.origin;
    }
    policyContainer = Be();
  }
  class Re {
    settingsObject = new ue();
  }
  const Se = new Re();
  return kt = {
    isAborted: fe,
    isCancelled: Me,
    isValidEncodedURL: d,
    createDeferredPromise: ne,
    ReadableStreamFrom: h,
    tryUpgradeRequestToAPotentiallyTrustworthyURL: se,
    clampAndCoarsenConnectionTimingInfo: ge,
    coarsenedSharedCurrentTime: ae,
    determineRequestsReferrer: ye,
    makePolicyContainer: Be,
    clonePolicyContainer: Qe,
    appendFetchMetadata: v,
    appendRequestOriginHeader: $,
    TAOCheck: L,
    corsCheck: T,
    crossOriginResourcePolicyCheck: S,
    createOpaqueTimingInfo: he,
    setRequestReferrerPolicyOnRedirect: y,
    isValidHTTPToken: u,
    requestBadPort: s,
    requestCurrentURL: p,
    responseURL: M,
    responseLocationURL: N,
    isBlobLike: a,
    isURLPotentiallyTrustworthy: j,
    isValidReasonPhrase: f,
    sameOrigin: le,
    normalizeMethod: pe,
    serializeJavascriptValueToJSONString: Le,
    iteratorMixin: de,
    createIterator: be,
    isValidHeaderName: I,
    isValidHeaderValue: m,
    isErrorLike: E,
    fullyReadBody: _e,
    bytesMatch: W,
    isReadableStreamLike: Pe,
    readableStreamClose: Je,
    isomorphicEncode: R,
    urlIsLocal: ie,
    urlHasHttpsScheme: Ee,
    urlIsHttpHttpsScheme: Ie,
    readAllBytes: q,
    simpleRangeHeaderValue: De,
    buildContentRange: ve,
    parseMetadata: J,
    createInflate: Ze,
    extractMimeType: Ce,
    getDecodeSplit: ee,
    utf8DecodeBytes: Ae,
    environmentSettingsObject: Se
  }, kt;
}
var bt, Ps;
function IA() {
  return Ps || (Ps = 1, bt = {
    kUrl: /* @__PURE__ */ Symbol("url"),
    kHeaders: /* @__PURE__ */ Symbol("headers"),
    kSignal: /* @__PURE__ */ Symbol("signal"),
    kState: /* @__PURE__ */ Symbol("state"),
    kDispatcher: /* @__PURE__ */ Symbol("dispatcher")
  }), bt;
}
var Ft, xs;
function qn() {
  if (xs) return Ft;
  xs = 1;
  const { Blob: e, File: r } = sA, { kState: t } = IA(), { webidl: o } = Xe();
  class A {
    constructor(g, Q, B = {}) {
      const i = Q, a = B.type, h = B.lastModified ?? Date.now();
      this[t] = {
        blobLike: g,
        name: i,
        type: a,
        lastModified: h
      };
    }
    stream(...g) {
      return o.brandCheck(this, A), this[t].blobLike.stream(...g);
    }
    arrayBuffer(...g) {
      return o.brandCheck(this, A), this[t].blobLike.arrayBuffer(...g);
    }
    slice(...g) {
      return o.brandCheck(this, A), this[t].blobLike.slice(...g);
    }
    text(...g) {
      return o.brandCheck(this, A), this[t].blobLike.text(...g);
    }
    get size() {
      return o.brandCheck(this, A), this[t].blobLike.size;
    }
    get type() {
      return o.brandCheck(this, A), this[t].blobLike.type;
    }
    get name() {
      return o.brandCheck(this, A), this[t].name;
    }
    get lastModified() {
      return o.brandCheck(this, A), this[t].lastModified;
    }
    get [Symbol.toStringTag]() {
      return "File";
    }
  }
  o.converters.Blob = o.interfaceConverter(e);
  function n(c) {
    return c instanceof r || c && (typeof c.stream == "function" || typeof c.arrayBuffer == "function") && c[Symbol.toStringTag] === "File";
  }
  return Ft = { FileLike: A, isFileLike: n }, Ft;
}
var Tt, Os;
function XA() {
  if (Os) return Tt;
  Os = 1;
  const { isBlobLike: e, iteratorMixin: r } = rA(), { kState: t } = IA(), { kEnumerableProperty: o } = Ue(), { FileLike: A, isFileLike: n } = qn(), { webidl: c } = Xe(), { File: g } = sA, Q = $e, B = globalThis.File ?? g;
  class i {
    constructor(u) {
      if (c.util.markAsUncloneable(this), u !== void 0)
        throw c.errors.conversionFailed({
          prefix: "FormData constructor",
          argument: "Argument 1",
          types: ["undefined"]
        });
      this[t] = [];
    }
    append(u, C, w = void 0) {
      c.brandCheck(this, i);
      const D = "FormData.append";
      if (c.argumentLengthCheck(arguments, 2, D), arguments.length === 3 && !e(C))
        throw new TypeError(
          "Failed to execute 'append' on 'FormData': parameter 2 is not of type 'Blob'"
        );
      u = c.converters.USVString(u, D, "name"), C = e(C) ? c.converters.Blob(C, D, "value", { strict: !1 }) : c.converters.USVString(C, D, "value"), w = arguments.length === 3 ? c.converters.USVString(w, D, "filename") : void 0;
      const b = a(u, C, w);
      this[t].push(b);
    }
    delete(u) {
      c.brandCheck(this, i);
      const C = "FormData.delete";
      c.argumentLengthCheck(arguments, 1, C), u = c.converters.USVString(u, C, "name"), this[t] = this[t].filter((w) => w.name !== u);
    }
    get(u) {
      c.brandCheck(this, i);
      const C = "FormData.get";
      c.argumentLengthCheck(arguments, 1, C), u = c.converters.USVString(u, C, "name");
      const w = this[t].findIndex((D) => D.name === u);
      return w === -1 ? null : this[t][w].value;
    }
    getAll(u) {
      c.brandCheck(this, i);
      const C = "FormData.getAll";
      return c.argumentLengthCheck(arguments, 1, C), u = c.converters.USVString(u, C, "name"), this[t].filter((w) => w.name === u).map((w) => w.value);
    }
    has(u) {
      c.brandCheck(this, i);
      const C = "FormData.has";
      return c.argumentLengthCheck(arguments, 1, C), u = c.converters.USVString(u, C, "name"), this[t].findIndex((w) => w.name === u) !== -1;
    }
    set(u, C, w = void 0) {
      c.brandCheck(this, i);
      const D = "FormData.set";
      if (c.argumentLengthCheck(arguments, 2, D), arguments.length === 3 && !e(C))
        throw new TypeError(
          "Failed to execute 'set' on 'FormData': parameter 2 is not of type 'Blob'"
        );
      u = c.converters.USVString(u, D, "name"), C = e(C) ? c.converters.Blob(C, D, "name", { strict: !1 }) : c.converters.USVString(C, D, "name"), w = arguments.length === 3 ? c.converters.USVString(w, D, "name") : void 0;
      const b = a(u, C, w), U = this[t].findIndex((G) => G.name === u);
      U !== -1 ? this[t] = [
        ...this[t].slice(0, U),
        b,
        ...this[t].slice(U + 1).filter((G) => G.name !== u)
      ] : this[t].push(b);
    }
    [Q.inspect.custom](u, C) {
      const w = this[t].reduce((b, U) => (b[U.name] ? Array.isArray(b[U.name]) ? b[U.name].push(U.value) : b[U.name] = [b[U.name], U.value] : b[U.name] = U.value, b), { __proto__: null });
      C.depth ??= u, C.colors ??= !0;
      const D = Q.formatWithOptions(C, w);
      return `FormData ${D.slice(D.indexOf("]") + 2)}`;
    }
  }
  r("FormData", i, t, "name", "value"), Object.defineProperties(i.prototype, {
    append: o,
    delete: o,
    get: o,
    getAll: o,
    has: o,
    set: o,
    [Symbol.toStringTag]: {
      value: "FormData",
      configurable: !0
    }
  });
  function a(h, u, C) {
    if (typeof u != "string") {
      if (n(u) || (u = u instanceof Blob ? new B([u], "blob", { type: u.type }) : new A(u, "blob", { type: u.type })), C !== void 0) {
        const w = {
          type: u.type,
          lastModified: u.lastModified
        };
        u = u instanceof g ? new B([u], C, w) : new A(u, C, w);
      }
    }
    return { name: h, value: u };
  }
  return Tt = { FormData: i, makeEntry: a }, Tt;
}
var St, _s;
function ji() {
  if (_s) return St;
  _s = 1;
  const { isUSVString: e, bufferToLowerCasedHeaderName: r } = Ue(), { utf8DecodeBytes: t } = rA(), { HTTP_TOKEN_CODEPOINTS: o, isomorphicDecode: A } = eA(), { isFileLike: n } = qn(), { makeEntry: c } = XA(), g = He, { File: Q } = sA, B = globalThis.File ?? Q, i = Buffer.from('form-data; name="'), a = Buffer.from("; filename"), h = Buffer.from("--"), u = Buffer.from(`--\r
`);
  function C(d) {
    for (let l = 0; l < d.length; ++l)
      if ((d.charCodeAt(l) & -128) !== 0)
        return !1;
    return !0;
  }
  function w(d) {
    const l = d.length;
    if (l < 27 || l > 70)
      return !1;
    for (let p = 0; p < l; ++p) {
      const s = d.charCodeAt(p);
      if (!(s >= 48 && s <= 57 || s >= 65 && s <= 90 || s >= 97 && s <= 122 || s === 39 || s === 45 || s === 95))
        return !1;
    }
    return !0;
  }
  function D(d, l) {
    g(l !== "failure" && l.essence === "multipart/form-data");
    const p = l.parameters.get("boundary");
    if (p === void 0)
      return "failure";
    const s = Buffer.from(`--${p}`, "utf8"), E = [], f = { position: 0 };
    for (; d[f.position] === 13 && d[f.position + 1] === 10; )
      f.position += 2;
    let I = d.length;
    for (; d[I - 1] === 10 && d[I - 2] === 13; )
      I -= 2;
    for (I !== d.length && (d = d.subarray(0, I)); ; ) {
      if (d.subarray(f.position, f.position + s.length).equals(s))
        f.position += s.length;
      else
        return "failure";
      if (f.position === d.length - 2 && N(d, h, f) || f.position === d.length - 4 && N(d, u, f))
        return E;
      if (d[f.position] !== 13 || d[f.position + 1] !== 10)
        return "failure";
      f.position += 2;
      const m = b(d, f);
      if (m === "failure")
        return "failure";
      let { name: y, filename: S, contentType: T, encoding: L } = m;
      f.position += 2;
      let v;
      {
        const oe = d.indexOf(s.subarray(2), f.position);
        if (oe === -1)
          return "failure";
        v = d.subarray(f.position, oe - 4), f.position += v.length, L === "base64" && (v = Buffer.from(v.toString(), "base64"));
      }
      if (d[f.position] !== 13 || d[f.position + 1] !== 10)
        return "failure";
      f.position += 2;
      let $;
      S !== null ? (T ??= "text/plain", C(T) || (T = ""), $ = new B([v], S, { type: T })) : $ = t(Buffer.from(v)), g(e(y)), g(typeof $ == "string" && e($) || n($)), E.push(c(y, $, S));
    }
  }
  function b(d, l) {
    let p = null, s = null, E = null, f = null;
    for (; ; ) {
      if (d[l.position] === 13 && d[l.position + 1] === 10)
        return p === null ? "failure" : { name: p, filename: s, contentType: E, encoding: f };
      let I = G(
        (m) => m !== 10 && m !== 13 && m !== 58,
        d,
        l
      );
      if (I = M(I, !0, !0, (m) => m === 9 || m === 32), !o.test(I.toString()) || d[l.position] !== 58)
        return "failure";
      switch (l.position++, G(
        (m) => m === 32 || m === 9,
        d,
        l
      ), r(I)) {
        case "content-disposition": {
          if (p = s = null, !N(d, i, l) || (l.position += 17, p = U(d, l), p === null))
            return "failure";
          if (N(d, a, l)) {
            let m = l.position + a.length;
            if (d[m] === 42 && (l.position += 1, m += 1), d[m] !== 61 || d[m + 1] !== 34 || (l.position += 12, s = U(d, l), s === null))
              return "failure";
          }
          break;
        }
        case "content-type": {
          let m = G(
            (y) => y !== 10 && y !== 13,
            d,
            l
          );
          m = M(m, !1, !0, (y) => y === 9 || y === 32), E = A(m);
          break;
        }
        case "content-transfer-encoding": {
          let m = G(
            (y) => y !== 10 && y !== 13,
            d,
            l
          );
          m = M(m, !1, !0, (y) => y === 9 || y === 32), f = A(m);
          break;
        }
        default:
          G(
            (m) => m !== 10 && m !== 13,
            d,
            l
          );
      }
      if (d[l.position] !== 13 && d[l.position + 1] !== 10)
        return "failure";
      l.position += 2;
    }
  }
  function U(d, l) {
    g(d[l.position - 1] === 34);
    let p = G(
      (s) => s !== 10 && s !== 13 && s !== 34,
      d,
      l
    );
    return d[l.position] !== 34 ? null : (l.position++, p = new TextDecoder().decode(p).replace(/%0A/ig, `
`).replace(/%0D/ig, "\r").replace(/%22/g, '"'), p);
  }
  function G(d, l, p) {
    let s = p.position;
    for (; s < l.length && d(l[s]); )
      ++s;
    return l.subarray(p.position, p.position = s);
  }
  function M(d, l, p, s) {
    let E = 0, f = d.length - 1;
    if (l)
      for (; E < d.length && s(d[E]); ) E++;
    for (; f > 0 && s(d[f]); ) f--;
    return E === 0 && f === d.length - 1 ? d : d.subarray(E, f + 1);
  }
  function N(d, l, p) {
    if (d.length < l.length)
      return !1;
    for (let s = 0; s < l.length; s++)
      if (l[s] !== d[p.position + s])
        return !1;
    return !0;
  }
  return St = {
    multipartFormDataParser: D,
    validateBoundary: w
  }, St;
}
var Ut, Ws;
function SA() {
  if (Ws) return Ut;
  Ws = 1;
  const e = Ue(), {
    ReadableStreamFrom: r,
    isBlobLike: t,
    isReadableStreamLike: o,
    readableStreamClose: A,
    createDeferredPromise: n,
    fullyReadBody: c,
    extractMimeType: g,
    utf8DecodeBytes: Q
  } = rA(), { FormData: B } = XA(), { kState: i } = IA(), { webidl: a } = Xe(), { Blob: h } = sA, u = He, { isErrored: C, isDisturbed: w } = tA, { isArrayBuffer: D } = Vn, { serializeAMimeType: b } = eA(), { multipartFormDataParser: U } = ji();
  let G;
  try {
    const v = require("node:crypto");
    G = ($) => v.randomInt(0, $);
  } catch {
    G = (v) => Math.floor(Math.random(v));
  }
  const M = new TextEncoder();
  function N() {
  }
  const d = globalThis.FinalizationRegistry && process.version.indexOf("v18") !== 0;
  let l;
  d && (l = new FinalizationRegistry((v) => {
    const $ = v.deref();
    $ && !$.locked && !w($) && !C($) && $.cancel("Response object has been garbage collected").catch(N);
  }));
  function p(v, $ = !1) {
    let oe = null;
    v instanceof ReadableStream ? oe = v : t(v) ? oe = v.stream() : oe = new ReadableStream({
      async pull(ye) {
        const we = typeof ae == "string" ? M.encode(ae) : ae;
        we.byteLength && ye.enqueue(we), queueMicrotask(() => A(ye));
      },
      start() {
      },
      type: "bytes"
    }), u(o(oe));
    let ge = null, ae = null, he = null, Be = null;
    if (typeof v == "string")
      ae = v, Be = "text/plain;charset=UTF-8";
    else if (v instanceof URLSearchParams)
      ae = v.toString(), Be = "application/x-www-form-urlencoded;charset=UTF-8";
    else if (D(v))
      ae = new Uint8Array(v.slice());
    else if (ArrayBuffer.isView(v))
      ae = new Uint8Array(v.buffer.slice(v.byteOffset, v.byteOffset + v.byteLength));
    else if (e.isFormDataLike(v)) {
      const ye = `----formdata-undici-0${`${G(1e11)}`.padStart(11, "0")}`, we = `--${ye}\r
Content-Disposition: form-data`;
      const j = (Z) => Z.replace(/\n/g, "%0A").replace(/\r/g, "%0D").replace(/"/g, "%22"), W = (Z) => Z.replace(/\r?\n|\r/g, `\r
`), re = [], J = new Uint8Array([13, 10]);
      he = 0;
      let _ = !1;
      for (const [Z, se] of v)
        if (typeof se == "string") {
          const le = M.encode(we + `; name="${j(W(Z))}"\r
\r
${W(se)}\r
`);
          re.push(le), he += le.byteLength;
        } else {
          const le = M.encode(`${we}; name="${j(W(Z))}"` + (se.name ? `; filename="${j(se.name)}"` : "") + `\r
Content-Type: ${se.type || "application/octet-stream"}\r
\r
`);
          re.push(le, se, J), typeof se.size == "number" ? he += le.byteLength + se.size + J.byteLength : _ = !0;
        }
      const P = M.encode(`--${ye}--\r
`);
      re.push(P), he += P.byteLength, _ && (he = null), ae = v, ge = async function* () {
        for (const Z of re)
          Z.stream ? yield* Z.stream() : yield Z;
      }, Be = `multipart/form-data; boundary=${ye}`;
    } else if (t(v))
      ae = v, he = v.size, v.type && (Be = v.type);
    else if (typeof v[Symbol.asyncIterator] == "function") {
      if ($)
        throw new TypeError("keepalive");
      if (e.isDisturbed(v) || v.locked)
        throw new TypeError(
          "Response body object should not be disturbed or locked"
        );
      oe = v instanceof ReadableStream ? v : r(v);
    }
    if ((typeof ae == "string" || e.isBuffer(ae)) && (he = Buffer.byteLength(ae)), ge != null) {
      let ye;
      oe = new ReadableStream({
        async start() {
          ye = ge(v)[Symbol.asyncIterator]();
        },
        async pull(we) {
          const { value: j, done: W } = await ye.next();
          if (W)
            queueMicrotask(() => {
              we.close(), we.byobRequest?.respond(0);
            });
          else if (!C(oe)) {
            const re = new Uint8Array(j);
            re.byteLength && we.enqueue(re);
          }
          return we.desiredSize > 0;
        },
        async cancel(we) {
          await ye.return();
        },
        type: "bytes"
      });
    }
    return [{ stream: oe, source: ae, length: he }, Be];
  }
  function s(v, $ = !1) {
    return v instanceof ReadableStream && (u(!e.isDisturbed(v), "The body has already been consumed."), u(!v.locked, "The stream is locked.")), p(v, $);
  }
  function E(v, $) {
    const [oe, ge] = $.stream.tee();
    return $.stream = oe, {
      stream: ge,
      length: $.length,
      source: $.source
    };
  }
  function f(v) {
    if (v.aborted)
      throw new DOMException("The operation was aborted.", "AbortError");
  }
  function I(v) {
    return {
      blob() {
        return y(this, (oe) => {
          let ge = L(this);
          return ge === null ? ge = "" : ge && (ge = b(ge)), new h([oe], { type: ge });
        }, v);
      },
      arrayBuffer() {
        return y(this, (oe) => new Uint8Array(oe).buffer, v);
      },
      text() {
        return y(this, Q, v);
      },
      json() {
        return y(this, T, v);
      },
      formData() {
        return y(this, (oe) => {
          const ge = L(this);
          if (ge !== null)
            switch (ge.essence) {
              case "multipart/form-data": {
                const ae = U(oe, ge);
                if (ae === "failure")
                  throw new TypeError("Failed to parse body as FormData.");
                const he = new B();
                return he[i] = ae, he;
              }
              case "application/x-www-form-urlencoded": {
                const ae = new URLSearchParams(oe.toString()), he = new B();
                for (const [Be, Qe] of ae)
                  he.append(Be, Qe);
                return he;
              }
            }
          throw new TypeError(
            'Content-Type was not one of "multipart/form-data" or "application/x-www-form-urlencoded".'
          );
        }, v);
      },
      bytes() {
        return y(this, (oe) => new Uint8Array(oe), v);
      }
    };
  }
  function m(v) {
    Object.assign(v.prototype, I(v));
  }
  async function y(v, $, oe) {
    if (a.brandCheck(v, oe), S(v))
      throw new TypeError("Body is unusable: Body has already been read");
    f(v[i]);
    const ge = n(), ae = (Be) => ge.reject(Be), he = (Be) => {
      try {
        ge.resolve($(Be));
      } catch (Qe) {
        ae(Qe);
      }
    };
    return v[i].body == null ? (he(Buffer.allocUnsafe(0)), ge.promise) : (await c(v[i].body, he, ae), ge.promise);
  }
  function S(v) {
    const $ = v[i].body;
    return $ != null && ($.stream.locked || e.isDisturbed($.stream));
  }
  function T(v) {
    return JSON.parse(Q(v));
  }
  function L(v) {
    const $ = v[i].headersList, oe = g($);
    return oe === "failure" ? null : oe;
  }
  return Ut = {
    extractBody: p,
    safelyExtractBody: s,
    cloneBody: E,
    mixinBody: m,
    streamRegistry: l,
    hasFinalizationRegistry: d,
    bodyUnusable: S
  }, Ut;
}
var Nt, qs;
function $i() {
  if (qs) return Nt;
  qs = 1;
  const e = He, r = Ue(), { channels: t } = FA(), o = _n(), {
    RequestContentLengthMismatchError: A,
    ResponseContentLengthMismatchError: n,
    RequestAbortedError: c,
    HeadersTimeoutError: g,
    HeadersOverflowError: Q,
    SocketError: B,
    InformationalError: i,
    BodyTimeoutError: a,
    HTTPParserError: h,
    ResponseExceededMaxSizeError: u
  } = Ye(), {
    kUrl: C,
    kReset: w,
    kClient: D,
    kParser: b,
    kBlocking: U,
    kRunning: G,
    kPending: M,
    kSize: N,
    kWriting: d,
    kQueue: l,
    kNoRef: p,
    kKeepAliveDefaultTimeout: s,
    kHostHeader: E,
    kPendingIdx: f,
    kRunningIdx: I,
    kError: m,
    kPipelining: y,
    kSocket: S,
    kKeepAliveTimeoutValue: T,
    kMaxHeadersSize: L,
    kKeepAliveMaxTimeout: v,
    kKeepAliveTimeoutThreshold: $,
    kHeadersTimeout: oe,
    kBodyTimeout: ge,
    kStrictContentLength: ae,
    kMaxRequests: he,
    kCounter: Be,
    kMaxResponseSize: Qe,
    kOnError: ye,
    kResume: we,
    kHTTPContext: j
  } = Oe(), W = Ki(), re = Buffer.alloc(0), J = Buffer[Symbol.species], _ = r.addListener, P = r.removeAllListeners;
  let Z;
  async function se() {
    const Ce = process.env.JEST_WORKER_ID ? Ls() : void 0;
    let Y;
    try {
      Y = await WebAssembly.compile(Xi());
    } catch {
      Y = await WebAssembly.compile(Ce || Ls());
    }
    return await WebAssembly.instantiate(Y, {
      env: {
        /* eslint-disable camelcase */
        wasm_on_url: (ee, K, Ae) => 0,
        wasm_on_status: (ee, K, Ae) => {
          e(fe.ptr === ee);
          const ue = K - Le + Me.byteOffset;
          return fe.onStatus(new J(Me.buffer, ue, Ae)) || 0;
        },
        wasm_on_message_begin: (ee) => (e(fe.ptr === ee), fe.onMessageBegin() || 0),
        wasm_on_header_field: (ee, K, Ae) => {
          e(fe.ptr === ee);
          const ue = K - Le + Me.byteOffset;
          return fe.onHeaderField(new J(Me.buffer, ue, Ae)) || 0;
        },
        wasm_on_header_value: (ee, K, Ae) => {
          e(fe.ptr === ee);
          const ue = K - Le + Me.byteOffset;
          return fe.onHeaderValue(new J(Me.buffer, ue, Ae)) || 0;
        },
        wasm_on_headers_complete: (ee, K, Ae, ue) => (e(fe.ptr === ee), fe.onHeadersComplete(K, !!Ae, !!ue) || 0),
        wasm_on_body: (ee, K, Ae) => {
          e(fe.ptr === ee);
          const ue = K - Le + Me.byteOffset;
          return fe.onBody(new J(Me.buffer, ue, Ae)) || 0;
        },
        wasm_on_message_complete: (ee) => (e(fe.ptr === ee), fe.onMessageComplete() || 0)
        /* eslint-enable camelcase */
      }
    });
  }
  let le = null, ne = se();
  ne.catch();
  let fe = null, Me = null, pe = 0, Le = null;
  const ke = 0, be = 1, de = 2 | be, _e = 4 | be, Pe = 8 | ke;
  class Je {
    constructor(Y, ee, { exports: K }) {
      e(Number.isFinite(Y[L]) && Y[L] > 0), this.llhttp = K, this.ptr = this.llhttp.llhttp_alloc(W.TYPE.RESPONSE), this.client = Y, this.socket = ee, this.timeout = null, this.timeoutValue = null, this.timeoutType = null, this.statusCode = null, this.statusText = "", this.upgrade = !1, this.headers = [], this.headersSize = 0, this.headersMaxSize = Y[L], this.shouldKeepAlive = !1, this.paused = !1, this.resume = this.resume.bind(this), this.bytesRead = 0, this.keepAlive = "", this.contentLength = "", this.connection = "", this.maxResponseSize = Y[Qe];
    }
    setTimeout(Y, ee) {
      Y !== this.timeoutValue || ee & be ^ this.timeoutType & be ? (this.timeout && (o.clearTimeout(this.timeout), this.timeout = null), Y && (ee & be ? this.timeout = o.setFastTimeout(X, Y, new WeakRef(this)) : (this.timeout = setTimeout(X, Y, new WeakRef(this)), this.timeout.unref())), this.timeoutValue = Y) : this.timeout && this.timeout.refresh && this.timeout.refresh(), this.timeoutType = ee;
    }
    resume() {
      this.socket.destroyed || !this.paused || (e(this.ptr != null), e(fe == null), this.llhttp.llhttp_resume(this.ptr), e(this.timeoutType === _e), this.timeout && this.timeout.refresh && this.timeout.refresh(), this.paused = !1, this.execute(this.socket.read() || re), this.readMore());
    }
    readMore() {
      for (; !this.paused && this.ptr; ) {
        const Y = this.socket.read();
        if (Y === null)
          break;
        this.execute(Y);
      }
    }
    execute(Y) {
      e(this.ptr != null), e(fe == null), e(!this.paused);
      const { socket: ee, llhttp: K } = this;
      Y.length > pe && (Le && K.free(Le), pe = Math.ceil(Y.length / 4096) * 4096, Le = K.malloc(pe)), new Uint8Array(K.memory.buffer, Le, pe).set(Y);
      try {
        let Ae;
        try {
          Me = Y, fe = this, Ae = K.llhttp_execute(this.ptr, Le, Y.length);
        } catch (Re) {
          throw Re;
        } finally {
          fe = null, Me = null;
        }
        const ue = K.llhttp_get_error_pos(this.ptr) - Le;
        if (Ae === W.ERROR.PAUSED_UPGRADE)
          this.onUpgrade(Y.slice(ue));
        else if (Ae === W.ERROR.PAUSED)
          this.paused = !0, ee.unshift(Y.slice(ue));
        else if (Ae !== W.ERROR.OK) {
          const Re = K.llhttp_get_error_reason(this.ptr);
          let Se = "";
          if (Re) {
            const F = new Uint8Array(K.memory.buffer, Re).indexOf(0);
            Se = "Response does not match the HTTP/1.1 protocol (" + Buffer.from(K.memory.buffer, Re, F).toString() + ")";
          }
          throw new h(Se, W.ERROR[Ae], Y.slice(ue));
        }
      } catch (Ae) {
        r.destroy(ee, Ae);
      }
    }
    destroy() {
      e(this.ptr != null), e(fe == null), this.llhttp.llhttp_free(this.ptr), this.ptr = null, this.timeout && o.clearTimeout(this.timeout), this.timeout = null, this.timeoutValue = null, this.timeoutType = null, this.paused = !1;
    }
    onStatus(Y) {
      this.statusText = Y.toString();
    }
    onMessageBegin() {
      const { socket: Y, client: ee } = this;
      if (Y.destroyed)
        return -1;
      const K = ee[l][ee[I]];
      if (!K)
        return -1;
      K.onResponseStarted();
    }
    onHeaderField(Y) {
      const ee = this.headers.length;
      (ee & 1) === 0 ? this.headers.push(Y) : this.headers[ee - 1] = Buffer.concat([this.headers[ee - 1], Y]), this.trackHeader(Y.length);
    }
    onHeaderValue(Y) {
      let ee = this.headers.length;
      (ee & 1) === 1 ? (this.headers.push(Y), ee += 1) : this.headers[ee - 1] = Buffer.concat([this.headers[ee - 1], Y]);
      const K = this.headers[ee - 2];
      if (K.length === 10) {
        const Ae = r.bufferToLowerCasedHeaderName(K);
        Ae === "keep-alive" ? this.keepAlive += Y.toString() : Ae === "connection" && (this.connection += Y.toString());
      } else K.length === 14 && r.bufferToLowerCasedHeaderName(K) === "content-length" && (this.contentLength += Y.toString());
      this.trackHeader(Y.length);
    }
    trackHeader(Y) {
      this.headersSize += Y, this.headersSize >= this.headersMaxSize && r.destroy(this.socket, new Q());
    }
    onUpgrade(Y) {
      const { upgrade: ee, client: K, socket: Ae, headers: ue, statusCode: Re } = this;
      e(ee), e(K[S] === Ae), e(!Ae.destroyed), e(!this.paused), e((ue.length & 1) === 0);
      const Se = K[l][K[I]];
      e(Se), e(Se.upgrade || Se.method === "CONNECT"), this.statusCode = null, this.statusText = "", this.shouldKeepAlive = null, this.headers = [], this.headersSize = 0, Ae.unshift(Y), Ae[b].destroy(), Ae[b] = null, Ae[D] = null, Ae[m] = null, P(Ae), K[S] = null, K[j] = null, K[l][K[I]++] = null, K.emit("disconnect", K[C], [K], new i("upgrade"));
      try {
        Se.onUpgrade(Re, ue, Ae);
      } catch (F) {
        r.destroy(Ae, F);
      }
      K[we]();
    }
    onHeadersComplete(Y, ee, K) {
      const { client: Ae, socket: ue, headers: Re, statusText: Se } = this;
      if (ue.destroyed)
        return -1;
      const F = Ae[l][Ae[I]];
      if (!F)
        return -1;
      if (e(!this.upgrade), e(this.statusCode < 200), Y === 100)
        return r.destroy(ue, new B("bad response", r.getSocketInfo(ue))), -1;
      if (ee && !F.upgrade)
        return r.destroy(ue, new B("bad upgrade", r.getSocketInfo(ue))), -1;
      if (e(this.timeoutType === de), this.statusCode = Y, this.shouldKeepAlive = K || // Override llhttp value which does not allow keepAlive for HEAD.
      F.method === "HEAD" && !ue[w] && this.connection.toLowerCase() === "keep-alive", this.statusCode >= 200) {
        const k = F.bodyTimeout != null ? F.bodyTimeout : Ae[ge];
        this.setTimeout(k, _e);
      } else this.timeout && this.timeout.refresh && this.timeout.refresh();
      if (F.method === "CONNECT")
        return e(Ae[G] === 1), this.upgrade = !0, 2;
      if (ee)
        return e(Ae[G] === 1), this.upgrade = !0, 2;
      if (e((this.headers.length & 1) === 0), this.headers = [], this.headersSize = 0, this.shouldKeepAlive && Ae[y]) {
        const k = this.keepAlive ? r.parseKeepAliveTimeout(this.keepAlive) : null;
        if (k != null) {
          const V = Math.min(
            k - Ae[$],
            Ae[v]
          );
          V <= 0 ? ue[w] = !0 : Ae[T] = V;
        } else
          Ae[T] = Ae[s];
      } else
        ue[w] = !0;
      const O = F.onHeaders(Y, Re, this.resume, Se) === !1;
      return F.aborted ? -1 : F.method === "HEAD" || Y < 200 ? 1 : (ue[U] && (ue[U] = !1, Ae[we]()), O ? W.ERROR.PAUSED : 0);
    }
    onBody(Y) {
      const { client: ee, socket: K, statusCode: Ae, maxResponseSize: ue } = this;
      if (K.destroyed)
        return -1;
      const Re = ee[l][ee[I]];
      if (e(Re), e(this.timeoutType === _e), this.timeout && this.timeout.refresh && this.timeout.refresh(), e(Ae >= 200), ue > -1 && this.bytesRead + Y.length > ue)
        return r.destroy(K, new u()), -1;
      if (this.bytesRead += Y.length, Re.onData(Y) === !1)
        return W.ERROR.PAUSED;
    }
    onMessageComplete() {
      const { client: Y, socket: ee, statusCode: K, upgrade: Ae, headers: ue, contentLength: Re, bytesRead: Se, shouldKeepAlive: F } = this;
      if (ee.destroyed && (!K || F))
        return -1;
      if (Ae)
        return;
      e(K >= 100), e((this.headers.length & 1) === 0);
      const O = Y[l][Y[I]];
      if (e(O), this.statusCode = null, this.statusText = "", this.bytesRead = 0, this.contentLength = "", this.keepAlive = "", this.connection = "", this.headers = [], this.headersSize = 0, !(K < 200)) {
        if (O.method !== "HEAD" && Re && Se !== parseInt(Re, 10))
          return r.destroy(ee, new n()), -1;
        if (O.onComplete(ue), Y[l][Y[I]++] = null, ee[d])
          return e(Y[G] === 0), r.destroy(ee, new i("reset")), W.ERROR.PAUSED;
        if (F) {
          if (ee[w] && Y[G] === 0)
            return r.destroy(ee, new i("reset")), W.ERROR.PAUSED;
          Y[y] == null || Y[y] === 1 ? setImmediate(() => Y[we]()) : Y[we]();
        } else return r.destroy(ee, new i("reset")), W.ERROR.PAUSED;
      }
    }
  }
  function X(Ce) {
    const { socket: Y, timeoutType: ee, client: K, paused: Ae } = Ce.deref();
    ee === de ? (!Y[d] || Y.writableNeedDrain || K[G] > 1) && (e(!Ae, "cannot be paused while waiting for headers"), r.destroy(Y, new g())) : ee === _e ? Ae || r.destroy(Y, new a()) : ee === Pe && (e(K[G] === 0 && K[T]), r.destroy(Y, new i("socket idle timeout")));
  }
  async function R(Ce, Y) {
    Ce[S] = Y, le || (le = await ne, ne = null), Y[p] = !1, Y[d] = !1, Y[w] = !1, Y[U] = !1, Y[b] = new Je(Ce, Y, le), _(Y, "error", function(K) {
      e(K.code !== "ERR_TLS_CERT_ALTNAME_INVALID");
      const Ae = this[b];
      if (K.code === "ECONNRESET" && Ae.statusCode && !Ae.shouldKeepAlive) {
        Ae.onMessageComplete();
        return;
      }
      this[m] = K, this[D][ye](K);
    }), _(Y, "readable", function() {
      const K = this[b];
      K && K.readMore();
    }), _(Y, "end", function() {
      const K = this[b];
      if (K.statusCode && !K.shouldKeepAlive) {
        K.onMessageComplete();
        return;
      }
      r.destroy(this, new B("other side closed", r.getSocketInfo(this)));
    }), _(Y, "close", function() {
      const K = this[D], Ae = this[b];
      Ae && (!this[m] && Ae.statusCode && !Ae.shouldKeepAlive && Ae.onMessageComplete(), this[b].destroy(), this[b] = null);
      const ue = this[m] || new B("closed", r.getSocketInfo(this));
      if (K[S] = null, K[j] = null, K.destroyed) {
        e(K[M] === 0);
        const Re = K[l].splice(K[I]);
        for (let Se = 0; Se < Re.length; Se++) {
          const F = Re[Se];
          r.errorRequest(K, F, ue);
        }
      } else if (K[G] > 0 && ue.code !== "UND_ERR_INFO") {
        const Re = K[l][K[I]];
        K[l][K[I]++] = null, r.errorRequest(K, Re, ue);
      }
      K[f] = K[I], e(K[G] === 0), K.emit("disconnect", K[C], [K], ue), K[we]();
    });
    let ee = !1;
    return Y.on("close", () => {
      ee = !0;
    }), {
      version: "h1",
      defaultPipelining: 1,
      write(...K) {
        return Ee(Ce, ...K);
      },
      resume() {
        q(Ce);
      },
      destroy(K, Ae) {
        ee ? queueMicrotask(Ae) : Y.destroy(K).on("close", Ae);
      },
      get destroyed() {
        return Y.destroyed;
      },
      busy(K) {
        return !!(Y[d] || Y[w] || Y[U] || K && (Ce[G] > 0 && !K.idempotent || Ce[G] > 0 && (K.upgrade || K.method === "CONNECT") || Ce[G] > 0 && r.bodyLength(K.body) !== 0 && (r.isStream(K.body) || r.isAsyncIterable(K.body) || r.isFormDataLike(K.body))));
      }
    };
  }
  function q(Ce) {
    const Y = Ce[S];
    if (Y && !Y.destroyed) {
      if (Ce[N] === 0 ? !Y[p] && Y.unref && (Y.unref(), Y[p] = !0) : Y[p] && Y.ref && (Y.ref(), Y[p] = !1), Ce[N] === 0)
        Y[b].timeoutType !== Pe && Y[b].setTimeout(Ce[T], Pe);
      else if (Ce[G] > 0 && Y[b].statusCode < 200 && Y[b].timeoutType !== de) {
        const ee = Ce[l][Ce[I]], K = ee.headersTimeout != null ? ee.headersTimeout : Ce[oe];
        Y[b].setTimeout(K, de);
      }
    }
  }
  function ie(Ce) {
    return Ce !== "GET" && Ce !== "HEAD" && Ce !== "OPTIONS" && Ce !== "TRACE" && Ce !== "CONNECT";
  }
  function Ee(Ce, Y) {
    const { method: ee, path: K, host: Ae, upgrade: ue, blocking: Re, reset: Se } = Y;
    let { body: F, headers: O, contentLength: k } = Y;
    const V = ee === "PUT" || ee === "POST" || ee === "PATCH" || ee === "QUERY" || ee === "PROPFIND" || ee === "PROPPATCH";
    if (r.isFormDataLike(F)) {
      Z || (Z = SA().extractBody);
      const [ce, Fe] = Z(F);
      Y.contentType == null && O.push("content-type", Fe), F = ce.stream, k = ce.length;
    } else r.isBlobLike(F) && Y.contentType == null && F.type && O.push("content-type", F.type);
    F && typeof F.read == "function" && F.read(0);
    const H = r.bodyLength(F);
    if (k = H ?? k, k === null && (k = Y.contentLength), k === 0 && !V && (k = null), ie(ee) && k > 0 && Y.contentLength !== null && Y.contentLength !== k) {
      if (Ce[ae])
        return r.errorRequest(Ce, Y, new A()), !1;
      process.emitWarning(new A());
    }
    const x = Ce[S], te = (ce) => {
      Y.aborted || Y.completed || (r.errorRequest(Ce, Y, ce || new c()), r.destroy(F), r.destroy(x, new i("aborted")));
    };
    try {
      Y.onConnect(te);
    } catch (ce) {
      r.errorRequest(Ce, Y, ce);
    }
    if (Y.aborted)
      return !1;
    ee === "HEAD" && (x[w] = !0), (ue || ee === "CONNECT") && (x[w] = !0), Se != null && (x[w] = Se), Ce[he] && x[Be]++ >= Ce[he] && (x[w] = !0), Re && (x[U] = !0);
    let z = `${ee} ${K} HTTP/1.1\r
`;
    if (typeof Ae == "string" ? z += `host: ${Ae}\r
` : z += Ce[E], ue ? z += `connection: upgrade\r
upgrade: ${ue}\r
` : Ce[y] && !x[w] ? z += `connection: keep-alive\r
` : z += `connection: close\r
`, Array.isArray(O))
      for (let ce = 0; ce < O.length; ce += 2) {
        const Fe = O[ce + 0], Ge = O[ce + 1];
        if (Array.isArray(Ge))
          for (let Ne = 0; Ne < Ge.length; Ne++)
            z += `${Fe}: ${Ge[Ne]}\r
`;
        else
          z += `${Fe}: ${Ge}\r
`;
      }
    return t.sendHeaders.hasSubscribers && t.sendHeaders.publish({ request: Y, headers: z, socket: x }), !F || H === 0 ? De(te, null, Ce, Y, x, k, z, V) : r.isBuffer(F) ? De(te, F, Ce, Y, x, k, z, V) : r.isBlobLike(F) ? typeof F.stream == "function" ? qe(te, F.stream(), Ce, Y, x, k, z, V) : ve(te, F, Ce, Y, x, k, z, V) : r.isStream(F) ? Ie(te, F, Ce, Y, x, k, z, V) : r.isIterable(F) ? qe(te, F, Ce, Y, x, k, z, V) : e(!1), !0;
  }
  function Ie(Ce, Y, ee, K, Ae, ue, Re, Se) {
    e(ue !== 0 || ee[G] === 0, "stream body cannot be pipelined");
    let F = !1;
    const O = new Ze({ abort: Ce, socket: Ae, request: K, contentLength: ue, client: ee, expectsPayload: Se, header: Re }), k = function(te) {
      if (!F)
        try {
          !O.write(te) && this.pause && this.pause();
        } catch (z) {
          r.destroy(this, z);
        }
    }, V = function() {
      F || Y.resume && Y.resume();
    }, H = function() {
      if (queueMicrotask(() => {
        Y.removeListener("error", x);
      }), !F) {
        const te = new c();
        queueMicrotask(() => x(te));
      }
    }, x = function(te) {
      if (!F) {
        if (F = !0, e(Ae.destroyed || Ae[d] && ee[G] <= 1), Ae.off("drain", V).off("error", x), Y.removeListener("data", k).removeListener("end", x).removeListener("close", H), !te)
          try {
            O.end();
          } catch (z) {
            te = z;
          }
        O.destroy(te), te && (te.code !== "UND_ERR_INFO" || te.message !== "reset") ? r.destroy(Y, te) : r.destroy(Y);
      }
    };
    Y.on("data", k).on("end", x).on("error", x).on("close", H), Y.resume && Y.resume(), Ae.on("drain", V).on("error", x), Y.errorEmitted ?? Y.errored ? setImmediate(() => x(Y.errored)) : (Y.endEmitted ?? Y.readableEnded) && setImmediate(() => x(null)), (Y.closeEmitted ?? Y.closed) && setImmediate(H);
  }
  function De(Ce, Y, ee, K, Ae, ue, Re, Se) {
    try {
      Y ? r.isBuffer(Y) && (e(ue === Y.byteLength, "buffer body must have content length"), Ae.cork(), Ae.write(`${Re}content-length: ${ue}\r
\r
`, "latin1"), Ae.write(Y), Ae.uncork(), K.onBodySent(Y), !Se && K.reset !== !1 && (Ae[w] = !0)) : ue === 0 ? Ae.write(`${Re}content-length: 0\r
\r
`, "latin1") : (e(ue === null, "no body must not have content length"), Ae.write(`${Re}\r
`, "latin1")), K.onRequestSent(), ee[we]();
    } catch (F) {
      Ce(F);
    }
  }
  async function ve(Ce, Y, ee, K, Ae, ue, Re, Se) {
    e(ue === Y.size, "blob body must have content length");
    try {
      if (ue != null && ue !== Y.size)
        throw new A();
      const F = Buffer.from(await Y.arrayBuffer());
      Ae.cork(), Ae.write(`${Re}content-length: ${ue}\r
\r
`, "latin1"), Ae.write(F), Ae.uncork(), K.onBodySent(F), K.onRequestSent(), !Se && K.reset !== !1 && (Ae[w] = !0), ee[we]();
    } catch (F) {
      Ce(F);
    }
  }
  async function qe(Ce, Y, ee, K, Ae, ue, Re, Se) {
    e(ue !== 0 || ee[G] === 0, "iterator body cannot be pipelined");
    let F = null;
    function O() {
      if (F) {
        const H = F;
        F = null, H();
      }
    }
    const k = () => new Promise((H, x) => {
      e(F === null), Ae[m] ? x(Ae[m]) : F = H;
    });
    Ae.on("close", O).on("drain", O);
    const V = new Ze({ abort: Ce, socket: Ae, request: K, contentLength: ue, client: ee, expectsPayload: Se, header: Re });
    try {
      for await (const H of Y) {
        if (Ae[m])
          throw Ae[m];
        V.write(H) || await k();
      }
      V.end();
    } catch (H) {
      V.destroy(H);
    } finally {
      Ae.off("close", O).off("drain", O);
    }
  }
  class Ze {
    constructor({ abort: Y, socket: ee, request: K, contentLength: Ae, client: ue, expectsPayload: Re, header: Se }) {
      this.socket = ee, this.request = K, this.contentLength = Ae, this.client = ue, this.bytesWritten = 0, this.expectsPayload = Re, this.header = Se, this.abort = Y, ee[d] = !0;
    }
    write(Y) {
      const { socket: ee, request: K, contentLength: Ae, client: ue, bytesWritten: Re, expectsPayload: Se, header: F } = this;
      if (ee[m])
        throw ee[m];
      if (ee.destroyed)
        return !1;
      const O = Buffer.byteLength(Y);
      if (!O)
        return !0;
      if (Ae !== null && Re + O > Ae) {
        if (ue[ae])
          throw new A();
        process.emitWarning(new A());
      }
      ee.cork(), Re === 0 && (!Se && K.reset !== !1 && (ee[w] = !0), Ae === null ? ee.write(`${F}transfer-encoding: chunked\r
`, "latin1") : ee.write(`${F}content-length: ${Ae}\r
\r
`, "latin1")), Ae === null && ee.write(`\r
${O.toString(16)}\r
`, "latin1"), this.bytesWritten += O;
      const k = ee.write(Y);
      return ee.uncork(), K.onBodySent(Y), k || ee[b].timeout && ee[b].timeoutType === de && ee[b].timeout.refresh && ee[b].timeout.refresh(), k;
    }
    end() {
      const { socket: Y, contentLength: ee, client: K, bytesWritten: Ae, expectsPayload: ue, header: Re, request: Se } = this;
      if (Se.onRequestSent(), Y[d] = !1, Y[m])
        throw Y[m];
      if (!Y.destroyed) {
        if (Ae === 0 ? ue ? Y.write(`${Re}content-length: 0\r
\r
`, "latin1") : Y.write(`${Re}\r
`, "latin1") : ee === null && Y.write(`\r
0\r
\r
`, "latin1"), ee !== null && Ae !== ee) {
          if (K[ae])
            throw new A();
          process.emitWarning(new A());
        }
        Y[b].timeout && Y[b].timeoutType === de && Y[b].timeout.refresh && Y[b].timeout.refresh(), K[we]();
      }
    }
    destroy(Y) {
      const { socket: ee, client: K, abort: Ae } = this;
      ee[d] = !1, Y && (e(K[G] <= 1, "pipeline should only contain this request"), Ae(Y));
    }
  }
  return Nt = R, Nt;
}
var Mt, zs;
function ea() {
  if (zs) return Mt;
  zs = 1;
  const e = He, { pipeline: r } = tA, t = Ue(), {
    RequestContentLengthMismatchError: o,
    RequestAbortedError: A,
    SocketError: n,
    InformationalError: c
  } = Ye(), {
    kUrl: g,
    kReset: Q,
    kClient: B,
    kRunning: i,
    kPending: a,
    kQueue: h,
    kPendingIdx: u,
    kRunningIdx: C,
    kError: w,
    kSocket: D,
    kStrictContentLength: b,
    kOnError: U,
    kMaxConcurrentStreams: G,
    kHTTP2Session: M,
    kResume: N,
    kSize: d,
    kHTTPContext: l
  } = Oe(), p = /* @__PURE__ */ Symbol("open streams");
  let s, E = !1, f;
  try {
    f = require("node:http2");
  } catch {
    f = { constants: {} };
  }
  const {
    constants: {
      HTTP2_HEADER_AUTHORITY: I,
      HTTP2_HEADER_METHOD: m,
      HTTP2_HEADER_PATH: y,
      HTTP2_HEADER_SCHEME: S,
      HTTP2_HEADER_CONTENT_LENGTH: T,
      HTTP2_HEADER_EXPECT: L,
      HTTP2_HEADER_STATUS: v
    }
  } = f;
  function $(_) {
    const P = [];
    for (const [Z, se] of Object.entries(_))
      if (Array.isArray(se))
        for (const le of se)
          P.push(Buffer.from(Z), Buffer.from(le));
      else
        P.push(Buffer.from(Z), Buffer.from(se));
    return P;
  }
  async function oe(_, P) {
    _[D] = P, E || (E = !0, process.emitWarning("H2 support is experimental, expect them to change at any time.", {
      code: "UNDICI-H2"
    }));
    const Z = f.connect(_[g], {
      createConnection: () => P,
      peerMaxConcurrentStreams: _[G]
    });
    Z[p] = 0, Z[B] = _, Z[D] = P, t.addListener(Z, "error", ae), t.addListener(Z, "frameError", he), t.addListener(Z, "end", Be), t.addListener(Z, "goaway", Qe), t.addListener(Z, "close", function() {
      const { [B]: le } = this, { [D]: ne } = le, fe = this[D][w] || this[w] || new n("closed", t.getSocketInfo(ne));
      if (le[M] = null, le.destroyed) {
        e(le[a] === 0);
        const Me = le[h].splice(le[C]);
        for (let pe = 0; pe < Me.length; pe++) {
          const Le = Me[pe];
          t.errorRequest(le, Le, fe);
        }
      }
    }), Z.unref(), _[M] = Z, P[M] = Z, t.addListener(P, "error", function(le) {
      e(le.code !== "ERR_TLS_CERT_ALTNAME_INVALID"), this[w] = le, this[B][U](le);
    }), t.addListener(P, "end", function() {
      t.destroy(this, new n("other side closed", t.getSocketInfo(this)));
    }), t.addListener(P, "close", function() {
      const le = this[w] || new n("closed", t.getSocketInfo(this));
      _[D] = null, this[M] != null && this[M].destroy(le), _[u] = _[C], e(_[i] === 0), _.emit("disconnect", _[g], [_], le), _[N]();
    });
    let se = !1;
    return P.on("close", () => {
      se = !0;
    }), {
      version: "h2",
      defaultPipelining: 1 / 0,
      write(...le) {
        return we(_, ...le);
      },
      resume() {
        ge(_);
      },
      destroy(le, ne) {
        se ? queueMicrotask(ne) : P.destroy(le).on("close", ne);
      },
      get destroyed() {
        return P.destroyed;
      },
      busy() {
        return !1;
      }
    };
  }
  function ge(_) {
    const P = _[D];
    P?.destroyed === !1 && (_[d] === 0 && _[G] === 0 ? (P.unref(), _[M].unref()) : (P.ref(), _[M].ref()));
  }
  function ae(_) {
    e(_.code !== "ERR_TLS_CERT_ALTNAME_INVALID"), this[D][w] = _, this[B][U](_);
  }
  function he(_, P, Z) {
    if (Z === 0) {
      const se = new c(`HTTP/2: "frameError" received - type ${_}, code ${P}`);
      this[D][w] = se, this[B][U](se);
    }
  }
  function Be() {
    const _ = new n("other side closed", t.getSocketInfo(this[D]));
    this.destroy(_), t.destroy(this[D], _);
  }
  function Qe(_) {
    const P = this[w] || new n(`HTTP/2: "GOAWAY" frame received with code ${_}`, t.getSocketInfo(this)), Z = this[B];
    if (Z[D] = null, Z[l] = null, this[M] != null && (this[M].destroy(P), this[M] = null), t.destroy(this[D], P), Z[C] < Z[h].length) {
      const se = Z[h][Z[C]];
      Z[h][Z[C]++] = null, t.errorRequest(Z, se, P), Z[u] = Z[C];
    }
    e(Z[i] === 0), Z.emit("disconnect", Z[g], [Z], P), Z[N]();
  }
  function ye(_) {
    return _ !== "GET" && _ !== "HEAD" && _ !== "OPTIONS" && _ !== "TRACE" && _ !== "CONNECT";
  }
  function we(_, P) {
    const Z = _[M], { method: se, path: le, host: ne, upgrade: fe, expectContinue: Me, signal: pe, headers: Le } = P;
    let { body: ke } = P;
    if (fe)
      return t.errorRequest(_, P, new Error("Upgrade not supported for H2")), !1;
    const be = {};
    for (let Ee = 0; Ee < Le.length; Ee += 2) {
      const Ie = Le[Ee + 0], De = Le[Ee + 1];
      if (Array.isArray(De))
        for (let ve = 0; ve < De.length; ve++)
          be[Ie] ? be[Ie] += `,${De[ve]}` : be[Ie] = De[ve];
      else
        be[Ie] = De;
    }
    let de;
    const { hostname: _e, port: Pe } = _[g];
    be[I] = ne || `${_e}${Pe ? `:${Pe}` : ""}`, be[m] = se;
    const Je = (Ee) => {
      P.aborted || P.completed || (Ee = Ee || new A(), t.errorRequest(_, P, Ee), de != null && t.destroy(de, Ee), t.destroy(ke, Ee), _[h][_[C]++] = null, _[N]());
    };
    try {
      P.onConnect(Je);
    } catch (Ee) {
      t.errorRequest(_, P, Ee);
    }
    if (P.aborted)
      return !1;
    if (se === "CONNECT")
      return Z.ref(), de = Z.request(be, { endStream: !1, signal: pe }), de.id && !de.pending ? (P.onUpgrade(null, null, de), ++Z[p], _[h][_[C]++] = null) : de.once("ready", () => {
        P.onUpgrade(null, null, de), ++Z[p], _[h][_[C]++] = null;
      }), de.once("close", () => {
        Z[p] -= 1, Z[p] === 0 && Z.unref();
      }), !0;
    be[y] = le, be[S] = "https";
    const X = se === "PUT" || se === "POST" || se === "PATCH";
    ke && typeof ke.read == "function" && ke.read(0);
    let R = t.bodyLength(ke);
    if (t.isFormDataLike(ke)) {
      s ??= SA().extractBody;
      const [Ee, Ie] = s(ke);
      be["content-type"] = Ie, ke = Ee.stream, R = Ee.length;
    }
    if (R == null && (R = P.contentLength), (R === 0 || !X) && (R = null), ye(se) && R > 0 && P.contentLength != null && P.contentLength !== R) {
      if (_[b])
        return t.errorRequest(_, P, new o()), !1;
      process.emitWarning(new o());
    }
    R != null && (e(ke, "no body must not have content length"), be[T] = `${R}`), Z.ref();
    const q = se === "GET" || se === "HEAD" || ke === null;
    return Me ? (be[L] = "100-continue", de = Z.request(be, { endStream: q, signal: pe }), de.once("continue", ie)) : (de = Z.request(be, {
      endStream: q,
      signal: pe
    }), ie()), ++Z[p], de.once("response", (Ee) => {
      const { [v]: Ie, ...De } = Ee;
      if (P.onResponseStarted(), P.aborted) {
        const ve = new A();
        t.errorRequest(_, P, ve), t.destroy(de, ve);
        return;
      }
      P.onHeaders(Number(Ie), $(De), de.resume.bind(de), "") === !1 && de.pause(), de.on("data", (ve) => {
        P.onData(ve) === !1 && de.pause();
      });
    }), de.once("end", () => {
      (de.state?.state == null || de.state.state < 6) && P.onComplete([]), Z[p] === 0 && Z.unref(), Je(new c("HTTP/2: stream half-closed (remote)")), _[h][_[C]++] = null, _[u] = _[C], _[N]();
    }), de.once("close", () => {
      Z[p] -= 1, Z[p] === 0 && Z.unref();
    }), de.once("error", function(Ee) {
      Je(Ee);
    }), de.once("frameError", (Ee, Ie) => {
      Je(new c(`HTTP/2: "frameError" received - type ${Ee}, code ${Ie}`));
    }), !0;
    function ie() {
      !ke || R === 0 ? j(
        Je,
        de,
        null,
        _,
        P,
        _[D],
        R,
        X
      ) : t.isBuffer(ke) ? j(
        Je,
        de,
        ke,
        _,
        P,
        _[D],
        R,
        X
      ) : t.isBlobLike(ke) ? typeof ke.stream == "function" ? J(
        Je,
        de,
        ke.stream(),
        _,
        P,
        _[D],
        R,
        X
      ) : re(
        Je,
        de,
        ke,
        _,
        P,
        _[D],
        R,
        X
      ) : t.isStream(ke) ? W(
        Je,
        _[D],
        X,
        de,
        ke,
        _,
        P,
        R
      ) : t.isIterable(ke) ? J(
        Je,
        de,
        ke,
        _,
        P,
        _[D],
        R,
        X
      ) : e(!1);
    }
  }
  function j(_, P, Z, se, le, ne, fe, Me) {
    try {
      Z != null && t.isBuffer(Z) && (e(fe === Z.byteLength, "buffer body must have content length"), P.cork(), P.write(Z), P.uncork(), P.end(), le.onBodySent(Z)), Me || (ne[Q] = !0), le.onRequestSent(), se[N]();
    } catch (pe) {
      _(pe);
    }
  }
  function W(_, P, Z, se, le, ne, fe, Me) {
    e(Me !== 0 || ne[i] === 0, "stream body cannot be pipelined");
    const pe = r(
      le,
      se,
      (ke) => {
        ke ? (t.destroy(pe, ke), _(ke)) : (t.removeAllListeners(pe), fe.onRequestSent(), Z || (P[Q] = !0), ne[N]());
      }
    );
    t.addListener(pe, "data", Le);
    function Le(ke) {
      fe.onBodySent(ke);
    }
  }
  async function re(_, P, Z, se, le, ne, fe, Me) {
    e(fe === Z.size, "blob body must have content length");
    try {
      if (fe != null && fe !== Z.size)
        throw new o();
      const pe = Buffer.from(await Z.arrayBuffer());
      P.cork(), P.write(pe), P.uncork(), P.end(), le.onBodySent(pe), le.onRequestSent(), Me || (ne[Q] = !0), se[N]();
    } catch (pe) {
      _(pe);
    }
  }
  async function J(_, P, Z, se, le, ne, fe, Me) {
    e(fe !== 0 || se[i] === 0, "iterator body cannot be pipelined");
    let pe = null;
    function Le() {
      if (pe) {
        const be = pe;
        pe = null, be();
      }
    }
    const ke = () => new Promise((be, de) => {
      e(pe === null), ne[w] ? de(ne[w]) : pe = be;
    });
    P.on("close", Le).on("drain", Le);
    try {
      for await (const be of Z) {
        if (ne[w])
          throw ne[w];
        const de = P.write(be);
        le.onBodySent(be), de || await ke();
      }
      P.end(), le.onRequestSent(), Me || (ne[Q] = !0), se[N]();
    } catch (be) {
      _(be);
    } finally {
      P.off("close", Le).off("drain", Le);
    }
  }
  return Mt = oe, Mt;
}
var Lt, Zs;
function ss() {
  if (Zs) return Lt;
  Zs = 1;
  const e = Ue(), { kBodyUsed: r } = Oe(), t = He, { InvalidArgumentError: o } = Ye(), A = kA, n = [300, 301, 302, 303, 307, 308], c = /* @__PURE__ */ Symbol("body");
  class g {
    constructor(u) {
      this[c] = u, this[r] = !1;
    }
    async *[Symbol.asyncIterator]() {
      t(!this[r], "disturbed"), this[r] = !0, yield* this[c];
    }
  }
  class Q {
    constructor(u, C, w, D) {
      if (C != null && (!Number.isInteger(C) || C < 0))
        throw new o("maxRedirections must be a positive number");
      e.validateHandler(D, w.method, w.upgrade), this.dispatch = u, this.location = null, this.abort = null, this.opts = { ...w, maxRedirections: 0 }, this.maxRedirections = C, this.handler = D, this.history = [], this.redirectionLimitReached = !1, e.isStream(this.opts.body) ? (e.bodyLength(this.opts.body) === 0 && this.opts.body.on("data", function() {
        t(!1);
      }), typeof this.opts.body.readableDidRead != "boolean" && (this.opts.body[r] = !1, A.prototype.on.call(this.opts.body, "data", function() {
        this[r] = !0;
      }))) : this.opts.body && typeof this.opts.body.pipeTo == "function" ? this.opts.body = new g(this.opts.body) : this.opts.body && typeof this.opts.body != "string" && !ArrayBuffer.isView(this.opts.body) && e.isIterable(this.opts.body) && (this.opts.body = new g(this.opts.body));
    }
    onConnect(u) {
      this.abort = u, this.handler.onConnect(u, { history: this.history });
    }
    onUpgrade(u, C, w) {
      this.handler.onUpgrade(u, C, w);
    }
    onError(u) {
      this.handler.onError(u);
    }
    onHeaders(u, C, w, D) {
      if (this.location = this.history.length >= this.maxRedirections || e.isDisturbed(this.opts.body) ? null : B(u, C), this.opts.throwOnMaxRedirect && this.history.length >= this.maxRedirections) {
        this.request && this.request.abort(new Error("max redirects")), this.redirectionLimitReached = !0, this.abort(new Error("max redirects"));
        return;
      }
      if (this.opts.origin && this.history.push(new URL(this.opts.path, this.opts.origin)), !this.location)
        return this.handler.onHeaders(u, C, w, D);
      const { origin: b, pathname: U, search: G } = e.parseURL(new URL(this.location, this.opts.origin && new URL(this.opts.path, this.opts.origin))), M = G ? `${U}${G}` : U;
      this.opts.headers = a(this.opts.headers, u === 303, this.opts.origin !== b), this.opts.path = M, this.opts.origin = b, this.opts.maxRedirections = 0, this.opts.query = null, u === 303 && this.opts.method !== "HEAD" && (this.opts.method = "GET", this.opts.body = null);
    }
    onData(u) {
      if (!this.location) return this.handler.onData(u);
    }
    onComplete(u) {
      this.location ? (this.location = null, this.abort = null, this.dispatch(this.opts, this)) : this.handler.onComplete(u);
    }
    onBodySent(u) {
      this.handler.onBodySent && this.handler.onBodySent(u);
    }
  }
  function B(h, u) {
    if (n.indexOf(h) === -1)
      return null;
    for (let C = 0; C < u.length; C += 2)
      if (u[C].length === 8 && e.headerNameToString(u[C]) === "location")
        return u[C + 1];
  }
  function i(h, u, C) {
    if (h.length === 4)
      return e.headerNameToString(h) === "host";
    if (u && e.headerNameToString(h).startsWith("content-"))
      return !0;
    if (C && (h.length === 13 || h.length === 6 || h.length === 19)) {
      const w = e.headerNameToString(h);
      return w === "authorization" || w === "cookie" || w === "proxy-authorization";
    }
    return !1;
  }
  function a(h, u, C) {
    const w = [];
    if (Array.isArray(h))
      for (let D = 0; D < h.length; D += 2)
        i(h[D], u, C) || w.push(h[D], h[D + 1]);
    else if (h && typeof h == "object")
      for (const D of Object.keys(h))
        i(D, u, C) || w.push(D, h[D]);
    else
      t(h == null, "headers must be an object or an array");
    return w;
  }
  return Lt = Q, Lt;
}
var Gt, Ks;
function os() {
  if (Ks) return Gt;
  Ks = 1;
  const e = ss();
  function r({ maxRedirections: t }) {
    return (o) => function(n, c) {
      const { maxRedirections: g = t } = n;
      if (!g)
        return o(n, c);
      const Q = new e(o, g, n, c);
      return n = { ...n, maxRedirections: 0 }, o(n, Q);
    };
  }
  return Gt = r, Gt;
}
var vt, Xs;
function UA() {
  if (Xs) return vt;
  Xs = 1;
  const e = He, r = WA, t = qA, o = Ue(), { channels: A } = FA(), n = zi(), c = TA(), {
    InvalidArgumentError: g,
    InformationalError: Q,
    ClientDestroyedError: B
  } = Ye(), i = ZA(), {
    kUrl: a,
    kServerName: h,
    kClient: u,
    kBusy: C,
    kConnect: w,
    kResuming: D,
    kRunning: b,
    kPending: U,
    kSize: G,
    kQueue: M,
    kConnected: N,
    kConnecting: d,
    kNeedDrain: l,
    kKeepAliveDefaultTimeout: p,
    kHostHeader: s,
    kPendingIdx: E,
    kRunningIdx: f,
    kError: I,
    kPipelining: m,
    kKeepAliveTimeoutValue: y,
    kMaxHeadersSize: S,
    kKeepAliveMaxTimeout: T,
    kKeepAliveTimeoutThreshold: L,
    kHeadersTimeout: v,
    kBodyTimeout: $,
    kStrictContentLength: oe,
    kConnector: ge,
    kMaxRedirections: ae,
    kMaxRequests: he,
    kCounter: Be,
    kClose: Qe,
    kDestroy: ye,
    kDispatch: we,
    kInterceptors: j,
    kLocalAddress: W,
    kMaxResponseSize: re,
    kOnError: J,
    kHTTPContext: _,
    kMaxConcurrentStreams: P,
    kResume: Z
  } = Oe(), se = $i(), le = ea();
  let ne = !1;
  const fe = /* @__PURE__ */ Symbol("kClosedResolve"), Me = () => {
  };
  function pe(X) {
    return X[m] ?? X[_]?.defaultPipelining ?? 1;
  }
  class Le extends c {
    /**
     *
     * @param {string|URL} url
     * @param {import('../../types/client.js').Client.Options} options
     */
    constructor(R, {
      interceptors: q,
      maxHeaderSize: ie,
      headersTimeout: Ee,
      socketTimeout: Ie,
      requestTimeout: De,
      connectTimeout: ve,
      bodyTimeout: qe,
      idleTimeout: Ze,
      keepAlive: Ce,
      keepAliveTimeout: Y,
      maxKeepAliveTimeout: ee,
      keepAliveMaxTimeout: K,
      keepAliveTimeoutThreshold: Ae,
      socketPath: ue,
      pipelining: Re,
      tls: Se,
      strictContentLength: F,
      maxCachedSessions: O,
      maxRedirections: k,
      connect: V,
      maxRequestsPerClient: H,
      localAddress: x,
      maxResponseSize: te,
      autoSelectFamily: z,
      autoSelectFamilyAttemptTimeout: ce,
      // h2
      maxConcurrentStreams: Fe,
      allowH2: Ge
    } = {}) {
      if (super(), Ce !== void 0)
        throw new g("unsupported keepAlive, use pipelining=0 instead");
      if (Ie !== void 0)
        throw new g("unsupported socketTimeout, use headersTimeout & bodyTimeout instead");
      if (De !== void 0)
        throw new g("unsupported requestTimeout, use headersTimeout & bodyTimeout instead");
      if (Ze !== void 0)
        throw new g("unsupported idleTimeout, use keepAliveTimeout instead");
      if (ee !== void 0)
        throw new g("unsupported maxKeepAliveTimeout, use keepAliveMaxTimeout instead");
      if (ie != null && !Number.isFinite(ie))
        throw new g("invalid maxHeaderSize");
      if (ue != null && typeof ue != "string")
        throw new g("invalid socketPath");
      if (ve != null && (!Number.isFinite(ve) || ve < 0))
        throw new g("invalid connectTimeout");
      if (Y != null && (!Number.isFinite(Y) || Y <= 0))
        throw new g("invalid keepAliveTimeout");
      if (K != null && (!Number.isFinite(K) || K <= 0))
        throw new g("invalid keepAliveMaxTimeout");
      if (Ae != null && !Number.isFinite(Ae))
        throw new g("invalid keepAliveTimeoutThreshold");
      if (Ee != null && (!Number.isInteger(Ee) || Ee < 0))
        throw new g("headersTimeout must be a positive integer or zero");
      if (qe != null && (!Number.isInteger(qe) || qe < 0))
        throw new g("bodyTimeout must be a positive integer or zero");
      if (V != null && typeof V != "function" && typeof V != "object")
        throw new g("connect must be a function or an object");
      if (k != null && (!Number.isInteger(k) || k < 0))
        throw new g("maxRedirections must be a positive number");
      if (H != null && (!Number.isInteger(H) || H < 0))
        throw new g("maxRequestsPerClient must be a positive number");
      if (x != null && (typeof x != "string" || r.isIP(x) === 0))
        throw new g("localAddress must be valid string IP address");
      if (te != null && (!Number.isInteger(te) || te < -1))
        throw new g("maxResponseSize must be a positive number");
      if (ce != null && (!Number.isInteger(ce) || ce < -1))
        throw new g("autoSelectFamilyAttemptTimeout must be a positive number");
      if (Ge != null && typeof Ge != "boolean")
        throw new g("allowH2 must be a valid boolean value");
      if (Fe != null && (typeof Fe != "number" || Fe < 1))
        throw new g("maxConcurrentStreams must be a positive integer, greater than 0");
      typeof V != "function" && (V = i({
        ...Se,
        maxCachedSessions: O,
        allowH2: Ge,
        socketPath: ue,
        timeout: ve,
        ...z ? { autoSelectFamily: z, autoSelectFamilyAttemptTimeout: ce } : void 0,
        ...V
      })), q?.Client && Array.isArray(q.Client) ? (this[j] = q.Client, ne || (ne = !0, process.emitWarning("Client.Options#interceptor is deprecated. Use Dispatcher#compose instead.", {
        code: "UNDICI-CLIENT-INTERCEPTOR-DEPRECATED"
      }))) : this[j] = [ke({ maxRedirections: k })], this[a] = o.parseOrigin(R), this[ge] = V, this[m] = Re ?? 1, this[S] = ie || t.maxHeaderSize, this[p] = Y ?? 4e3, this[T] = K ?? 6e5, this[L] = Ae ?? 2e3, this[y] = this[p], this[h] = null, this[W] = x ?? null, this[D] = 0, this[l] = 0, this[s] = `host: ${this[a].hostname}${this[a].port ? `:${this[a].port}` : ""}\r
`, this[$] = qe ?? 3e5, this[v] = Ee ?? 3e5, this[oe] = F ?? !0, this[ae] = k, this[he] = H, this[fe] = null, this[re] = te > -1 ? te : -1, this[P] = Fe ?? 100, this[_] = null, this[M] = [], this[f] = 0, this[E] = 0, this[Z] = (Ne) => Pe(this, Ne), this[J] = (Ne) => be(this, Ne);
    }
    get pipelining() {
      return this[m];
    }
    set pipelining(R) {
      this[m] = R, this[Z](!0);
    }
    get [U]() {
      return this[M].length - this[E];
    }
    get [b]() {
      return this[E] - this[f];
    }
    get [G]() {
      return this[M].length - this[f];
    }
    get [N]() {
      return !!this[_] && !this[d] && !this[_].destroyed;
    }
    get [C]() {
      return !!(this[_]?.busy(null) || this[G] >= (pe(this) || 1) || this[U] > 0);
    }
    /* istanbul ignore: only used for test */
    [w](R) {
      de(this), this.once("connect", R);
    }
    [we](R, q) {
      const ie = R.origin || this[a].origin, Ee = new n(ie, R, q);
      return this[M].push(Ee), this[D] || (o.bodyLength(Ee.body) == null && o.isIterable(Ee.body) ? (this[D] = 1, queueMicrotask(() => Pe(this))) : this[Z](!0)), this[D] && this[l] !== 2 && this[C] && (this[l] = 2), this[l] < 2;
    }
    async [Qe]() {
      return new Promise((R) => {
        this[G] ? this[fe] = R : R(null);
      });
    }
    async [ye](R) {
      return new Promise((q) => {
        const ie = this[M].splice(this[E]);
        for (let Ie = 0; Ie < ie.length; Ie++) {
          const De = ie[Ie];
          o.errorRequest(this, De, R);
        }
        const Ee = () => {
          this[fe] && (this[fe](), this[fe] = null), q(null);
        };
        this[_] ? (this[_].destroy(R, Ee), this[_] = null) : queueMicrotask(Ee), this[Z]();
      });
    }
  }
  const ke = os();
  function be(X, R) {
    if (X[b] === 0 && R.code !== "UND_ERR_INFO" && R.code !== "UND_ERR_SOCKET") {
      e(X[E] === X[f]);
      const q = X[M].splice(X[f]);
      for (let ie = 0; ie < q.length; ie++) {
        const Ee = q[ie];
        o.errorRequest(X, Ee, R);
      }
      e(X[G] === 0);
    }
  }
  async function de(X) {
    e(!X[d]), e(!X[_]);
    let { host: R, hostname: q, protocol: ie, port: Ee } = X[a];
    if (q[0] === "[") {
      const Ie = q.indexOf("]");
      e(Ie !== -1);
      const De = q.substring(1, Ie);
      e(r.isIP(De)), q = De;
    }
    X[d] = !0, A.beforeConnect.hasSubscribers && A.beforeConnect.publish({
      connectParams: {
        host: R,
        hostname: q,
        protocol: ie,
        port: Ee,
        version: X[_]?.version,
        servername: X[h],
        localAddress: X[W]
      },
      connector: X[ge]
    });
    try {
      const Ie = await new Promise((De, ve) => {
        X[ge]({
          host: R,
          hostname: q,
          protocol: ie,
          port: Ee,
          servername: X[h],
          localAddress: X[W]
        }, (qe, Ze) => {
          qe ? ve(qe) : De(Ze);
        });
      });
      if (X.destroyed) {
        o.destroy(Ie.on("error", Me), new B());
        return;
      }
      e(Ie);
      try {
        X[_] = Ie.alpnProtocol === "h2" ? await le(X, Ie) : await se(X, Ie);
      } catch (De) {
        throw Ie.destroy().on("error", Me), De;
      }
      X[d] = !1, Ie[Be] = 0, Ie[he] = X[he], Ie[u] = X, Ie[I] = null, A.connected.hasSubscribers && A.connected.publish({
        connectParams: {
          host: R,
          hostname: q,
          protocol: ie,
          port: Ee,
          version: X[_]?.version,
          servername: X[h],
          localAddress: X[W]
        },
        connector: X[ge],
        socket: Ie
      }), X.emit("connect", X[a], [X]);
    } catch (Ie) {
      if (X.destroyed)
        return;
      if (X[d] = !1, A.connectError.hasSubscribers && A.connectError.publish({
        connectParams: {
          host: R,
          hostname: q,
          protocol: ie,
          port: Ee,
          version: X[_]?.version,
          servername: X[h],
          localAddress: X[W]
        },
        connector: X[ge],
        error: Ie
      }), Ie.code === "ERR_TLS_CERT_ALTNAME_INVALID")
        for (e(X[b] === 0); X[U] > 0 && X[M][X[E]].servername === X[h]; ) {
          const De = X[M][X[E]++];
          o.errorRequest(X, De, Ie);
        }
      else
        be(X, Ie);
      X.emit("connectionError", X[a], [X], Ie);
    }
    X[Z]();
  }
  function _e(X) {
    X[l] = 0, X.emit("drain", X[a], [X]);
  }
  function Pe(X, R) {
    X[D] !== 2 && (X[D] = 2, Je(X, R), X[D] = 0, X[f] > 256 && (X[M].splice(0, X[f]), X[E] -= X[f], X[f] = 0));
  }
  function Je(X, R) {
    for (; ; ) {
      if (X.destroyed) {
        e(X[U] === 0);
        return;
      }
      if (X[fe] && !X[G]) {
        X[fe](), X[fe] = null;
        return;
      }
      if (X[_] && X[_].resume(), X[C])
        X[l] = 2;
      else if (X[l] === 2) {
        R ? (X[l] = 1, queueMicrotask(() => _e(X))) : _e(X);
        continue;
      }
      if (X[U] === 0 || X[b] >= (pe(X) || 1))
        return;
      const q = X[M][X[E]];
      if (X[a].protocol === "https:" && X[h] !== q.servername) {
        if (X[b] > 0)
          return;
        X[h] = q.servername, X[_]?.destroy(new Q("servername changed"), () => {
          X[_] = null, Pe(X);
        });
      }
      if (X[d])
        return;
      if (!X[_]) {
        de(X);
        return;
      }
      if (X[_].destroyed || X[_].busy(q))
        return;
      !q.aborted && X[_].write(q) ? X[E]++ : X[M].splice(X[E], 1);
    }
  }
  return vt = Le, vt;
}
var Yt, js;
function zn() {
  if (js) return Yt;
  js = 1;
  const e = 2048, r = e - 1;
  class t {
    constructor() {
      this.bottom = 0, this.top = 0, this.list = new Array(e), this.next = null;
    }
    isEmpty() {
      return this.top === this.bottom;
    }
    isFull() {
      return (this.top + 1 & r) === this.bottom;
    }
    push(A) {
      this.list[this.top] = A, this.top = this.top + 1 & r;
    }
    shift() {
      const A = this.list[this.bottom];
      return A === void 0 ? null : (this.list[this.bottom] = void 0, this.bottom = this.bottom + 1 & r, A);
    }
  }
  return Yt = class {
    constructor() {
      this.head = this.tail = new t();
    }
    isEmpty() {
      return this.head.isEmpty();
    }
    push(A) {
      this.head.isFull() && (this.head = this.head.next = new t()), this.head.push(A);
    }
    shift() {
      const A = this.tail, n = A.shift();
      return A.isEmpty() && A.next !== null && (this.tail = A.next), n;
    }
  }, Yt;
}
var Jt, $s;
function Aa() {
  if ($s) return Jt;
  $s = 1;
  const { kFree: e, kConnected: r, kPending: t, kQueued: o, kRunning: A, kSize: n } = Oe(), c = /* @__PURE__ */ Symbol("pool");
  class g {
    constructor(B) {
      this[c] = B;
    }
    get connected() {
      return this[c][r];
    }
    get free() {
      return this[c][e];
    }
    get pending() {
      return this[c][t];
    }
    get queued() {
      return this[c][o];
    }
    get running() {
      return this[c][A];
    }
    get size() {
      return this[c][n];
    }
  }
  return Jt = g, Jt;
}
var Ht, eo;
function Zn() {
  if (eo) return Ht;
  eo = 1;
  const e = TA(), r = zn(), { kConnected: t, kSize: o, kRunning: A, kPending: n, kQueued: c, kBusy: g, kFree: Q, kUrl: B, kClose: i, kDestroy: a, kDispatch: h } = Oe(), u = Aa(), C = /* @__PURE__ */ Symbol("clients"), w = /* @__PURE__ */ Symbol("needDrain"), D = /* @__PURE__ */ Symbol("queue"), b = /* @__PURE__ */ Symbol("closed resolve"), U = /* @__PURE__ */ Symbol("onDrain"), G = /* @__PURE__ */ Symbol("onConnect"), M = /* @__PURE__ */ Symbol("onDisconnect"), N = /* @__PURE__ */ Symbol("onConnectionError"), d = /* @__PURE__ */ Symbol("get dispatcher"), l = /* @__PURE__ */ Symbol("add client"), p = /* @__PURE__ */ Symbol("remove client"), s = /* @__PURE__ */ Symbol("stats");
  class E extends e {
    constructor() {
      super(), this[D] = new r(), this[C] = [], this[c] = 0;
      const I = this;
      this[U] = function(y, S) {
        const T = I[D];
        let L = !1;
        for (; !L; ) {
          const v = T.shift();
          if (!v)
            break;
          I[c]--, L = !this.dispatch(v.opts, v.handler);
        }
        this[w] = L, !this[w] && I[w] && (I[w] = !1, I.emit("drain", y, [I, ...S])), I[b] && T.isEmpty() && Promise.all(I[C].map((v) => v.close())).then(I[b]);
      }, this[G] = (m, y) => {
        I.emit("connect", m, [I, ...y]);
      }, this[M] = (m, y, S) => {
        I.emit("disconnect", m, [I, ...y], S);
      }, this[N] = (m, y, S) => {
        I.emit("connectionError", m, [I, ...y], S);
      }, this[s] = new u(this);
    }
    get [g]() {
      return this[w];
    }
    get [t]() {
      return this[C].filter((I) => I[t]).length;
    }
    get [Q]() {
      return this[C].filter((I) => I[t] && !I[w]).length;
    }
    get [n]() {
      let I = this[c];
      for (const { [n]: m } of this[C])
        I += m;
      return I;
    }
    get [A]() {
      let I = 0;
      for (const { [A]: m } of this[C])
        I += m;
      return I;
    }
    get [o]() {
      let I = this[c];
      for (const { [o]: m } of this[C])
        I += m;
      return I;
    }
    get stats() {
      return this[s];
    }
    async [i]() {
      this[D].isEmpty() ? await Promise.all(this[C].map((I) => I.close())) : await new Promise((I) => {
        this[b] = I;
      });
    }
    async [a](I) {
      for (; ; ) {
        const m = this[D].shift();
        if (!m)
          break;
        m.handler.onError(I);
      }
      await Promise.all(this[C].map((m) => m.destroy(I)));
    }
    [h](I, m) {
      const y = this[d]();
      return y ? y.dispatch(I, m) || (y[w] = !0, this[w] = !this[d]()) : (this[w] = !0, this[D].push({ opts: I, handler: m }), this[c]++), !this[w];
    }
    [l](I) {
      return I.on("drain", this[U]).on("connect", this[G]).on("disconnect", this[M]).on("connectionError", this[N]), this[C].push(I), this[w] && queueMicrotask(() => {
        this[w] && this[U](I[B], [this, I]);
      }), this;
    }
    [p](I) {
      I.close(() => {
        const m = this[C].indexOf(I);
        m !== -1 && this[C].splice(m, 1);
      }), this[w] = this[C].some((m) => !m[w] && m.closed !== !0 && m.destroyed !== !0);
    }
  }
  return Ht = {
    PoolBase: E,
    kClients: C,
    kNeedDrain: w,
    kAddClient: l,
    kRemoveClient: p,
    kGetDispatcher: d
  }, Ht;
}
var Vt, Ao;
function NA() {
  if (Ao) return Vt;
  Ao = 1;
  const {
    PoolBase: e,
    kClients: r,
    kNeedDrain: t,
    kAddClient: o,
    kGetDispatcher: A
  } = Zn(), n = UA(), {
    InvalidArgumentError: c
  } = Ye(), g = Ue(), { kUrl: Q, kInterceptors: B } = Oe(), i = ZA(), a = /* @__PURE__ */ Symbol("options"), h = /* @__PURE__ */ Symbol("connections"), u = /* @__PURE__ */ Symbol("factory");
  function C(D, b) {
    return new n(D, b);
  }
  class w extends e {
    constructor(b, {
      connections: U,
      factory: G = C,
      connect: M,
      connectTimeout: N,
      tls: d,
      maxCachedSessions: l,
      socketPath: p,
      autoSelectFamily: s,
      autoSelectFamilyAttemptTimeout: E,
      allowH2: f,
      ...I
    } = {}) {
      if (super(), U != null && (!Number.isFinite(U) || U < 0))
        throw new c("invalid connections");
      if (typeof G != "function")
        throw new c("factory must be a function.");
      if (M != null && typeof M != "function" && typeof M != "object")
        throw new c("connect must be a function or an object");
      typeof M != "function" && (M = i({
        ...d,
        maxCachedSessions: l,
        allowH2: f,
        socketPath: p,
        timeout: N,
        ...s ? { autoSelectFamily: s, autoSelectFamilyAttemptTimeout: E } : void 0,
        ...M
      })), this[B] = I.interceptors?.Pool && Array.isArray(I.interceptors.Pool) ? I.interceptors.Pool : [], this[h] = U || null, this[Q] = g.parseOrigin(b), this[a] = { ...g.deepClone(I), connect: M, allowH2: f }, this[a].interceptors = I.interceptors ? { ...I.interceptors } : void 0, this[u] = G, this.on("connectionError", (m, y, S) => {
        for (const T of y) {
          const L = this[r].indexOf(T);
          L !== -1 && this[r].splice(L, 1);
        }
      });
    }
    [A]() {
      for (const b of this[r])
        if (!b[t])
          return b;
      if (!this[h] || this[r].length < this[h]) {
        const b = this[u](this[Q], this[a]);
        return this[o](b), b;
      }
    }
  }
  return Vt = w, Vt;
}
var Pt, to;
function ta() {
  if (to) return Pt;
  to = 1;
  const {
    BalancedPoolMissingUpstreamError: e,
    InvalidArgumentError: r
  } = Ye(), {
    PoolBase: t,
    kClients: o,
    kNeedDrain: A,
    kAddClient: n,
    kRemoveClient: c,
    kGetDispatcher: g
  } = Zn(), Q = NA(), { kUrl: B, kInterceptors: i } = Oe(), { parseOrigin: a } = Ue(), h = /* @__PURE__ */ Symbol("factory"), u = /* @__PURE__ */ Symbol("options"), C = /* @__PURE__ */ Symbol("kGreatestCommonDivisor"), w = /* @__PURE__ */ Symbol("kCurrentWeight"), D = /* @__PURE__ */ Symbol("kIndex"), b = /* @__PURE__ */ Symbol("kWeight"), U = /* @__PURE__ */ Symbol("kMaxWeightPerServer"), G = /* @__PURE__ */ Symbol("kErrorPenalty");
  function M(l, p) {
    if (l === 0) return p;
    for (; p !== 0; ) {
      const s = p;
      p = l % p, l = s;
    }
    return l;
  }
  function N(l, p) {
    return new Q(l, p);
  }
  class d extends t {
    constructor(p = [], { factory: s = N, ...E } = {}) {
      if (super(), this[u] = E, this[D] = -1, this[w] = 0, this[U] = this[u].maxWeightPerServer || 100, this[G] = this[u].errorPenalty || 15, Array.isArray(p) || (p = [p]), typeof s != "function")
        throw new r("factory must be a function.");
      this[i] = E.interceptors?.BalancedPool && Array.isArray(E.interceptors.BalancedPool) ? E.interceptors.BalancedPool : [], this[h] = s;
      for (const f of p)
        this.addUpstream(f);
      this._updateBalancedPoolStats();
    }
    addUpstream(p) {
      const s = a(p).origin;
      if (this[o].find((f) => f[B].origin === s && f.closed !== !0 && f.destroyed !== !0))
        return this;
      const E = this[h](s, Object.assign({}, this[u]));
      this[n](E), E.on("connect", () => {
        E[b] = Math.min(this[U], E[b] + this[G]);
      }), E.on("connectionError", () => {
        E[b] = Math.max(1, E[b] - this[G]), this._updateBalancedPoolStats();
      }), E.on("disconnect", (...f) => {
        const I = f[2];
        I && I.code === "UND_ERR_SOCKET" && (E[b] = Math.max(1, E[b] - this[G]), this._updateBalancedPoolStats());
      });
      for (const f of this[o])
        f[b] = this[U];
      return this._updateBalancedPoolStats(), this;
    }
    _updateBalancedPoolStats() {
      let p = 0;
      for (let s = 0; s < this[o].length; s++)
        p = M(this[o][s][b], p);
      this[C] = p;
    }
    removeUpstream(p) {
      const s = a(p).origin, E = this[o].find((f) => f[B].origin === s && f.closed !== !0 && f.destroyed !== !0);
      return E && this[c](E), this;
    }
    get upstreams() {
      return this[o].filter((p) => p.closed !== !0 && p.destroyed !== !0).map((p) => p[B].origin);
    }
    [g]() {
      if (this[o].length === 0)
        throw new e();
      if (!this[o].find((I) => !I[A] && I.closed !== !0 && I.destroyed !== !0) || this[o].map((I) => I[A]).reduce((I, m) => I && m, !0))
        return;
      let E = 0, f = this[o].findIndex((I) => !I[A]);
      for (; E++ < this[o].length; ) {
        this[D] = (this[D] + 1) % this[o].length;
        const I = this[o][this[D]];
        if (I[b] > this[o][f][b] && !I[A] && (f = this[D]), this[D] === 0 && (this[w] = this[w] - this[C], this[w] <= 0 && (this[w] = this[U])), I[b] >= this[w] && !I[A])
          return I;
      }
      return this[w] = this[o][f][b], this[D] = f, this[o][f];
    }
  }
  return Pt = d, Pt;
}
var xt, ro;
function MA() {
  if (ro) return xt;
  ro = 1;
  const { InvalidArgumentError: e } = Ye(), { kClients: r, kRunning: t, kClose: o, kDestroy: A, kDispatch: n, kInterceptors: c } = Oe(), g = TA(), Q = NA(), B = UA(), i = Ue(), a = os(), h = /* @__PURE__ */ Symbol("onConnect"), u = /* @__PURE__ */ Symbol("onDisconnect"), C = /* @__PURE__ */ Symbol("onConnectionError"), w = /* @__PURE__ */ Symbol("maxRedirections"), D = /* @__PURE__ */ Symbol("onDrain"), b = /* @__PURE__ */ Symbol("factory"), U = /* @__PURE__ */ Symbol("options");
  function G(N, d) {
    return d && d.connections === 1 ? new B(N, d) : new Q(N, d);
  }
  class M extends g {
    constructor({ factory: d = G, maxRedirections: l = 0, connect: p, ...s } = {}) {
      if (super(), typeof d != "function")
        throw new e("factory must be a function.");
      if (p != null && typeof p != "function" && typeof p != "object")
        throw new e("connect must be a function or an object");
      if (!Number.isInteger(l) || l < 0)
        throw new e("maxRedirections must be a positive number");
      p && typeof p != "function" && (p = { ...p }), this[c] = s.interceptors?.Agent && Array.isArray(s.interceptors.Agent) ? s.interceptors.Agent : [a({ maxRedirections: l })], this[U] = { ...i.deepClone(s), connect: p }, this[U].interceptors = s.interceptors ? { ...s.interceptors } : void 0, this[w] = l, this[b] = d, this[r] = /* @__PURE__ */ new Map(), this[D] = (E, f) => {
        this.emit("drain", E, [this, ...f]);
      }, this[h] = (E, f) => {
        this.emit("connect", E, [this, ...f]);
      }, this[u] = (E, f, I) => {
        this.emit("disconnect", E, [this, ...f], I);
      }, this[C] = (E, f, I) => {
        this.emit("connectionError", E, [this, ...f], I);
      };
    }
    get [t]() {
      let d = 0;
      for (const l of this[r].values())
        d += l[t];
      return d;
    }
    [n](d, l) {
      let p;
      if (d.origin && (typeof d.origin == "string" || d.origin instanceof URL))
        p = String(d.origin);
      else
        throw new e("opts.origin must be a non-empty string or URL.");
      let s = this[r].get(p);
      return s || (s = this[b](d.origin, this[U]).on("drain", this[D]).on("connect", this[h]).on("disconnect", this[u]).on("connectionError", this[C]), this[r].set(p, s)), s.dispatch(d, l);
    }
    async [o]() {
      const d = [];
      for (const l of this[r].values())
        d.push(l.close());
      this[r].clear(), await Promise.all(d);
    }
    async [A](d) {
      const l = [];
      for (const p of this[r].values())
        l.push(p.destroy(d));
      this[r].clear(), await Promise.all(l);
    }
  }
  return xt = M, xt;
}
var Ot, so;
function Kn() {
  if (so) return Ot;
  so = 1;
  const { kProxy: e, kClose: r, kDestroy: t, kDispatch: o, kInterceptors: A } = Oe(), { URL: n } = vi, c = MA(), g = NA(), Q = TA(), { InvalidArgumentError: B, RequestAbortedError: i, SecureProxyConnectionError: a } = Ye(), h = ZA(), u = UA(), C = /* @__PURE__ */ Symbol("proxy agent"), w = /* @__PURE__ */ Symbol("proxy client"), D = /* @__PURE__ */ Symbol("proxy headers"), b = /* @__PURE__ */ Symbol("request tls settings"), U = /* @__PURE__ */ Symbol("proxy tls settings"), G = /* @__PURE__ */ Symbol("connect endpoint function"), M = /* @__PURE__ */ Symbol("tunnel proxy");
  function N(m) {
    return m === "https:" ? 443 : 80;
  }
  function d(m, y) {
    return new g(m, y);
  }
  const l = () => {
  };
  function p(m, y) {
    return y.connections === 1 ? new u(m, y) : new g(m, y);
  }
  class s extends Q {
    #e;
    constructor(y, { headers: S = {}, connect: T, factory: L }) {
      if (super(), !y)
        throw new B("Proxy URL is mandatory");
      this[D] = S, L ? this.#e = L(y, { connect: T }) : this.#e = new u(y, { connect: T });
    }
    [o](y, S) {
      const T = S.onHeaders;
      S.onHeaders = function(oe, ge, ae) {
        if (oe === 407) {
          typeof S.onError == "function" && S.onError(new B("Proxy Authentication Required (407)"));
          return;
        }
        T && T.call(this, oe, ge, ae);
      };
      const {
        origin: L,
        path: v = "/",
        headers: $ = {}
      } = y;
      if (y.path = L + v, !("host" in $) && !("Host" in $)) {
        const { host: oe } = new n(L);
        $.host = oe;
      }
      return y.headers = { ...this[D], ...$ }, this.#e[o](y, S);
    }
    async [r]() {
      return this.#e.close();
    }
    async [t](y) {
      return this.#e.destroy(y);
    }
  }
  class E extends Q {
    constructor(y) {
      if (super(), !y || typeof y == "object" && !(y instanceof n) && !y.uri)
        throw new B("Proxy uri is mandatory");
      const { clientFactory: S = d } = y;
      if (typeof S != "function")
        throw new B("Proxy opts.clientFactory must be a function.");
      const { proxyTunnel: T = !0 } = y, L = this.#e(y), { href: v, origin: $, port: oe, protocol: ge, username: ae, password: he, hostname: Be } = L;
      if (this[e] = { uri: v, protocol: ge }, this[A] = y.interceptors?.ProxyAgent && Array.isArray(y.interceptors.ProxyAgent) ? y.interceptors.ProxyAgent : [], this[b] = y.requestTls, this[U] = y.proxyTls, this[D] = y.headers || {}, this[M] = T, y.auth && y.token)
        throw new B("opts.auth cannot be used in combination with opts.token");
      y.auth ? this[D]["proxy-authorization"] = `Basic ${y.auth}` : y.token ? this[D]["proxy-authorization"] = y.token : ae && he && (this[D]["proxy-authorization"] = `Basic ${Buffer.from(`${decodeURIComponent(ae)}:${decodeURIComponent(he)}`).toString("base64")}`);
      const Qe = h({ ...y.proxyTls });
      this[G] = h({ ...y.requestTls });
      const ye = y.factory || p, we = (j, W) => {
        const { protocol: re } = new n(j);
        return !this[M] && re === "http:" && this[e].protocol === "http:" ? new s(this[e].uri, {
          headers: this[D],
          connect: Qe,
          factory: ye
        }) : ye(j, W);
      };
      this[w] = S(L, { connect: Qe }), this[C] = new c({
        ...y,
        factory: we,
        connect: async (j, W) => {
          let re = j.host;
          j.port || (re += `:${N(j.protocol)}`);
          try {
            const { socket: J, statusCode: _ } = await this[w].connect({
              origin: $,
              port: oe,
              path: re,
              signal: j.signal,
              headers: {
                ...this[D],
                host: j.host
              },
              servername: this[U]?.servername || Be
            });
            if (_ !== 200 && (J.on("error", l).destroy(), W(new i(`Proxy response (${_}) !== 200 when HTTP Tunneling`))), j.protocol !== "https:") {
              W(null, J);
              return;
            }
            let P;
            this[b] ? P = this[b].servername : P = j.servername, this[G]({ ...j, servername: P, httpSocket: J }, W);
          } catch (J) {
            J.code === "ERR_TLS_CERT_ALTNAME_INVALID" ? W(new a(J)) : W(J);
          }
        }
      });
    }
    dispatch(y, S) {
      const T = f(y.headers);
      if (I(T), T && !("host" in T) && !("Host" in T)) {
        const { host: L } = new n(y.origin);
        T.host = L;
      }
      return this[C].dispatch(
        {
          ...y,
          headers: T
        },
        S
      );
    }
    /**
     * @param {import('../types/proxy-agent').ProxyAgent.Options | string | URL} opts
     * @returns {URL}
     */
    #e(y) {
      return typeof y == "string" ? new n(y) : y instanceof n ? y : new n(y.uri);
    }
    async [r]() {
      await this[C].close(), await this[w].close();
    }
    async [t]() {
      await this[C].destroy(), await this[w].destroy();
    }
  }
  function f(m) {
    if (Array.isArray(m)) {
      const y = {};
      for (let S = 0; S < m.length; S += 2)
        y[m[S]] = m[S + 1];
      return y;
    }
    return m;
  }
  function I(m) {
    if (m && Object.keys(m).find((S) => S.toLowerCase() === "proxy-authorization"))
      throw new B("Proxy-Authorization should be sent in ProxyAgent constructor");
  }
  return Ot = E, Ot;
}
var _t, oo;
function ra() {
  if (oo) return _t;
  oo = 1;
  const e = TA(), { kClose: r, kDestroy: t, kClosed: o, kDestroyed: A, kDispatch: n, kNoProxyAgent: c, kHttpProxyAgent: g, kHttpsProxyAgent: Q } = Oe(), B = Kn(), i = MA(), a = {
    "http:": 80,
    "https:": 443
  };
  let h = !1;
  class u extends e {
    #e = null;
    #A = null;
    #s = null;
    constructor(w = {}) {
      super(), this.#s = w, h || (h = !0, process.emitWarning("EnvHttpProxyAgent is experimental, expect them to change at any time.", {
        code: "UNDICI-EHPA"
      }));
      const { httpProxy: D, httpsProxy: b, noProxy: U, ...G } = w;
      this[c] = new i(G);
      const M = D ?? process.env.http_proxy ?? process.env.HTTP_PROXY;
      M ? this[g] = new B({ ...G, uri: M }) : this[g] = this[c];
      const N = b ?? process.env.https_proxy ?? process.env.HTTPS_PROXY;
      N ? this[Q] = new B({ ...G, uri: N }) : this[Q] = this[g], this.#o();
    }
    [n](w, D) {
      const b = new URL(w.origin);
      return this.#r(b).dispatch(w, D);
    }
    async [r]() {
      await this[c].close(), this[g][o] || await this[g].close(), this[Q][o] || await this[Q].close();
    }
    async [t](w) {
      await this[c].destroy(w), this[g][A] || await this[g].destroy(w), this[Q][A] || await this[Q].destroy(w);
    }
    #r(w) {
      let { protocol: D, host: b, port: U } = w;
      return b = b.replace(/:\d*$/, "").toLowerCase(), U = Number.parseInt(U, 10) || a[D] || 0, this.#t(b, U) ? D === "https:" ? this[Q] : this[g] : this[c];
    }
    #t(w, D) {
      if (this.#n && this.#o(), this.#A.length === 0)
        return !0;
      if (this.#e === "*")
        return !1;
      for (let b = 0; b < this.#A.length; b++) {
        const U = this.#A[b];
        if (!(U.port && U.port !== D)) {
          if (/^[.*]/.test(U.hostname)) {
            if (w.endsWith(U.hostname.replace(/^\*/, "")))
              return !1;
          } else if (w === U.hostname)
            return !1;
        }
      }
      return !0;
    }
    #o() {
      const w = this.#s.noProxy ?? this.#i, D = w.split(/[,\s]/), b = [];
      for (let U = 0; U < D.length; U++) {
        const G = D[U];
        if (!G)
          continue;
        const M = G.match(/^(.+):(\d+)$/);
        b.push({
          hostname: (M ? M[1] : G).toLowerCase(),
          port: M ? Number.parseInt(M[2], 10) : 0
        });
      }
      this.#e = w, this.#A = b;
    }
    get #n() {
      return this.#s.noProxy !== void 0 ? !1 : this.#e !== this.#i;
    }
    get #i() {
      return process.env.no_proxy ?? process.env.NO_PROXY ?? "";
    }
  }
  return _t = u, _t;
}
var Wt, no;
function ns() {
  if (no) return Wt;
  no = 1;
  const e = He, { kRetryHandlerDefaultRetry: r } = Oe(), { RequestRetryError: t } = Ye(), {
    isDisturbed: o,
    parseHeaders: A,
    parseRangeHeader: n,
    wrapRequestBody: c
  } = Ue();
  function g(B) {
    const i = Date.now();
    return new Date(B).getTime() - i;
  }
  class Q {
    constructor(i, a) {
      const { retryOptions: h, ...u } = i, {
        // Retry scoped
        retry: C,
        maxRetries: w,
        maxTimeout: D,
        minTimeout: b,
        timeoutFactor: U,
        // Response scoped
        methods: G,
        errorCodes: M,
        retryAfter: N,
        statusCodes: d
      } = h ?? {};
      this.dispatch = a.dispatch, this.handler = a.handler, this.opts = { ...u, body: c(i.body) }, this.abort = null, this.aborted = !1, this.retryOpts = {
        retry: C ?? Q[r],
        retryAfter: N ?? !0,
        maxTimeout: D ?? 30 * 1e3,
        // 30s,
        minTimeout: b ?? 500,
        // .5s
        timeoutFactor: U ?? 2,
        maxRetries: w ?? 5,
        // What errors we should retry
        methods: G ?? ["GET", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE"],
        // Indicates which errors to retry
        statusCodes: d ?? [500, 502, 503, 504, 429],
        // List of errors to retry
        errorCodes: M ?? [
          "ECONNRESET",
          "ECONNREFUSED",
          "ENOTFOUND",
          "ENETDOWN",
          "ENETUNREACH",
          "EHOSTDOWN",
          "EHOSTUNREACH",
          "EPIPE",
          "UND_ERR_SOCKET"
        ]
      }, this.retryCount = 0, this.retryCountCheckpoint = 0, this.start = 0, this.end = null, this.etag = null, this.resume = null, this.handler.onConnect((l) => {
        this.aborted = !0, this.abort ? this.abort(l) : this.reason = l;
      });
    }
    onRequestSent() {
      this.handler.onRequestSent && this.handler.onRequestSent();
    }
    onUpgrade(i, a, h) {
      this.handler.onUpgrade && this.handler.onUpgrade(i, a, h);
    }
    onConnect(i) {
      this.aborted ? i(this.reason) : this.abort = i;
    }
    onBodySent(i) {
      if (this.handler.onBodySent) return this.handler.onBodySent(i);
    }
    static [r](i, { state: a, opts: h }, u) {
      const { statusCode: C, code: w, headers: D } = i, { method: b, retryOptions: U } = h, {
        maxRetries: G,
        minTimeout: M,
        maxTimeout: N,
        timeoutFactor: d,
        statusCodes: l,
        errorCodes: p,
        methods: s
      } = U, { counter: E } = a;
      if (w && w !== "UND_ERR_REQ_RETRY" && !p.includes(w)) {
        u(i);
        return;
      }
      if (Array.isArray(s) && !s.includes(b)) {
        u(i);
        return;
      }
      if (C != null && Array.isArray(l) && !l.includes(C)) {
        u(i);
        return;
      }
      if (E > G) {
        u(i);
        return;
      }
      let f = D?.["retry-after"];
      f && (f = Number(f), f = Number.isNaN(f) ? g(f) : f * 1e3);
      const I = f > 0 ? Math.min(f, N) : Math.min(M * d ** (E - 1), N);
      setTimeout(() => u(null), I);
    }
    onHeaders(i, a, h, u) {
      const C = A(a);
      if (this.retryCount += 1, i >= 300)
        return this.retryOpts.statusCodes.includes(i) === !1 ? this.handler.onHeaders(
          i,
          a,
          h,
          u
        ) : (this.abort(
          new t("Request failed", i, {
            headers: C,
            data: {
              count: this.retryCount
            }
          })
        ), !1);
      if (this.resume != null) {
        if (this.resume = null, i !== 206 && (this.start > 0 || i !== 200))
          return this.abort(
            new t("server does not support the range header and the payload was partially consumed", i, {
              headers: C,
              data: { count: this.retryCount }
            })
          ), !1;
        const D = n(C["content-range"]);
        if (!D)
          return this.abort(
            new t("Content-Range mismatch", i, {
              headers: C,
              data: { count: this.retryCount }
            })
          ), !1;
        if (this.etag != null && this.etag !== C.etag)
          return this.abort(
            new t("ETag mismatch", i, {
              headers: C,
              data: { count: this.retryCount }
            })
          ), !1;
        const { start: b, size: U, end: G = U - 1 } = D;
        return e(this.start === b, "content-range mismatch"), e(this.end == null || this.end === G, "content-range mismatch"), this.resume = h, !0;
      }
      if (this.end == null) {
        if (i === 206) {
          const D = n(C["content-range"]);
          if (D == null)
            return this.handler.onHeaders(
              i,
              a,
              h,
              u
            );
          const { start: b, size: U, end: G = U - 1 } = D;
          e(
            b != null && Number.isFinite(b),
            "content-range mismatch"
          ), e(G != null && Number.isFinite(G), "invalid content-length"), this.start = b, this.end = G;
        }
        if (this.end == null) {
          const D = C["content-length"];
          this.end = D != null ? Number(D) - 1 : null;
        }
        return e(Number.isFinite(this.start)), e(
          this.end == null || Number.isFinite(this.end),
          "invalid content-length"
        ), this.resume = h, this.etag = C.etag != null ? C.etag : null, this.etag != null && this.etag.startsWith("W/") && (this.etag = null), this.handler.onHeaders(
          i,
          a,
          h,
          u
        );
      }
      const w = new t("Request failed", i, {
        headers: C,
        data: { count: this.retryCount }
      });
      return this.abort(w), !1;
    }
    onData(i) {
      return this.start += i.length, this.handler.onData(i);
    }
    onComplete(i) {
      return this.retryCount = 0, this.handler.onComplete(i);
    }
    onError(i) {
      if (this.aborted || o(this.opts.body))
        return this.handler.onError(i);
      this.retryCount - this.retryCountCheckpoint > 0 ? this.retryCount = this.retryCountCheckpoint + (this.retryCount - this.retryCountCheckpoint) : this.retryCount += 1, this.retryOpts.retry(
        i,
        {
          state: { counter: this.retryCount },
          opts: { retryOptions: this.retryOpts, ...this.opts }
        },
        a.bind(this)
      );
      function a(h) {
        if (h != null || this.aborted || o(this.opts.body))
          return this.handler.onError(h);
        if (this.start !== 0) {
          const u = { range: `bytes=${this.start}-${this.end ?? ""}` };
          this.etag != null && (u["if-match"] = this.etag), this.opts = {
            ...this.opts,
            headers: {
              ...this.opts.headers,
              ...u
            }
          };
        }
        try {
          this.retryCountCheckpoint = this.retryCount, this.dispatch(this.opts, this);
        } catch (u) {
          this.handler.onError(u);
        }
      }
    }
  }
  return Wt = Q, Wt;
}
var qt, io;
function sa() {
  if (io) return qt;
  io = 1;
  const e = zA(), r = ns();
  class t extends e {
    #e = null;
    #A = null;
    constructor(A, n = {}) {
      super(n), this.#e = A, this.#A = n;
    }
    dispatch(A, n) {
      const c = new r({
        ...A,
        retryOptions: this.#A
      }, {
        dispatch: this.#e.dispatch.bind(this.#e),
        handler: n
      });
      return this.#e.dispatch(A, c);
    }
    close() {
      return this.#e.close();
    }
    destroy() {
      return this.#e.destroy();
    }
  }
  return qt = t, qt;
}
var QA = {}, PA = { exports: {} }, zt, ao;
function Xn() {
  if (ao) return zt;
  ao = 1;
  const e = He, { Readable: r } = tA, { RequestAbortedError: t, NotSupportedError: o, InvalidArgumentError: A, AbortError: n } = Ye(), c = Ue(), { ReadableStreamFrom: g } = Ue(), Q = /* @__PURE__ */ Symbol("kConsume"), B = /* @__PURE__ */ Symbol("kReading"), i = /* @__PURE__ */ Symbol("kBody"), a = /* @__PURE__ */ Symbol("kAbort"), h = /* @__PURE__ */ Symbol("kContentType"), u = /* @__PURE__ */ Symbol("kContentLength"), C = () => {
  };
  class w extends r {
    constructor({
      resume: E,
      abort: f,
      contentType: I = "",
      contentLength: m,
      highWaterMark: y = 64 * 1024
      // Same as nodejs fs streams.
    }) {
      super({
        autoDestroy: !0,
        read: E,
        highWaterMark: y
      }), this._readableState.dataEmitted = !1, this[a] = f, this[Q] = null, this[i] = null, this[h] = I, this[u] = m, this[B] = !1;
    }
    destroy(E) {
      return !E && !this._readableState.endEmitted && (E = new t()), E && this[a](), super.destroy(E);
    }
    _destroy(E, f) {
      this[B] ? f(E) : setImmediate(() => {
        f(E);
      });
    }
    on(E, ...f) {
      return (E === "data" || E === "readable") && (this[B] = !0), super.on(E, ...f);
    }
    addListener(E, ...f) {
      return this.on(E, ...f);
    }
    off(E, ...f) {
      const I = super.off(E, ...f);
      return (E === "data" || E === "readable") && (this[B] = this.listenerCount("data") > 0 || this.listenerCount("readable") > 0), I;
    }
    removeListener(E, ...f) {
      return this.off(E, ...f);
    }
    push(E) {
      return this[Q] && E !== null ? (l(this[Q], E), this[B] ? super.push(E) : !0) : super.push(E);
    }
    // https://fetch.spec.whatwg.org/#dom-body-text
    async text() {
      return U(this, "text");
    }
    // https://fetch.spec.whatwg.org/#dom-body-json
    async json() {
      return U(this, "json");
    }
    // https://fetch.spec.whatwg.org/#dom-body-blob
    async blob() {
      return U(this, "blob");
    }
    // https://fetch.spec.whatwg.org/#dom-body-bytes
    async bytes() {
      return U(this, "bytes");
    }
    // https://fetch.spec.whatwg.org/#dom-body-arraybuffer
    async arrayBuffer() {
      return U(this, "arrayBuffer");
    }
    // https://fetch.spec.whatwg.org/#dom-body-formdata
    async formData() {
      throw new o();
    }
    // https://fetch.spec.whatwg.org/#dom-body-bodyused
    get bodyUsed() {
      return c.isDisturbed(this);
    }
    // https://fetch.spec.whatwg.org/#dom-body-body
    get body() {
      return this[i] || (this[i] = g(this), this[Q] && (this[i].getReader(), e(this[i].locked))), this[i];
    }
    async dump(E) {
      let f = Number.isFinite(E?.limit) ? E.limit : 131072;
      const I = E?.signal;
      if (I != null && (typeof I != "object" || !("aborted" in I)))
        throw new A("signal must be an AbortSignal");
      return I?.throwIfAborted(), this._readableState.closeEmitted ? null : await new Promise((m, y) => {
        this[u] > f && this.destroy(new n());
        const S = () => {
          this.destroy(I.reason ?? new n());
        };
        I?.addEventListener("abort", S), this.on("close", function() {
          I?.removeEventListener("abort", S), I?.aborted ? y(I.reason ?? new n()) : m(null);
        }).on("error", C).on("data", function(T) {
          f -= T.length, f <= 0 && this.destroy();
        }).resume();
      });
    }
  }
  function D(s) {
    return s[i] && s[i].locked === !0 || s[Q];
  }
  function b(s) {
    return c.isDisturbed(s) || D(s);
  }
  async function U(s, E) {
    return e(!s[Q]), new Promise((f, I) => {
      if (b(s)) {
        const m = s._readableState;
        m.destroyed && m.closeEmitted === !1 ? s.on("error", (y) => {
          I(y);
        }).on("close", () => {
          I(new TypeError("unusable"));
        }) : I(m.errored ?? new TypeError("unusable"));
      } else
        queueMicrotask(() => {
          s[Q] = {
            type: E,
            stream: s,
            resolve: f,
            reject: I,
            length: 0,
            body: []
          }, s.on("error", function(m) {
            p(this[Q], m);
          }).on("close", function() {
            this[Q].body !== null && p(this[Q], new t());
          }), G(s[Q]);
        });
    });
  }
  function G(s) {
    if (s.body === null)
      return;
    const { _readableState: E } = s.stream;
    if (E.bufferIndex) {
      const f = E.bufferIndex, I = E.buffer.length;
      for (let m = f; m < I; m++)
        l(s, E.buffer[m]);
    } else
      for (const f of E.buffer)
        l(s, f);
    for (E.endEmitted ? d(this[Q]) : s.stream.on("end", function() {
      d(this[Q]);
    }), s.stream.resume(); s.stream.read() != null; )
      ;
  }
  function M(s, E) {
    if (s.length === 0 || E === 0)
      return "";
    const f = s.length === 1 ? s[0] : Buffer.concat(s, E), I = f.length, m = I > 2 && f[0] === 239 && f[1] === 187 && f[2] === 191 ? 3 : 0;
    return f.utf8Slice(m, I);
  }
  function N(s, E) {
    if (s.length === 0 || E === 0)
      return new Uint8Array(0);
    if (s.length === 1)
      return new Uint8Array(s[0]);
    const f = new Uint8Array(Buffer.allocUnsafeSlow(E).buffer);
    let I = 0;
    for (let m = 0; m < s.length; ++m) {
      const y = s[m];
      f.set(y, I), I += y.length;
    }
    return f;
  }
  function d(s) {
    const { type: E, body: f, resolve: I, stream: m, length: y } = s;
    try {
      E === "text" ? I(M(f, y)) : E === "json" ? I(JSON.parse(M(f, y))) : E === "arrayBuffer" ? I(N(f, y).buffer) : E === "blob" ? I(new Blob(f, { type: m[h] })) : E === "bytes" && I(N(f, y)), p(s);
    } catch (S) {
      m.destroy(S);
    }
  }
  function l(s, E) {
    s.length += E.length, s.body.push(E);
  }
  function p(s, E) {
    s.body !== null && (E ? s.reject(E) : s.resolve(), s.type = null, s.stream = null, s.resolve = null, s.reject = null, s.length = 0, s.body = null);
  }
  return zt = { Readable: w, chunksDecode: M }, zt;
}
var Zt, co;
function jn() {
  if (co) return Zt;
  co = 1;
  const e = He, {
    ResponseStatusCodeError: r
  } = Ye(), { chunksDecode: t } = Xn(), o = 128 * 1024;
  async function A({ callback: g, body: Q, contentType: B, statusCode: i, statusMessage: a, headers: h }) {
    e(Q);
    let u = [], C = 0;
    try {
      for await (const U of Q)
        if (u.push(U), C += U.length, C > o) {
          u = [], C = 0;
          break;
        }
    } catch {
      u = [], C = 0;
    }
    const w = `Response status code ${i}${a ? `: ${a}` : ""}`;
    if (i === 204 || !B || !C) {
      queueMicrotask(() => g(new r(w, i, h)));
      return;
    }
    const D = Error.stackTraceLimit;
    Error.stackTraceLimit = 0;
    let b;
    try {
      n(B) ? b = JSON.parse(t(u, C)) : c(B) && (b = t(u, C));
    } catch {
    } finally {
      Error.stackTraceLimit = D;
    }
    queueMicrotask(() => g(new r(w, i, h, b)));
  }
  const n = (g) => g.length > 15 && g[11] === "/" && g[0] === "a" && g[1] === "p" && g[2] === "p" && g[3] === "l" && g[4] === "i" && g[5] === "c" && g[6] === "a" && g[7] === "t" && g[8] === "i" && g[9] === "o" && g[10] === "n" && g[12] === "j" && g[13] === "s" && g[14] === "o" && g[15] === "n", c = (g) => g.length > 4 && g[4] === "/" && g[0] === "t" && g[1] === "e" && g[2] === "x" && g[3] === "t";
  return Zt = {
    getResolveErrorBodyCallback: A,
    isContentTypeApplicationJson: n,
    isContentTypeText: c
  }, Zt;
}
var go;
function oa() {
  if (go) return PA.exports;
  go = 1;
  const e = He, { Readable: r } = Xn(), { InvalidArgumentError: t, RequestAbortedError: o } = Ye(), A = Ue(), { getResolveErrorBodyCallback: n } = jn(), { AsyncResource: c } = bA;
  class g extends c {
    constructor(i, a) {
      if (!i || typeof i != "object")
        throw new t("invalid opts");
      const { signal: h, method: u, opaque: C, body: w, onInfo: D, responseHeaders: b, throwOnError: U, highWaterMark: G } = i;
      try {
        if (typeof a != "function")
          throw new t("invalid callback");
        if (G && (typeof G != "number" || G < 0))
          throw new t("invalid highWaterMark");
        if (h && typeof h.on != "function" && typeof h.addEventListener != "function")
          throw new t("signal must be an EventEmitter or EventTarget");
        if (u === "CONNECT")
          throw new t("invalid method");
        if (D && typeof D != "function")
          throw new t("invalid onInfo callback");
        super("UNDICI_REQUEST");
      } catch (M) {
        throw A.isStream(w) && A.destroy(w.on("error", A.nop), M), M;
      }
      this.method = u, this.responseHeaders = b || null, this.opaque = C || null, this.callback = a, this.res = null, this.abort = null, this.body = w, this.trailers = {}, this.context = null, this.onInfo = D || null, this.throwOnError = U, this.highWaterMark = G, this.signal = h, this.reason = null, this.removeAbortListener = null, A.isStream(w) && w.on("error", (M) => {
        this.onError(M);
      }), this.signal && (this.signal.aborted ? this.reason = this.signal.reason ?? new o() : this.removeAbortListener = A.addAbortListener(this.signal, () => {
        this.reason = this.signal.reason ?? new o(), this.res ? A.destroy(this.res.on("error", A.nop), this.reason) : this.abort && this.abort(this.reason), this.removeAbortListener && (this.res?.off("close", this.removeAbortListener), this.removeAbortListener(), this.removeAbortListener = null);
      }));
    }
    onConnect(i, a) {
      if (this.reason) {
        i(this.reason);
        return;
      }
      e(this.callback), this.abort = i, this.context = a;
    }
    onHeaders(i, a, h, u) {
      const { callback: C, opaque: w, abort: D, context: b, responseHeaders: U, highWaterMark: G } = this, M = U === "raw" ? A.parseRawHeaders(a) : A.parseHeaders(a);
      if (i < 200) {
        this.onInfo && this.onInfo({ statusCode: i, headers: M });
        return;
      }
      const N = U === "raw" ? A.parseHeaders(a) : M, d = N["content-type"], l = N["content-length"], p = new r({
        resume: h,
        abort: D,
        contentType: d,
        contentLength: this.method !== "HEAD" && l ? Number(l) : null,
        highWaterMark: G
      });
      this.removeAbortListener && p.on("close", this.removeAbortListener), this.callback = null, this.res = p, C !== null && (this.throwOnError && i >= 400 ? this.runInAsyncScope(
        n,
        null,
        { callback: C, body: p, contentType: d, statusCode: i, statusMessage: u, headers: M }
      ) : this.runInAsyncScope(C, null, null, {
        statusCode: i,
        headers: M,
        trailers: this.trailers,
        opaque: w,
        body: p,
        context: b
      }));
    }
    onData(i) {
      return this.res.push(i);
    }
    onComplete(i) {
      A.parseHeaders(i, this.trailers), this.res.push(null);
    }
    onError(i) {
      const { res: a, callback: h, body: u, opaque: C } = this;
      h && (this.callback = null, queueMicrotask(() => {
        this.runInAsyncScope(h, null, i, { opaque: C });
      })), a && (this.res = null, queueMicrotask(() => {
        A.destroy(a, i);
      })), u && (this.body = null, A.destroy(u, i)), this.removeAbortListener && (a?.off("close", this.removeAbortListener), this.removeAbortListener(), this.removeAbortListener = null);
    }
  }
  function Q(B, i) {
    if (i === void 0)
      return new Promise((a, h) => {
        Q.call(this, B, (u, C) => u ? h(u) : a(C));
      });
    try {
      this.dispatch(B, new g(B, i));
    } catch (a) {
      if (typeof i != "function")
        throw a;
      const h = B?.opaque;
      queueMicrotask(() => i(a, { opaque: h }));
    }
  }
  return PA.exports = Q, PA.exports.RequestHandler = g, PA.exports;
}
var Kt, lo;
function jA() {
  if (lo) return Kt;
  lo = 1;
  const { addAbortListener: e } = Ue(), { RequestAbortedError: r } = Ye(), t = /* @__PURE__ */ Symbol("kListener"), o = /* @__PURE__ */ Symbol("kSignal");
  function A(g) {
    g.abort ? g.abort(g[o]?.reason) : g.reason = g[o]?.reason ?? new r(), c(g);
  }
  function n(g, Q) {
    if (g.reason = null, g[o] = null, g[t] = null, !!Q) {
      if (Q.aborted) {
        A(g);
        return;
      }
      g[o] = Q, g[t] = () => {
        A(g);
      }, e(g[o], g[t]);
    }
  }
  function c(g) {
    g[o] && ("removeEventListener" in g[o] ? g[o].removeEventListener("abort", g[t]) : g[o].removeListener("abort", g[t]), g[o] = null, g[t] = null);
  }
  return Kt = {
    addSignal: n,
    removeSignal: c
  }, Kt;
}
var Xt, Eo;
function na() {
  if (Eo) return Xt;
  Eo = 1;
  const e = He, { finished: r, PassThrough: t } = tA, { InvalidArgumentError: o, InvalidReturnValueError: A } = Ye(), n = Ue(), { getResolveErrorBodyCallback: c } = jn(), { AsyncResource: g } = bA, { addSignal: Q, removeSignal: B } = jA();
  class i extends g {
    constructor(u, C, w) {
      if (!u || typeof u != "object")
        throw new o("invalid opts");
      const { signal: D, method: b, opaque: U, body: G, onInfo: M, responseHeaders: N, throwOnError: d } = u;
      try {
        if (typeof w != "function")
          throw new o("invalid callback");
        if (typeof C != "function")
          throw new o("invalid factory");
        if (D && typeof D.on != "function" && typeof D.addEventListener != "function")
          throw new o("signal must be an EventEmitter or EventTarget");
        if (b === "CONNECT")
          throw new o("invalid method");
        if (M && typeof M != "function")
          throw new o("invalid onInfo callback");
        super("UNDICI_STREAM");
      } catch (l) {
        throw n.isStream(G) && n.destroy(G.on("error", n.nop), l), l;
      }
      this.responseHeaders = N || null, this.opaque = U || null, this.factory = C, this.callback = w, this.res = null, this.abort = null, this.context = null, this.trailers = null, this.body = G, this.onInfo = M || null, this.throwOnError = d || !1, n.isStream(G) && G.on("error", (l) => {
        this.onError(l);
      }), Q(this, D);
    }
    onConnect(u, C) {
      if (this.reason) {
        u(this.reason);
        return;
      }
      e(this.callback), this.abort = u, this.context = C;
    }
    onHeaders(u, C, w, D) {
      const { factory: b, opaque: U, context: G, callback: M, responseHeaders: N } = this, d = N === "raw" ? n.parseRawHeaders(C) : n.parseHeaders(C);
      if (u < 200) {
        this.onInfo && this.onInfo({ statusCode: u, headers: d });
        return;
      }
      this.factory = null;
      let l;
      if (this.throwOnError && u >= 400) {
        const E = (N === "raw" ? n.parseHeaders(C) : d)["content-type"];
        l = new t(), this.callback = null, this.runInAsyncScope(
          c,
          null,
          { callback: M, body: l, contentType: E, statusCode: u, statusMessage: D, headers: d }
        );
      } else {
        if (b === null)
          return;
        if (l = this.runInAsyncScope(b, null, {
          statusCode: u,
          headers: d,
          opaque: U,
          context: G
        }), !l || typeof l.write != "function" || typeof l.end != "function" || typeof l.on != "function")
          throw new A("expected Writable");
        r(l, { readable: !1 }, (s) => {
          const { callback: E, res: f, opaque: I, trailers: m, abort: y } = this;
          this.res = null, (s || !f.readable) && n.destroy(f, s), this.callback = null, this.runInAsyncScope(E, null, s || null, { opaque: I, trailers: m }), s && y();
        });
      }
      return l.on("drain", w), this.res = l, (l.writableNeedDrain !== void 0 ? l.writableNeedDrain : l._writableState?.needDrain) !== !0;
    }
    onData(u) {
      const { res: C } = this;
      return C ? C.write(u) : !0;
    }
    onComplete(u) {
      const { res: C } = this;
      B(this), C && (this.trailers = n.parseHeaders(u), C.end());
    }
    onError(u) {
      const { res: C, callback: w, opaque: D, body: b } = this;
      B(this), this.factory = null, C ? (this.res = null, n.destroy(C, u)) : w && (this.callback = null, queueMicrotask(() => {
        this.runInAsyncScope(w, null, u, { opaque: D });
      })), b && (this.body = null, n.destroy(b, u));
    }
  }
  function a(h, u, C) {
    if (C === void 0)
      return new Promise((w, D) => {
        a.call(this, h, u, (b, U) => b ? D(b) : w(U));
      });
    try {
      this.dispatch(h, new i(h, u, C));
    } catch (w) {
      if (typeof C != "function")
        throw w;
      const D = h?.opaque;
      queueMicrotask(() => C(w, { opaque: D }));
    }
  }
  return Xt = a, Xt;
}
var jt, uo;
function ia() {
  if (uo) return jt;
  uo = 1;
  const {
    Readable: e,
    Duplex: r,
    PassThrough: t
  } = tA, {
    InvalidArgumentError: o,
    InvalidReturnValueError: A,
    RequestAbortedError: n
  } = Ye(), c = Ue(), { AsyncResource: g } = bA, { addSignal: Q, removeSignal: B } = jA(), i = He, a = /* @__PURE__ */ Symbol("resume");
  class h extends e {
    constructor() {
      super({ autoDestroy: !0 }), this[a] = null;
    }
    _read() {
      const { [a]: b } = this;
      b && (this[a] = null, b());
    }
    _destroy(b, U) {
      this._read(), U(b);
    }
  }
  class u extends e {
    constructor(b) {
      super({ autoDestroy: !0 }), this[a] = b;
    }
    _read() {
      this[a]();
    }
    _destroy(b, U) {
      !b && !this._readableState.endEmitted && (b = new n()), U(b);
    }
  }
  class C extends g {
    constructor(b, U) {
      if (!b || typeof b != "object")
        throw new o("invalid opts");
      if (typeof U != "function")
        throw new o("invalid handler");
      const { signal: G, method: M, opaque: N, onInfo: d, responseHeaders: l } = b;
      if (G && typeof G.on != "function" && typeof G.addEventListener != "function")
        throw new o("signal must be an EventEmitter or EventTarget");
      if (M === "CONNECT")
        throw new o("invalid method");
      if (d && typeof d != "function")
        throw new o("invalid onInfo callback");
      super("UNDICI_PIPELINE"), this.opaque = N || null, this.responseHeaders = l || null, this.handler = U, this.abort = null, this.context = null, this.onInfo = d || null, this.req = new h().on("error", c.nop), this.ret = new r({
        readableObjectMode: b.objectMode,
        autoDestroy: !0,
        read: () => {
          const { body: p } = this;
          p?.resume && p.resume();
        },
        write: (p, s, E) => {
          const { req: f } = this;
          f.push(p, s) || f._readableState.destroyed ? E() : f[a] = E;
        },
        destroy: (p, s) => {
          const { body: E, req: f, res: I, ret: m, abort: y } = this;
          !p && !m._readableState.endEmitted && (p = new n()), y && p && y(), c.destroy(E, p), c.destroy(f, p), c.destroy(I, p), B(this), s(p);
        }
      }).on("prefinish", () => {
        const { req: p } = this;
        p.push(null);
      }), this.res = null, Q(this, G);
    }
    onConnect(b, U) {
      const { ret: G, res: M } = this;
      if (this.reason) {
        b(this.reason);
        return;
      }
      i(!M, "pipeline cannot be retried"), i(!G.destroyed), this.abort = b, this.context = U;
    }
    onHeaders(b, U, G) {
      const { opaque: M, handler: N, context: d } = this;
      if (b < 200) {
        if (this.onInfo) {
          const p = this.responseHeaders === "raw" ? c.parseRawHeaders(U) : c.parseHeaders(U);
          this.onInfo({ statusCode: b, headers: p });
        }
        return;
      }
      this.res = new u(G);
      let l;
      try {
        this.handler = null;
        const p = this.responseHeaders === "raw" ? c.parseRawHeaders(U) : c.parseHeaders(U);
        l = this.runInAsyncScope(N, null, {
          statusCode: b,
          headers: p,
          opaque: M,
          body: this.res,
          context: d
        });
      } catch (p) {
        throw this.res.on("error", c.nop), p;
      }
      if (!l || typeof l.on != "function")
        throw new A("expected Readable");
      l.on("data", (p) => {
        const { ret: s, body: E } = this;
        !s.push(p) && E.pause && E.pause();
      }).on("error", (p) => {
        const { ret: s } = this;
        c.destroy(s, p);
      }).on("end", () => {
        const { ret: p } = this;
        p.push(null);
      }).on("close", () => {
        const { ret: p } = this;
        p._readableState.ended || c.destroy(p, new n());
      }), this.body = l;
    }
    onData(b) {
      const { res: U } = this;
      return U.push(b);
    }
    onComplete(b) {
      const { res: U } = this;
      U.push(null);
    }
    onError(b) {
      const { ret: U } = this;
      this.handler = null, c.destroy(U, b);
    }
  }
  function w(D, b) {
    try {
      const U = new C(D, b);
      return this.dispatch({ ...D, body: U.req }, U), U.ret;
    } catch (U) {
      return new t().destroy(U);
    }
  }
  return jt = w, jt;
}
var $t, Qo;
function aa() {
  if (Qo) return $t;
  Qo = 1;
  const { InvalidArgumentError: e, SocketError: r } = Ye(), { AsyncResource: t } = bA, o = Ue(), { addSignal: A, removeSignal: n } = jA(), c = He;
  class g extends t {
    constructor(i, a) {
      if (!i || typeof i != "object")
        throw new e("invalid opts");
      if (typeof a != "function")
        throw new e("invalid callback");
      const { signal: h, opaque: u, responseHeaders: C } = i;
      if (h && typeof h.on != "function" && typeof h.addEventListener != "function")
        throw new e("signal must be an EventEmitter or EventTarget");
      super("UNDICI_UPGRADE"), this.responseHeaders = C || null, this.opaque = u || null, this.callback = a, this.abort = null, this.context = null, A(this, h);
    }
    onConnect(i, a) {
      if (this.reason) {
        i(this.reason);
        return;
      }
      c(this.callback), this.abort = i, this.context = null;
    }
    onHeaders() {
      throw new r("bad upgrade", null);
    }
    onUpgrade(i, a, h) {
      c(i === 101);
      const { callback: u, opaque: C, context: w } = this;
      n(this), this.callback = null;
      const D = this.responseHeaders === "raw" ? o.parseRawHeaders(a) : o.parseHeaders(a);
      this.runInAsyncScope(u, null, null, {
        headers: D,
        socket: h,
        opaque: C,
        context: w
      });
    }
    onError(i) {
      const { callback: a, opaque: h } = this;
      n(this), a && (this.callback = null, queueMicrotask(() => {
        this.runInAsyncScope(a, null, i, { opaque: h });
      }));
    }
  }
  function Q(B, i) {
    if (i === void 0)
      return new Promise((a, h) => {
        Q.call(this, B, (u, C) => u ? h(u) : a(C));
      });
    try {
      const a = new g(B, i);
      this.dispatch({
        ...B,
        method: B.method || "GET",
        upgrade: B.protocol || "Websocket"
      }, a);
    } catch (a) {
      if (typeof i != "function")
        throw a;
      const h = B?.opaque;
      queueMicrotask(() => i(a, { opaque: h }));
    }
  }
  return $t = Q, $t;
}
var er, Bo;
function ca() {
  if (Bo) return er;
  Bo = 1;
  const e = He, { AsyncResource: r } = bA, { InvalidArgumentError: t, SocketError: o } = Ye(), A = Ue(), { addSignal: n, removeSignal: c } = jA();
  class g extends r {
    constructor(i, a) {
      if (!i || typeof i != "object")
        throw new t("invalid opts");
      if (typeof a != "function")
        throw new t("invalid callback");
      const { signal: h, opaque: u, responseHeaders: C } = i;
      if (h && typeof h.on != "function" && typeof h.addEventListener != "function")
        throw new t("signal must be an EventEmitter or EventTarget");
      super("UNDICI_CONNECT"), this.opaque = u || null, this.responseHeaders = C || null, this.callback = a, this.abort = null, n(this, h);
    }
    onConnect(i, a) {
      if (this.reason) {
        i(this.reason);
        return;
      }
      e(this.callback), this.abort = i, this.context = a;
    }
    onHeaders() {
      throw new o("bad connect", null);
    }
    onUpgrade(i, a, h) {
      const { callback: u, opaque: C, context: w } = this;
      c(this), this.callback = null;
      let D = a;
      D != null && (D = this.responseHeaders === "raw" ? A.parseRawHeaders(a) : A.parseHeaders(a)), this.runInAsyncScope(u, null, null, {
        statusCode: i,
        headers: D,
        socket: h,
        opaque: C,
        context: w
      });
    }
    onError(i) {
      const { callback: a, opaque: h } = this;
      c(this), a && (this.callback = null, queueMicrotask(() => {
        this.runInAsyncScope(a, null, i, { opaque: h });
      }));
    }
  }
  function Q(B, i) {
    if (i === void 0)
      return new Promise((a, h) => {
        Q.call(this, B, (u, C) => u ? h(u) : a(C));
      });
    try {
      const a = new g(B, i);
      this.dispatch({ ...B, method: "CONNECT" }, a);
    } catch (a) {
      if (typeof i != "function")
        throw a;
      const h = B?.opaque;
      queueMicrotask(() => i(a, { opaque: h }));
    }
  }
  return er = Q, er;
}
var ho;
function ga() {
  return ho || (ho = 1, QA.request = oa(), QA.stream = na(), QA.pipeline = ia(), QA.upgrade = aa(), QA.connect = ca()), QA;
}
var Ar, Io;
function $n() {
  if (Io) return Ar;
  Io = 1;
  const { UndiciError: e } = Ye(), r = /* @__PURE__ */ Symbol.for("undici.error.UND_MOCK_ERR_MOCK_NOT_MATCHED");
  class t extends e {
    constructor(A) {
      super(A), Error.captureStackTrace(this, t), this.name = "MockNotMatchedError", this.message = A || "The request does not match any registered mock dispatches", this.code = "UND_MOCK_ERR_MOCK_NOT_MATCHED";
    }
    static [Symbol.hasInstance](A) {
      return A && A[r] === !0;
    }
    [r] = !0;
  }
  return Ar = {
    MockNotMatchedError: t
  }, Ar;
}
var tr, Co;
function LA() {
  return Co || (Co = 1, tr = {
    kAgent: /* @__PURE__ */ Symbol("agent"),
    kOptions: /* @__PURE__ */ Symbol("options"),
    kFactory: /* @__PURE__ */ Symbol("factory"),
    kDispatches: /* @__PURE__ */ Symbol("dispatches"),
    kDispatchKey: /* @__PURE__ */ Symbol("dispatch key"),
    kDefaultHeaders: /* @__PURE__ */ Symbol("default headers"),
    kDefaultTrailers: /* @__PURE__ */ Symbol("default trailers"),
    kContentLength: /* @__PURE__ */ Symbol("content length"),
    kMockAgent: /* @__PURE__ */ Symbol("mock agent"),
    kMockAgentSet: /* @__PURE__ */ Symbol("mock agent set"),
    kMockAgentGet: /* @__PURE__ */ Symbol("mock agent get"),
    kMockDispatch: /* @__PURE__ */ Symbol("mock dispatch"),
    kClose: /* @__PURE__ */ Symbol("close"),
    kOriginalClose: /* @__PURE__ */ Symbol("original agent close"),
    kOrigin: /* @__PURE__ */ Symbol("origin"),
    kIsMockActive: /* @__PURE__ */ Symbol("is mock active"),
    kNetConnect: /* @__PURE__ */ Symbol("net connect"),
    kGetNetConnect: /* @__PURE__ */ Symbol("get net connect"),
    kConnected: /* @__PURE__ */ Symbol("connected")
  }), tr;
}
var rr, fo;
function $A() {
  if (fo) return rr;
  fo = 1;
  const { MockNotMatchedError: e } = $n(), {
    kDispatches: r,
    kMockAgent: t,
    kOriginalDispatch: o,
    kOrigin: A,
    kGetNetConnect: n
  } = LA(), { buildURL: c } = Ue(), { STATUS_CODES: g } = qA, {
    types: {
      isPromise: Q
    }
  } = $e;
  function B(I, m) {
    return typeof I == "string" ? I === m : I instanceof RegExp ? I.test(m) : typeof I == "function" ? I(m) === !0 : !1;
  }
  function i(I) {
    return Object.fromEntries(
      Object.entries(I).map(([m, y]) => [m.toLocaleLowerCase(), y])
    );
  }
  function a(I, m) {
    if (Array.isArray(I)) {
      for (let y = 0; y < I.length; y += 2)
        if (I[y].toLocaleLowerCase() === m.toLocaleLowerCase())
          return I[y + 1];
      return;
    } else return typeof I.get == "function" ? I.get(m) : i(I)[m.toLocaleLowerCase()];
  }
  function h(I) {
    const m = I.slice(), y = [];
    for (let S = 0; S < m.length; S += 2)
      y.push([m[S], m[S + 1]]);
    return Object.fromEntries(y);
  }
  function u(I, m) {
    if (typeof I.headers == "function")
      return Array.isArray(m) && (m = h(m)), I.headers(m ? i(m) : {});
    if (typeof I.headers > "u")
      return !0;
    if (typeof m != "object" || typeof I.headers != "object")
      return !1;
    for (const [y, S] of Object.entries(I.headers)) {
      const T = a(m, y);
      if (!B(S, T))
        return !1;
    }
    return !0;
  }
  function C(I) {
    if (typeof I != "string")
      return I;
    const m = I.split("?");
    if (m.length !== 2)
      return I;
    const y = new URLSearchParams(m.pop());
    return y.sort(), [...m, y.toString()].join("?");
  }
  function w(I, { path: m, method: y, body: S, headers: T }) {
    const L = B(I.path, m), v = B(I.method, y), $ = typeof I.body < "u" ? B(I.body, S) : !0, oe = u(I, T);
    return L && v && $ && oe;
  }
  function D(I) {
    return Buffer.isBuffer(I) || I instanceof Uint8Array || I instanceof ArrayBuffer ? I : typeof I == "object" ? JSON.stringify(I) : I.toString();
  }
  function b(I, m) {
    const y = m.query ? c(m.path, m.query) : m.path, S = typeof y == "string" ? C(y) : y;
    let T = I.filter(({ consumed: L }) => !L).filter(({ path: L }) => B(C(L), S));
    if (T.length === 0)
      throw new e(`Mock dispatch not matched for path '${S}'`);
    if (T = T.filter(({ method: L }) => B(L, m.method)), T.length === 0)
      throw new e(`Mock dispatch not matched for method '${m.method}' on path '${S}'`);
    if (T = T.filter(({ body: L }) => typeof L < "u" ? B(L, m.body) : !0), T.length === 0)
      throw new e(`Mock dispatch not matched for body '${m.body}' on path '${S}'`);
    if (T = T.filter((L) => u(L, m.headers)), T.length === 0) {
      const L = typeof m.headers == "object" ? JSON.stringify(m.headers) : m.headers;
      throw new e(`Mock dispatch not matched for headers '${L}' on path '${S}'`);
    }
    return T[0];
  }
  function U(I, m, y) {
    const S = { timesInvoked: 0, times: 1, persist: !1, consumed: !1 }, T = typeof y == "function" ? { callback: y } : { ...y }, L = { ...S, ...m, pending: !0, data: { error: null, ...T } };
    return I.push(L), L;
  }
  function G(I, m) {
    const y = I.findIndex((S) => S.consumed ? w(S, m) : !1);
    y !== -1 && I.splice(y, 1);
  }
  function M(I) {
    const { path: m, method: y, body: S, headers: T, query: L } = I;
    return {
      path: m,
      method: y,
      body: S,
      headers: T,
      query: L
    };
  }
  function N(I) {
    const m = Object.keys(I), y = [];
    for (let S = 0; S < m.length; ++S) {
      const T = m[S], L = I[T], v = Buffer.from(`${T}`);
      if (Array.isArray(L))
        for (let $ = 0; $ < L.length; ++$)
          y.push(v, Buffer.from(`${L[$]}`));
      else
        y.push(v, Buffer.from(`${L}`));
    }
    return y;
  }
  function d(I) {
    return g[I] || "unknown";
  }
  async function l(I) {
    const m = [];
    for await (const y of I)
      m.push(y);
    return Buffer.concat(m).toString("utf8");
  }
  function p(I, m) {
    const y = M(I), S = b(this[r], y);
    S.timesInvoked++, S.data.callback && (S.data = { ...S.data, ...S.data.callback(I) });
    const { data: { statusCode: T, data: L, headers: v, trailers: $, error: oe }, delay: ge, persist: ae } = S, { timesInvoked: he, times: Be } = S;
    if (S.consumed = !ae && he >= Be, S.pending = he < Be, oe !== null)
      return G(this[r], y), m.onError(oe), !0;
    typeof ge == "number" && ge > 0 ? setTimeout(() => {
      Qe(this[r]);
    }, ge) : Qe(this[r]);
    function Qe(we, j = L) {
      const W = Array.isArray(I.headers) ? h(I.headers) : I.headers, re = typeof j == "function" ? j({ ...I, headers: W }) : j;
      if (Q(re)) {
        re.then((Z) => Qe(we, Z));
        return;
      }
      const J = D(re), _ = N(v), P = N($);
      m.onConnect?.((Z) => m.onError(Z), null), m.onHeaders?.(T, _, ye, d(T)), m.onData?.(Buffer.from(J)), m.onComplete?.(P), G(we, y);
    }
    function ye() {
    }
    return !0;
  }
  function s() {
    const I = this[t], m = this[A], y = this[o];
    return function(T, L) {
      if (I.isMockActive)
        try {
          p.call(this, T, L);
        } catch (v) {
          if (v instanceof e) {
            const $ = I[n]();
            if ($ === !1)
              throw new e(`${v.message}: subsequent request to origin ${m} was not allowed (net.connect disabled)`);
            if (E($, m))
              y.call(this, T, L);
            else
              throw new e(`${v.message}: subsequent request to origin ${m} was not allowed (net.connect is not enabled for this origin)`);
          } else
            throw v;
        }
      else
        y.call(this, T, L);
    };
  }
  function E(I, m) {
    const y = new URL(m);
    return I === !0 ? !0 : !!(Array.isArray(I) && I.some((S) => B(S, y.host)));
  }
  function f(I) {
    if (I) {
      const { agent: m, ...y } = I;
      return y;
    }
  }
  return rr = {
    getResponseData: D,
    getMockDispatch: b,
    addMockDispatch: U,
    deleteMockDispatch: G,
    buildKey: M,
    generateKeyValues: N,
    matchValue: B,
    getResponse: l,
    getStatusText: d,
    mockDispatch: p,
    buildMockDispatch: s,
    checkNetConnect: E,
    buildMockOptions: f,
    getHeaderByName: a,
    buildHeadersFromArray: h
  }, rr;
}
var xA = {}, po;
function ei() {
  if (po) return xA;
  po = 1;
  const { getResponseData: e, buildKey: r, addMockDispatch: t } = $A(), {
    kDispatches: o,
    kDispatchKey: A,
    kDefaultHeaders: n,
    kDefaultTrailers: c,
    kContentLength: g,
    kMockDispatch: Q
  } = LA(), { InvalidArgumentError: B } = Ye(), { buildURL: i } = Ue();
  class a {
    constructor(C) {
      this[Q] = C;
    }
    /**
     * Delay a reply by a set amount in ms.
     */
    delay(C) {
      if (typeof C != "number" || !Number.isInteger(C) || C <= 0)
        throw new B("waitInMs must be a valid integer > 0");
      return this[Q].delay = C, this;
    }
    /**
     * For a defined reply, never mark as consumed.
     */
    persist() {
      return this[Q].persist = !0, this;
    }
    /**
     * Allow one to define a reply for a set amount of matching requests.
     */
    times(C) {
      if (typeof C != "number" || !Number.isInteger(C) || C <= 0)
        throw new B("repeatTimes must be a valid integer > 0");
      return this[Q].times = C, this;
    }
  }
  class h {
    constructor(C, w) {
      if (typeof C != "object")
        throw new B("opts must be an object");
      if (typeof C.path > "u")
        throw new B("opts.path must be defined");
      if (typeof C.method > "u" && (C.method = "GET"), typeof C.path == "string")
        if (C.query)
          C.path = i(C.path, C.query);
        else {
          const D = new URL(C.path, "data://");
          C.path = D.pathname + D.search;
        }
      typeof C.method == "string" && (C.method = C.method.toUpperCase()), this[A] = r(C), this[o] = w, this[n] = {}, this[c] = {}, this[g] = !1;
    }
    createMockScopeDispatchData({ statusCode: C, data: w, responseOptions: D }) {
      const b = e(w), U = this[g] ? { "content-length": b.length } : {}, G = { ...this[n], ...U, ...D.headers }, M = { ...this[c], ...D.trailers };
      return { statusCode: C, data: w, headers: G, trailers: M };
    }
    validateReplyParameters(C) {
      if (typeof C.statusCode > "u")
        throw new B("statusCode must be defined");
      if (typeof C.responseOptions != "object" || C.responseOptions === null)
        throw new B("responseOptions must be an object");
    }
    /**
     * Mock an undici request with a defined reply.
     */
    reply(C) {
      if (typeof C == "function") {
        const U = (M) => {
          const N = C(M);
          if (typeof N != "object" || N === null)
            throw new B("reply options callback must return an object");
          const d = { data: "", responseOptions: {}, ...N };
          return this.validateReplyParameters(d), {
            ...this.createMockScopeDispatchData(d)
          };
        }, G = t(this[o], this[A], U);
        return new a(G);
      }
      const w = {
        statusCode: C,
        data: arguments[1] === void 0 ? "" : arguments[1],
        responseOptions: arguments[2] === void 0 ? {} : arguments[2]
      };
      this.validateReplyParameters(w);
      const D = this.createMockScopeDispatchData(w), b = t(this[o], this[A], D);
      return new a(b);
    }
    /**
     * Mock an undici request with a defined error.
     */
    replyWithError(C) {
      if (typeof C > "u")
        throw new B("error must be defined");
      const w = t(this[o], this[A], { error: C });
      return new a(w);
    }
    /**
     * Set default reply headers on the interceptor for subsequent replies
     */
    defaultReplyHeaders(C) {
      if (typeof C > "u")
        throw new B("headers must be defined");
      return this[n] = C, this;
    }
    /**
     * Set default reply trailers on the interceptor for subsequent replies
     */
    defaultReplyTrailers(C) {
      if (typeof C > "u")
        throw new B("trailers must be defined");
      return this[c] = C, this;
    }
    /**
     * Set reply content length header for replies on the interceptor
     */
    replyContentLength() {
      return this[g] = !0, this;
    }
  }
  return xA.MockInterceptor = h, xA.MockScope = a, xA;
}
var sr, wo;
function Ai() {
  if (wo) return sr;
  wo = 1;
  const { promisify: e } = $e, r = UA(), { buildMockDispatch: t } = $A(), {
    kDispatches: o,
    kMockAgent: A,
    kClose: n,
    kOriginalClose: c,
    kOrigin: g,
    kOriginalDispatch: Q,
    kConnected: B
  } = LA(), { MockInterceptor: i } = ei(), a = Oe(), { InvalidArgumentError: h } = Ye();
  class u extends r {
    constructor(w, D) {
      if (super(w, D), !D || !D.agent || typeof D.agent.dispatch != "function")
        throw new h("Argument opts.agent must implement Agent");
      this[A] = D.agent, this[g] = w, this[o] = [], this[B] = 1, this[Q] = this.dispatch, this[c] = this.close.bind(this), this.dispatch = t.call(this), this.close = this[n];
    }
    get [a.kConnected]() {
      return this[B];
    }
    /**
     * Sets up the base interceptor for mocking replies from undici.
     */
    intercept(w) {
      return new i(w, this[o]);
    }
    async [n]() {
      await e(this[c])(), this[B] = 0, this[A][a.kClients].delete(this[g]);
    }
  }
  return sr = u, sr;
}
var or, mo;
function ti() {
  if (mo) return or;
  mo = 1;
  const { promisify: e } = $e, r = NA(), { buildMockDispatch: t } = $A(), {
    kDispatches: o,
    kMockAgent: A,
    kClose: n,
    kOriginalClose: c,
    kOrigin: g,
    kOriginalDispatch: Q,
    kConnected: B
  } = LA(), { MockInterceptor: i } = ei(), a = Oe(), { InvalidArgumentError: h } = Ye();
  class u extends r {
    constructor(w, D) {
      if (super(w, D), !D || !D.agent || typeof D.agent.dispatch != "function")
        throw new h("Argument opts.agent must implement Agent");
      this[A] = D.agent, this[g] = w, this[o] = [], this[B] = 1, this[Q] = this.dispatch, this[c] = this.close.bind(this), this.dispatch = t.call(this), this.close = this[n];
    }
    get [a.kConnected]() {
      return this[B];
    }
    /**
     * Sets up the base interceptor for mocking replies from undici.
     */
    intercept(w) {
      return new i(w, this[o]);
    }
    async [n]() {
      await e(this[c])(), this[B] = 0, this[A][a.kClients].delete(this[g]);
    }
  }
  return or = u, or;
}
var nr, yo;
function la() {
  if (yo) return nr;
  yo = 1;
  const e = {
    pronoun: "it",
    is: "is",
    was: "was",
    this: "this"
  }, r = {
    pronoun: "they",
    is: "are",
    was: "were",
    this: "these"
  };
  return nr = class {
    constructor(o, A) {
      this.singular = o, this.plural = A;
    }
    pluralize(o) {
      const A = o === 1, n = A ? e : r, c = A ? this.singular : this.plural;
      return { ...n, count: o, noun: c };
    }
  }, nr;
}
var ir, Do;
function Ea() {
  if (Do) return ir;
  Do = 1;
  const { Transform: e } = tA, { Console: r } = Yi, t = process.versions.icu ? "✅" : "Y ", o = process.versions.icu ? "❌" : "N ";
  return ir = class {
    constructor({ disableColors: n } = {}) {
      this.transform = new e({
        transform(c, g, Q) {
          Q(null, c);
        }
      }), this.logger = new r({
        stdout: this.transform,
        inspectOptions: {
          colors: !n && !process.env.CI
        }
      });
    }
    format(n) {
      const c = n.map(
        ({ method: g, path: Q, data: { statusCode: B }, persist: i, times: a, timesInvoked: h, origin: u }) => ({
          Method: g,
          Origin: u,
          Path: Q,
          "Status code": B,
          Persistent: i ? t : o,
          Invocations: h,
          Remaining: i ? 1 / 0 : a - h
        })
      );
      return this.logger.table(c), this.transform.read().toString();
    }
  }, ir;
}
var ar, Ro;
function ua() {
  if (Ro) return ar;
  Ro = 1;
  const { kClients: e } = Oe(), r = MA(), {
    kAgent: t,
    kMockAgentSet: o,
    kMockAgentGet: A,
    kDispatches: n,
    kIsMockActive: c,
    kNetConnect: g,
    kGetNetConnect: Q,
    kOptions: B,
    kFactory: i
  } = LA(), a = Ai(), h = ti(), { matchValue: u, buildMockOptions: C } = $A(), { InvalidArgumentError: w, UndiciError: D } = Ye(), b = zA(), U = la(), G = Ea();
  class M extends b {
    constructor(d) {
      if (super(d), this[g] = !0, this[c] = !0, d?.agent && typeof d.agent.dispatch != "function")
        throw new w("Argument opts.agent must implement Agent");
      const l = d?.agent ? d.agent : new r(d);
      this[t] = l, this[e] = l[e], this[B] = C(d);
    }
    get(d) {
      let l = this[A](d);
      return l || (l = this[i](d), this[o](d, l)), l;
    }
    dispatch(d, l) {
      return this.get(d.origin), this[t].dispatch(d, l);
    }
    async close() {
      await this[t].close(), this[e].clear();
    }
    deactivate() {
      this[c] = !1;
    }
    activate() {
      this[c] = !0;
    }
    enableNetConnect(d) {
      if (typeof d == "string" || typeof d == "function" || d instanceof RegExp)
        Array.isArray(this[g]) ? this[g].push(d) : this[g] = [d];
      else if (typeof d > "u")
        this[g] = !0;
      else
        throw new w("Unsupported matcher. Must be one of String|Function|RegExp.");
    }
    disableNetConnect() {
      this[g] = !1;
    }
    // This is required to bypass issues caused by using global symbols - see:
    // https://github.com/nodejs/undici/issues/1447
    get isMockActive() {
      return this[c];
    }
    [o](d, l) {
      this[e].set(d, l);
    }
    [i](d) {
      const l = Object.assign({ agent: this }, this[B]);
      return this[B] && this[B].connections === 1 ? new a(d, l) : new h(d, l);
    }
    [A](d) {
      const l = this[e].get(d);
      if (l)
        return l;
      if (typeof d != "string") {
        const p = this[i]("http://localhost:9999");
        return this[o](d, p), p;
      }
      for (const [p, s] of Array.from(this[e]))
        if (s && typeof p != "string" && u(p, d)) {
          const E = this[i](d);
          return this[o](d, E), E[n] = s[n], E;
        }
    }
    [Q]() {
      return this[g];
    }
    pendingInterceptors() {
      const d = this[e];
      return Array.from(d.entries()).flatMap(([l, p]) => p[n].map((s) => ({ ...s, origin: l }))).filter(({ pending: l }) => l);
    }
    assertNoPendingInterceptors({ pendingInterceptorsFormatter: d = new G() } = {}) {
      const l = this.pendingInterceptors();
      if (l.length === 0)
        return;
      const p = new U("interceptor", "interceptors").pluralize(l.length);
      throw new D(`
${p.count} ${p.noun} ${p.is} pending:

${d.format(l)}
`.trim());
    }
  }
  return ar = M, ar;
}
var cr, ko;
function is() {
  if (ko) return cr;
  ko = 1;
  const e = /* @__PURE__ */ Symbol.for("undici.globalDispatcher.1"), { InvalidArgumentError: r } = Ye(), t = MA();
  A() === void 0 && o(new t());
  function o(n) {
    if (!n || typeof n.dispatch != "function")
      throw new r("Argument agent must implement Agent");
    Object.defineProperty(globalThis, e, {
      value: n,
      writable: !0,
      enumerable: !1,
      configurable: !1
    });
  }
  function A() {
    return globalThis[e];
  }
  return cr = {
    setGlobalDispatcher: o,
    getGlobalDispatcher: A
  }, cr;
}
var gr, bo;
function as() {
  return bo || (bo = 1, gr = class {
    #e;
    constructor(r) {
      if (typeof r != "object" || r === null)
        throw new TypeError("handler must be an object");
      this.#e = r;
    }
    onConnect(...r) {
      return this.#e.onConnect?.(...r);
    }
    onError(...r) {
      return this.#e.onError?.(...r);
    }
    onUpgrade(...r) {
      return this.#e.onUpgrade?.(...r);
    }
    onResponseStarted(...r) {
      return this.#e.onResponseStarted?.(...r);
    }
    onHeaders(...r) {
      return this.#e.onHeaders?.(...r);
    }
    onData(...r) {
      return this.#e.onData?.(...r);
    }
    onComplete(...r) {
      return this.#e.onComplete?.(...r);
    }
    onBodySent(...r) {
      return this.#e.onBodySent?.(...r);
    }
  }), gr;
}
var lr, Fo;
function Qa() {
  if (Fo) return lr;
  Fo = 1;
  const e = ss();
  return lr = (r) => {
    const t = r?.maxRedirections;
    return (o) => function(n, c) {
      const { maxRedirections: g = t, ...Q } = n;
      if (!g)
        return o(n, c);
      const B = new e(
        o,
        g,
        n,
        c
      );
      return o(Q, B);
    };
  }, lr;
}
var Er, To;
function Ba() {
  if (To) return Er;
  To = 1;
  const e = ns();
  return Er = (r) => (t) => function(A, n) {
    return t(
      A,
      new e(
        { ...A, retryOptions: { ...r, ...A.retryOptions } },
        {
          handler: n,
          dispatch: t
        }
      )
    );
  }, Er;
}
var ur, So;
function ha() {
  if (So) return ur;
  So = 1;
  const e = Ue(), { InvalidArgumentError: r, RequestAbortedError: t } = Ye(), o = as();
  class A extends o {
    #e = 1024 * 1024;
    #A = null;
    #s = !1;
    #r = !1;
    #t = 0;
    #o = null;
    #n = null;
    constructor({ maxSize: g }, Q) {
      if (super(Q), g != null && (!Number.isFinite(g) || g < 1))
        throw new r("maxSize must be a number greater than 0");
      this.#e = g ?? this.#e, this.#n = Q;
    }
    onConnect(g) {
      this.#A = g, this.#n.onConnect(this.#i.bind(this));
    }
    #i(g) {
      this.#r = !0, this.#o = g;
    }
    // TODO: will require adjustment after new hooks are out
    onHeaders(g, Q, B, i) {
      const h = e.parseHeaders(Q)["content-length"];
      if (h != null && h > this.#e)
        throw new t(
          `Response size (${h}) larger than maxSize (${this.#e})`
        );
      return this.#r ? !0 : this.#n.onHeaders(
        g,
        Q,
        B,
        i
      );
    }
    onError(g) {
      this.#s || (g = this.#o ?? g, this.#n.onError(g));
    }
    onData(g) {
      return this.#t = this.#t + g.length, this.#t >= this.#e && (this.#s = !0, this.#r ? this.#n.onError(this.#o) : this.#n.onComplete([])), !0;
    }
    onComplete(g) {
      if (!this.#s) {
        if (this.#r) {
          this.#n.onError(this.reason);
          return;
        }
        this.#n.onComplete(g);
      }
    }
  }
  function n({ maxSize: c } = {
    maxSize: 1024 * 1024
  }) {
    return (g) => function(B, i) {
      const { dumpMaxSize: a = c } = B, h = new A(
        { maxSize: a },
        i
      );
      return g(B, h);
    };
  }
  return ur = n, ur;
}
var Qr, Uo;
function Ia() {
  if (Uo) return Qr;
  Uo = 1;
  const { isIP: e } = WA, { lookup: r } = Ji, t = as(), { InvalidArgumentError: o, InformationalError: A } = Ye(), n = Math.pow(2, 31) - 1;
  class c {
    #e = 0;
    #A = 0;
    #s = /* @__PURE__ */ new Map();
    dualStack = !0;
    affinity = null;
    lookup = null;
    pick = null;
    constructor(B) {
      this.#e = B.maxTTL, this.#A = B.maxItems, this.dualStack = B.dualStack, this.affinity = B.affinity, this.lookup = B.lookup ?? this.#r, this.pick = B.pick ?? this.#t;
    }
    get full() {
      return this.#s.size === this.#A;
    }
    runLookup(B, i, a) {
      const h = this.#s.get(B.hostname);
      if (h == null && this.full) {
        a(null, B.origin);
        return;
      }
      const u = {
        affinity: this.affinity,
        dualStack: this.dualStack,
        lookup: this.lookup,
        pick: this.pick,
        ...i.dns,
        maxTTL: this.#e,
        maxItems: this.#A
      };
      if (h == null)
        this.lookup(B, u, (C, w) => {
          if (C || w == null || w.length === 0) {
            a(C ?? new A("No DNS entries found"));
            return;
          }
          this.setRecords(B, w);
          const D = this.#s.get(B.hostname), b = this.pick(
            B,
            D,
            u.affinity
          );
          let U;
          typeof b.port == "number" ? U = `:${b.port}` : B.port !== "" ? U = `:${B.port}` : U = "", a(
            null,
            `${B.protocol}//${b.family === 6 ? `[${b.address}]` : b.address}${U}`
          );
        });
      else {
        const C = this.pick(
          B,
          h,
          u.affinity
        );
        if (C == null) {
          this.#s.delete(B.hostname), this.runLookup(B, i, a);
          return;
        }
        let w;
        typeof C.port == "number" ? w = `:${C.port}` : B.port !== "" ? w = `:${B.port}` : w = "", a(
          null,
          `${B.protocol}//${C.family === 6 ? `[${C.address}]` : C.address}${w}`
        );
      }
    }
    #r(B, i, a) {
      r(
        B.hostname,
        {
          all: !0,
          family: this.dualStack === !1 ? this.affinity : 0,
          order: "ipv4first"
        },
        (h, u) => {
          if (h)
            return a(h);
          const C = /* @__PURE__ */ new Map();
          for (const w of u)
            C.set(`${w.address}:${w.family}`, w);
          a(null, C.values());
        }
      );
    }
    #t(B, i, a) {
      let h = null;
      const { records: u, offset: C } = i;
      let w;
      if (this.dualStack ? (a == null && (C == null || C === n ? (i.offset = 0, a = 4) : (i.offset++, a = (i.offset & 1) === 1 ? 6 : 4)), u[a] != null && u[a].ips.length > 0 ? w = u[a] : w = u[a === 4 ? 6 : 4]) : w = u[a], w == null || w.ips.length === 0)
        return h;
      w.offset == null || w.offset === n ? w.offset = 0 : w.offset++;
      const D = w.offset % w.ips.length;
      return h = w.ips[D] ?? null, h == null ? h : Date.now() - h.timestamp > h.ttl ? (w.ips.splice(D, 1), this.pick(B, i, a)) : h;
    }
    setRecords(B, i) {
      const a = Date.now(), h = { records: { 4: null, 6: null } };
      for (const u of i) {
        u.timestamp = a, typeof u.ttl == "number" ? u.ttl = Math.min(u.ttl, this.#e) : u.ttl = this.#e;
        const C = h.records[u.family] ?? { ips: [] };
        C.ips.push(u), h.records[u.family] = C;
      }
      this.#s.set(B.hostname, h);
    }
    getHandler(B, i) {
      return new g(this, B, i);
    }
  }
  class g extends t {
    #e = null;
    #A = null;
    #s = null;
    #r = null;
    #t = null;
    constructor(B, { origin: i, handler: a, dispatch: h }, u) {
      super(a), this.#t = i, this.#r = a, this.#A = { ...u }, this.#e = B, this.#s = h;
    }
    onError(B) {
      switch (B.code) {
        case "ETIMEDOUT":
        case "ECONNREFUSED": {
          if (this.#e.dualStack) {
            this.#e.runLookup(this.#t, this.#A, (i, a) => {
              if (i)
                return this.#r.onError(i);
              const h = {
                ...this.#A,
                origin: a
              };
              this.#s(h, this);
            });
            return;
          }
          this.#r.onError(B);
          return;
        }
        case "ENOTFOUND":
          this.#e.deleteRecord(this.#t);
        // eslint-disable-next-line no-fallthrough
        default:
          this.#r.onError(B);
          break;
      }
    }
  }
  return Qr = (Q) => {
    if (Q?.maxTTL != null && (typeof Q?.maxTTL != "number" || Q?.maxTTL < 0))
      throw new o("Invalid maxTTL. Must be a positive number");
    if (Q?.maxItems != null && (typeof Q?.maxItems != "number" || Q?.maxItems < 1))
      throw new o(
        "Invalid maxItems. Must be a positive number and greater than zero"
      );
    if (Q?.affinity != null && Q?.affinity !== 4 && Q?.affinity !== 6)
      throw new o("Invalid affinity. Must be either 4 or 6");
    if (Q?.dualStack != null && typeof Q?.dualStack != "boolean")
      throw new o("Invalid dualStack. Must be a boolean");
    if (Q?.lookup != null && typeof Q?.lookup != "function")
      throw new o("Invalid lookup. Must be a function");
    if (Q?.pick != null && typeof Q?.pick != "function")
      throw new o("Invalid pick. Must be a function");
    const B = Q?.dualStack ?? !0;
    let i;
    B ? i = Q?.affinity ?? null : i = Q?.affinity ?? 4;
    const a = {
      maxTTL: Q?.maxTTL ?? 1e4,
      // Expressed in ms
      lookup: Q?.lookup ?? null,
      pick: Q?.pick ?? null,
      dualStack: B,
      affinity: i,
      maxItems: Q?.maxItems ?? 1 / 0
    }, h = new c(a);
    return (u) => function(w, D) {
      const b = w.origin.constructor === URL ? w.origin : new URL(w.origin);
      return e(b.hostname) !== 0 ? u(w, D) : (h.runLookup(b, w, (U, G) => {
        if (U)
          return D.onError(U);
        let M = null;
        M = {
          ...w,
          servername: b.hostname,
          // For SNI on TLS
          origin: G,
          headers: {
            host: b.hostname,
            ...w.headers
          }
        }, u(
          M,
          h.getHandler({ origin: b, dispatch: u, handler: D }, w)
        );
      }), !0);
    };
  }, Qr;
}
var Br, No;
function wA() {
  if (No) return Br;
  No = 1;
  const { kConstruct: e } = Oe(), { kEnumerableProperty: r } = Ue(), {
    iteratorMixin: t,
    isValidHeaderName: o,
    isValidHeaderValue: A
  } = rA(), { webidl: n } = Xe(), c = He, g = $e, Q = /* @__PURE__ */ Symbol("headers map"), B = /* @__PURE__ */ Symbol("headers map sorted");
  function i(N) {
    return N === 10 || N === 13 || N === 9 || N === 32;
  }
  function a(N) {
    let d = 0, l = N.length;
    for (; l > d && i(N.charCodeAt(l - 1)); ) --l;
    for (; l > d && i(N.charCodeAt(d)); ) ++d;
    return d === 0 && l === N.length ? N : N.substring(d, l);
  }
  function h(N, d) {
    if (Array.isArray(d))
      for (let l = 0; l < d.length; ++l) {
        const p = d[l];
        if (p.length !== 2)
          throw n.errors.exception({
            header: "Headers constructor",
            message: `expected name/value pair to be length 2, found ${p.length}.`
          });
        u(N, p[0], p[1]);
      }
    else if (typeof d == "object" && d !== null) {
      const l = Object.keys(d);
      for (let p = 0; p < l.length; ++p)
        u(N, l[p], d[l[p]]);
    } else
      throw n.errors.conversionFailed({
        prefix: "Headers constructor",
        argument: "Argument 1",
        types: ["sequence<sequence<ByteString>>", "record<ByteString, ByteString>"]
      });
  }
  function u(N, d, l) {
    if (l = a(l), o(d)) {
      if (!A(l))
        throw n.errors.invalidArgument({
          prefix: "Headers.append",
          value: l,
          type: "header value"
        });
    } else throw n.errors.invalidArgument({
      prefix: "Headers.append",
      value: d,
      type: "header name"
    });
    if (b(N) === "immutable")
      throw new TypeError("immutable");
    return G(N).append(d, l, !1);
  }
  function C(N, d) {
    return N[0] < d[0] ? -1 : 1;
  }
  class w {
    /** @type {[string, string][]|null} */
    cookies = null;
    constructor(d) {
      d instanceof w ? (this[Q] = new Map(d[Q]), this[B] = d[B], this.cookies = d.cookies === null ? null : [...d.cookies]) : (this[Q] = new Map(d), this[B] = null);
    }
    /**
     * @see https://fetch.spec.whatwg.org/#header-list-contains
     * @param {string} name
     * @param {boolean} isLowerCase
     */
    contains(d, l) {
      return this[Q].has(l ? d : d.toLowerCase());
    }
    clear() {
      this[Q].clear(), this[B] = null, this.cookies = null;
    }
    /**
     * @see https://fetch.spec.whatwg.org/#concept-header-list-append
     * @param {string} name
     * @param {string} value
     * @param {boolean} isLowerCase
     */
    append(d, l, p) {
      this[B] = null;
      const s = p ? d : d.toLowerCase(), E = this[Q].get(s);
      if (E) {
        const f = s === "cookie" ? "; " : ", ";
        this[Q].set(s, {
          name: E.name,
          value: `${E.value}${f}${l}`
        });
      } else
        this[Q].set(s, { name: d, value: l });
      s === "set-cookie" && (this.cookies ??= []).push(l);
    }
    /**
     * @see https://fetch.spec.whatwg.org/#concept-header-list-set
     * @param {string} name
     * @param {string} value
     * @param {boolean} isLowerCase
     */
    set(d, l, p) {
      this[B] = null;
      const s = p ? d : d.toLowerCase();
      s === "set-cookie" && (this.cookies = [l]), this[Q].set(s, { name: d, value: l });
    }
    /**
     * @see https://fetch.spec.whatwg.org/#concept-header-list-delete
     * @param {string} name
     * @param {boolean} isLowerCase
     */
    delete(d, l) {
      this[B] = null, l || (d = d.toLowerCase()), d === "set-cookie" && (this.cookies = null), this[Q].delete(d);
    }
    /**
     * @see https://fetch.spec.whatwg.org/#concept-header-list-get
     * @param {string} name
     * @param {boolean} isLowerCase
     * @returns {string | null}
     */
    get(d, l) {
      return this[Q].get(l ? d : d.toLowerCase())?.value ?? null;
    }
    *[Symbol.iterator]() {
      for (const { 0: d, 1: { value: l } } of this[Q])
        yield [d, l];
    }
    get entries() {
      const d = {};
      if (this[Q].size !== 0)
        for (const { name: l, value: p } of this[Q].values())
          d[l] = p;
      return d;
    }
    rawValues() {
      return this[Q].values();
    }
    get entriesList() {
      const d = [];
      if (this[Q].size !== 0)
        for (const { 0: l, 1: { name: p, value: s } } of this[Q])
          if (l === "set-cookie")
            for (const E of this.cookies)
              d.push([p, E]);
          else
            d.push([p, s]);
      return d;
    }
    // https://fetch.spec.whatwg.org/#convert-header-names-to-a-sorted-lowercase-set
    toSortedArray() {
      const d = this[Q].size, l = new Array(d);
      if (d <= 32) {
        if (d === 0)
          return l;
        const p = this[Q][Symbol.iterator](), s = p.next().value;
        l[0] = [s[0], s[1].value], c(s[1].value !== null);
        for (let E = 1, f = 0, I = 0, m = 0, y = 0, S, T; E < d; ++E) {
          for (T = p.next().value, S = l[E] = [T[0], T[1].value], c(S[1] !== null), m = 0, I = E; m < I; )
            y = m + (I - m >> 1), l[y][0] <= S[0] ? m = y + 1 : I = y;
          if (E !== y) {
            for (f = E; f > m; )
              l[f] = l[--f];
            l[m] = S;
          }
        }
        if (!p.next().done)
          throw new TypeError("Unreachable");
        return l;
      } else {
        let p = 0;
        for (const { 0: s, 1: { value: E } } of this[Q])
          l[p++] = [s, E], c(E !== null);
        return l.sort(C);
      }
    }
  }
  class D {
    #e;
    #A;
    constructor(d = void 0) {
      n.util.markAsUncloneable(this), d !== e && (this.#A = new w(), this.#e = "none", d !== void 0 && (d = n.converters.HeadersInit(d, "Headers contructor", "init"), h(this, d)));
    }
    // https://fetch.spec.whatwg.org/#dom-headers-append
    append(d, l) {
      n.brandCheck(this, D), n.argumentLengthCheck(arguments, 2, "Headers.append");
      const p = "Headers.append";
      return d = n.converters.ByteString(d, p, "name"), l = n.converters.ByteString(l, p, "value"), u(this, d, l);
    }
    // https://fetch.spec.whatwg.org/#dom-headers-delete
    delete(d) {
      if (n.brandCheck(this, D), n.argumentLengthCheck(arguments, 1, "Headers.delete"), d = n.converters.ByteString(d, "Headers.delete", "name"), !o(d))
        throw n.errors.invalidArgument({
          prefix: "Headers.delete",
          value: d,
          type: "header name"
        });
      if (this.#e === "immutable")
        throw new TypeError("immutable");
      this.#A.contains(d, !1) && this.#A.delete(d, !1);
    }
    // https://fetch.spec.whatwg.org/#dom-headers-get
    get(d) {
      n.brandCheck(this, D), n.argumentLengthCheck(arguments, 1, "Headers.get");
      const l = "Headers.get";
      if (d = n.converters.ByteString(d, l, "name"), !o(d))
        throw n.errors.invalidArgument({
          prefix: l,
          value: d,
          type: "header name"
        });
      return this.#A.get(d, !1);
    }
    // https://fetch.spec.whatwg.org/#dom-headers-has
    has(d) {
      n.brandCheck(this, D), n.argumentLengthCheck(arguments, 1, "Headers.has");
      const l = "Headers.has";
      if (d = n.converters.ByteString(d, l, "name"), !o(d))
        throw n.errors.invalidArgument({
          prefix: l,
          value: d,
          type: "header name"
        });
      return this.#A.contains(d, !1);
    }
    // https://fetch.spec.whatwg.org/#dom-headers-set
    set(d, l) {
      n.brandCheck(this, D), n.argumentLengthCheck(arguments, 2, "Headers.set");
      const p = "Headers.set";
      if (d = n.converters.ByteString(d, p, "name"), l = n.converters.ByteString(l, p, "value"), l = a(l), o(d)) {
        if (!A(l))
          throw n.errors.invalidArgument({
            prefix: p,
            value: l,
            type: "header value"
          });
      } else throw n.errors.invalidArgument({
        prefix: p,
        value: d,
        type: "header name"
      });
      if (this.#e === "immutable")
        throw new TypeError("immutable");
      this.#A.set(d, l, !1);
    }
    // https://fetch.spec.whatwg.org/#dom-headers-getsetcookie
    getSetCookie() {
      n.brandCheck(this, D);
      const d = this.#A.cookies;
      return d ? [...d] : [];
    }
    // https://fetch.spec.whatwg.org/#concept-header-list-sort-and-combine
    get [B]() {
      if (this.#A[B])
        return this.#A[B];
      const d = [], l = this.#A.toSortedArray(), p = this.#A.cookies;
      if (p === null || p.length === 1)
        return this.#A[B] = l;
      for (let s = 0; s < l.length; ++s) {
        const { 0: E, 1: f } = l[s];
        if (E === "set-cookie")
          for (let I = 0; I < p.length; ++I)
            d.push([E, p[I]]);
        else
          d.push([E, f]);
      }
      return this.#A[B] = d;
    }
    [g.inspect.custom](d, l) {
      return l.depth ??= d, `Headers ${g.formatWithOptions(l, this.#A.entries)}`;
    }
    static getHeadersGuard(d) {
      return d.#e;
    }
    static setHeadersGuard(d, l) {
      d.#e = l;
    }
    static getHeadersList(d) {
      return d.#A;
    }
    static setHeadersList(d, l) {
      d.#A = l;
    }
  }
  const { getHeadersGuard: b, setHeadersGuard: U, getHeadersList: G, setHeadersList: M } = D;
  return Reflect.deleteProperty(D, "getHeadersGuard"), Reflect.deleteProperty(D, "setHeadersGuard"), Reflect.deleteProperty(D, "getHeadersList"), Reflect.deleteProperty(D, "setHeadersList"), t("Headers", D, B, 0, 1), Object.defineProperties(D.prototype, {
    append: r,
    delete: r,
    get: r,
    has: r,
    set: r,
    getSetCookie: r,
    [Symbol.toStringTag]: {
      value: "Headers",
      configurable: !0
    },
    [g.inspect.custom]: {
      enumerable: !1
    }
  }), n.converters.HeadersInit = function(N, d, l) {
    if (n.util.Type(N) === "Object") {
      const p = Reflect.get(N, Symbol.iterator);
      if (!g.types.isProxy(N) && p === D.prototype.entries)
        try {
          return G(N).entriesList;
        } catch {
        }
      return typeof p == "function" ? n.converters["sequence<sequence<ByteString>>"](N, d, l, p.bind(N)) : n.converters["record<ByteString, ByteString>"](N, d, l);
    }
    throw n.errors.conversionFailed({
      prefix: "Headers constructor",
      argument: "Argument 1",
      types: ["sequence<sequence<ByteString>>", "record<ByteString, ByteString>"]
    });
  }, Br = {
    fill: h,
    // for test.
    compareHeaderName: C,
    Headers: D,
    HeadersList: w,
    getHeadersGuard: b,
    setHeadersGuard: U,
    setHeadersList: M,
    getHeadersList: G
  }, Br;
}
var hr, Mo;
function et() {
  if (Mo) return hr;
  Mo = 1;
  const { Headers: e, HeadersList: r, fill: t, getHeadersGuard: o, setHeadersGuard: A, setHeadersList: n } = wA(), { extractBody: c, cloneBody: g, mixinBody: Q, hasFinalizationRegistry: B, streamRegistry: i, bodyUnusable: a } = SA(), h = Ue(), u = $e, { kEnumerableProperty: C } = h, {
    isValidReasonPhrase: w,
    isCancelled: D,
    isAborted: b,
    isBlobLike: U,
    serializeJavascriptValueToJSONString: G,
    isErrorLike: M,
    isomorphicEncode: N,
    environmentSettingsObject: d
  } = rA(), {
    redirectStatusSet: l,
    nullBodyStatus: p
  } = KA(), { kState: s, kHeaders: E } = IA(), { webidl: f } = Xe(), { FormData: I } = XA(), { URLSerializer: m } = eA(), { kConstruct: y } = Oe(), S = He, { types: T } = $e, L = new TextEncoder("utf-8");
  class v {
    // Creates network error Response.
    static error() {
      return we(ge(), "immutable");
    }
    // https://fetch.spec.whatwg.org/#dom-response-json
    static json(W, re = {}) {
      f.argumentLengthCheck(arguments, 1, "Response.json"), re !== null && (re = f.converters.ResponseInit(re));
      const J = L.encode(
        G(W)
      ), _ = c(J), P = we(oe({}), "response");
      return ye(P, re, { body: _[0], type: "application/json" }), P;
    }
    // Creates a redirect Response that redirects to url with status status.
    static redirect(W, re = 302) {
      f.argumentLengthCheck(arguments, 1, "Response.redirect"), W = f.converters.USVString(W), re = f.converters["unsigned short"](re);
      let J;
      try {
        J = new URL(W, d.settingsObject.baseUrl);
      } catch (Z) {
        throw new TypeError(`Failed to parse URL from ${W}`, { cause: Z });
      }
      if (!l.has(re))
        throw new RangeError(`Invalid status code ${re}`);
      const _ = we(oe({}), "immutable");
      _[s].status = re;
      const P = N(m(J));
      return _[s].headersList.append("location", P, !0), _;
    }
    // https://fetch.spec.whatwg.org/#dom-response
    constructor(W = null, re = {}) {
      if (f.util.markAsUncloneable(this), W === y)
        return;
      W !== null && (W = f.converters.BodyInit(W)), re = f.converters.ResponseInit(re), this[s] = oe({}), this[E] = new e(y), A(this[E], "response"), n(this[E], this[s].headersList);
      let J = null;
      if (W != null) {
        const [_, P] = c(W);
        J = { body: _, type: P };
      }
      ye(this, re, J);
    }
    // Returns response’s type, e.g., "cors".
    get type() {
      return f.brandCheck(this, v), this[s].type;
    }
    // Returns response’s URL, if it has one; otherwise the empty string.
    get url() {
      f.brandCheck(this, v);
      const W = this[s].urlList, re = W[W.length - 1] ?? null;
      return re === null ? "" : m(re, !0);
    }
    // Returns whether response was obtained through a redirect.
    get redirected() {
      return f.brandCheck(this, v), this[s].urlList.length > 1;
    }
    // Returns response’s status.
    get status() {
      return f.brandCheck(this, v), this[s].status;
    }
    // Returns whether response’s status is an ok status.
    get ok() {
      return f.brandCheck(this, v), this[s].status >= 200 && this[s].status <= 299;
    }
    // Returns response’s status message.
    get statusText() {
      return f.brandCheck(this, v), this[s].statusText;
    }
    // Returns response’s headers as Headers.
    get headers() {
      return f.brandCheck(this, v), this[E];
    }
    get body() {
      return f.brandCheck(this, v), this[s].body ? this[s].body.stream : null;
    }
    get bodyUsed() {
      return f.brandCheck(this, v), !!this[s].body && h.isDisturbed(this[s].body.stream);
    }
    // Returns a clone of response.
    clone() {
      if (f.brandCheck(this, v), a(this))
        throw f.errors.exception({
          header: "Response.clone",
          message: "Body has already been consumed."
        });
      const W = $(this[s]);
      return B && this[s].body?.stream && i.register(this, new WeakRef(this[s].body.stream)), we(W, o(this[E]));
    }
    [u.inspect.custom](W, re) {
      re.depth === null && (re.depth = 2), re.colors ??= !0;
      const J = {
        status: this.status,
        statusText: this.statusText,
        headers: this.headers,
        body: this.body,
        bodyUsed: this.bodyUsed,
        ok: this.ok,
        redirected: this.redirected,
        type: this.type,
        url: this.url
      };
      return `Response ${u.formatWithOptions(re, J)}`;
    }
  }
  Q(v), Object.defineProperties(v.prototype, {
    type: C,
    url: C,
    status: C,
    ok: C,
    redirected: C,
    statusText: C,
    headers: C,
    clone: C,
    body: C,
    bodyUsed: C,
    [Symbol.toStringTag]: {
      value: "Response",
      configurable: !0
    }
  }), Object.defineProperties(v, {
    json: C,
    redirect: C,
    error: C
  });
  function $(j) {
    if (j.internalResponse)
      return Be(
        $(j.internalResponse),
        j.type
      );
    const W = oe({ ...j, body: null });
    return j.body != null && (W.body = g(W, j.body)), W;
  }
  function oe(j) {
    return {
      aborted: !1,
      rangeRequested: !1,
      timingAllowPassed: !1,
      requestIncludesCredentials: !1,
      type: "default",
      status: 200,
      timingInfo: null,
      cacheState: "",
      statusText: "",
      ...j,
      headersList: j?.headersList ? new r(j?.headersList) : new r(),
      urlList: j?.urlList ? [...j.urlList] : []
    };
  }
  function ge(j) {
    const W = M(j);
    return oe({
      type: "error",
      status: 0,
      error: W ? j : new Error(j && String(j)),
      aborted: j && j.name === "AbortError"
    });
  }
  function ae(j) {
    return (
      // A network error is a response whose type is "error",
      j.type === "error" && // status is 0
      j.status === 0
    );
  }
  function he(j, W) {
    return W = {
      internalResponse: j,
      ...W
    }, new Proxy(j, {
      get(re, J) {
        return J in W ? W[J] : re[J];
      },
      set(re, J, _) {
        return S(!(J in W)), re[J] = _, !0;
      }
    });
  }
  function Be(j, W) {
    if (W === "basic")
      return he(j, {
        type: "basic",
        headersList: j.headersList
      });
    if (W === "cors")
      return he(j, {
        type: "cors",
        headersList: j.headersList
      });
    if (W === "opaque")
      return he(j, {
        type: "opaque",
        urlList: Object.freeze([]),
        status: 0,
        statusText: "",
        body: null
      });
    if (W === "opaqueredirect")
      return he(j, {
        type: "opaqueredirect",
        status: 0,
        statusText: "",
        headersList: [],
        body: null
      });
    S(!1);
  }
  function Qe(j, W = null) {
    return S(D(j)), b(j) ? ge(Object.assign(new DOMException("The operation was aborted.", "AbortError"), { cause: W })) : ge(Object.assign(new DOMException("Request was cancelled."), { cause: W }));
  }
  function ye(j, W, re) {
    if (W.status !== null && (W.status < 200 || W.status > 599))
      throw new RangeError('init["status"] must be in the range of 200 to 599, inclusive.');
    if ("statusText" in W && W.statusText != null && !w(String(W.statusText)))
      throw new TypeError("Invalid statusText");
    if ("status" in W && W.status != null && (j[s].status = W.status), "statusText" in W && W.statusText != null && (j[s].statusText = W.statusText), "headers" in W && W.headers != null && t(j[E], W.headers), re) {
      if (p.includes(j.status))
        throw f.errors.exception({
          header: "Response constructor",
          message: `Invalid response status code ${j.status}`
        });
      j[s].body = re.body, re.type != null && !j[s].headersList.contains("content-type", !0) && j[s].headersList.append("content-type", re.type, !0);
    }
  }
  function we(j, W) {
    const re = new v(y);
    return re[s] = j, re[E] = new e(y), n(re[E], j.headersList), A(re[E], W), B && j.body?.stream && i.register(re, new WeakRef(j.body.stream)), re;
  }
  return f.converters.ReadableStream = f.interfaceConverter(
    ReadableStream
  ), f.converters.FormData = f.interfaceConverter(
    I
  ), f.converters.URLSearchParams = f.interfaceConverter(
    URLSearchParams
  ), f.converters.XMLHttpRequestBodyInit = function(j, W, re) {
    return typeof j == "string" ? f.converters.USVString(j, W, re) : U(j) ? f.converters.Blob(j, W, re, { strict: !1 }) : ArrayBuffer.isView(j) || T.isArrayBuffer(j) ? f.converters.BufferSource(j, W, re) : h.isFormDataLike(j) ? f.converters.FormData(j, W, re, { strict: !1 }) : j instanceof URLSearchParams ? f.converters.URLSearchParams(j, W, re) : f.converters.DOMString(j, W, re);
  }, f.converters.BodyInit = function(j, W, re) {
    return j instanceof ReadableStream ? f.converters.ReadableStream(j, W, re) : j?.[Symbol.asyncIterator] ? j : f.converters.XMLHttpRequestBodyInit(j, W, re);
  }, f.converters.ResponseInit = f.dictionaryConverter([
    {
      key: "status",
      converter: f.converters["unsigned short"],
      defaultValue: () => 200
    },
    {
      key: "statusText",
      converter: f.converters.ByteString,
      defaultValue: () => ""
    },
    {
      key: "headers",
      converter: f.converters.HeadersInit
    }
  ]), hr = {
    isNetworkError: ae,
    makeNetworkError: ge,
    makeResponse: oe,
    makeAppropriateNetworkError: Qe,
    filterResponse: Be,
    Response: v,
    cloneResponse: $,
    fromInnerResponse: we
  }, hr;
}
var Ir, Lo;
function Ca() {
  if (Lo) return Ir;
  Lo = 1;
  const { kConnected: e, kSize: r } = Oe();
  class t {
    constructor(n) {
      this.value = n;
    }
    deref() {
      return this.value[e] === 0 && this.value[r] === 0 ? void 0 : this.value;
    }
  }
  class o {
    constructor(n) {
      this.finalizer = n;
    }
    register(n, c) {
      n.on && n.on("disconnect", () => {
        n[e] === 0 && n[r] === 0 && this.finalizer(c);
      });
    }
    unregister(n) {
    }
  }
  return Ir = function() {
    return process.env.NODE_V8_COVERAGE && process.version.startsWith("v18") ? (process._rawDebug("Using compatibility WeakRef and FinalizationRegistry"), {
      WeakRef: t,
      FinalizationRegistry: o
    }) : { WeakRef, FinalizationRegistry };
  }, Ir;
}
var Cr, Go;
function GA() {
  if (Go) return Cr;
  Go = 1;
  const { extractBody: e, mixinBody: r, cloneBody: t, bodyUnusable: o } = SA(), { Headers: A, fill: n, HeadersList: c, setHeadersGuard: g, getHeadersGuard: Q, setHeadersList: B, getHeadersList: i } = wA(), { FinalizationRegistry: a } = Ca()(), h = Ue(), u = $e, {
    isValidHTTPToken: C,
    sameOrigin: w,
    environmentSettingsObject: D
  } = rA(), {
    forbiddenMethodsSet: b,
    corsSafeListedMethodsSet: U,
    referrerPolicy: G,
    requestRedirect: M,
    requestMode: N,
    requestCredentials: d,
    requestCache: l,
    requestDuplex: p
  } = KA(), { kEnumerableProperty: s, normalizedMethodRecordsBase: E, normalizedMethodRecords: f } = h, { kHeaders: I, kSignal: m, kState: y, kDispatcher: S } = IA(), { webidl: T } = Xe(), { URLSerializer: L } = eA(), { kConstruct: v } = Oe(), $ = He, { getMaxListeners: oe, setMaxListeners: ge, getEventListeners: ae, defaultMaxListeners: he } = kA, Be = /* @__PURE__ */ Symbol("abortController"), Qe = new a(({ signal: P, abort: Z }) => {
    P.removeEventListener("abort", Z);
  }), ye = /* @__PURE__ */ new WeakMap();
  function we(P) {
    return Z;
    function Z() {
      const se = P.deref();
      if (se !== void 0) {
        Qe.unregister(Z), this.removeEventListener("abort", Z), se.abort(this.reason);
        const le = ye.get(se.signal);
        if (le !== void 0) {
          if (le.size !== 0) {
            for (const ne of le) {
              const fe = ne.deref();
              fe !== void 0 && fe.abort(this.reason);
            }
            le.clear();
          }
          ye.delete(se.signal);
        }
      }
    }
  }
  let j = !1;
  class W {
    // https://fetch.spec.whatwg.org/#dom-request
    constructor(Z, se = {}) {
      if (T.util.markAsUncloneable(this), Z === v)
        return;
      const le = "Request constructor";
      T.argumentLengthCheck(arguments, 1, le), Z = T.converters.RequestInfo(Z, le, "input"), se = T.converters.RequestInit(se, le, "init");
      let ne = null, fe = null;
      const Me = D.settingsObject.baseUrl;
      let pe = null;
      if (typeof Z == "string") {
        this[S] = se.dispatcher;
        let q;
        try {
          q = new URL(Z, Me);
        } catch (ie) {
          throw new TypeError("Failed to parse URL from " + Z, { cause: ie });
        }
        if (q.username || q.password)
          throw new TypeError(
            "Request cannot be constructed from a URL that includes credentials: " + Z
          );
        ne = re({ urlList: [q] }), fe = "cors";
      } else
        this[S] = se.dispatcher || Z[S], $(Z instanceof W), ne = Z[y], pe = Z[m];
      const Le = D.settingsObject.origin;
      let ke = "client";
      if (ne.window?.constructor?.name === "EnvironmentSettingsObject" && w(ne.window, Le) && (ke = ne.window), se.window != null)
        throw new TypeError(`'window' option '${ke}' must be null`);
      "window" in se && (ke = "no-window"), ne = re({
        // URL request’s URL.
        // undici implementation note: this is set as the first item in request's urlList in makeRequest
        // method request’s method.
        method: ne.method,
        // header list A copy of request’s header list.
        // undici implementation note: headersList is cloned in makeRequest
        headersList: ne.headersList,
        // unsafe-request flag Set.
        unsafeRequest: ne.unsafeRequest,
        // client This’s relevant settings object.
        client: D.settingsObject,
        // window window.
        window: ke,
        // priority request’s priority.
        priority: ne.priority,
        // origin request’s origin. The propagation of the origin is only significant for navigation requests
        // being handled by a service worker. In this scenario a request can have an origin that is different
        // from the current client.
        origin: ne.origin,
        // referrer request’s referrer.
        referrer: ne.referrer,
        // referrer policy request’s referrer policy.
        referrerPolicy: ne.referrerPolicy,
        // mode request’s mode.
        mode: ne.mode,
        // credentials mode request’s credentials mode.
        credentials: ne.credentials,
        // cache mode request’s cache mode.
        cache: ne.cache,
        // redirect mode request’s redirect mode.
        redirect: ne.redirect,
        // integrity metadata request’s integrity metadata.
        integrity: ne.integrity,
        // keepalive request’s keepalive.
        keepalive: ne.keepalive,
        // reload-navigation flag request’s reload-navigation flag.
        reloadNavigation: ne.reloadNavigation,
        // history-navigation flag request’s history-navigation flag.
        historyNavigation: ne.historyNavigation,
        // URL list A clone of request’s URL list.
        urlList: [...ne.urlList]
      });
      const be = Object.keys(se).length !== 0;
      if (be && (ne.mode === "navigate" && (ne.mode = "same-origin"), ne.reloadNavigation = !1, ne.historyNavigation = !1, ne.origin = "client", ne.referrer = "client", ne.referrerPolicy = "", ne.url = ne.urlList[ne.urlList.length - 1], ne.urlList = [ne.url]), se.referrer !== void 0) {
        const q = se.referrer;
        if (q === "")
          ne.referrer = "no-referrer";
        else {
          let ie;
          try {
            ie = new URL(q, Me);
          } catch (Ee) {
            throw new TypeError(`Referrer "${q}" is not a valid URL.`, { cause: Ee });
          }
          ie.protocol === "about:" && ie.hostname === "client" || Le && !w(ie, D.settingsObject.baseUrl) ? ne.referrer = "client" : ne.referrer = ie;
        }
      }
      se.referrerPolicy !== void 0 && (ne.referrerPolicy = se.referrerPolicy);
      let de;
      if (se.mode !== void 0 ? de = se.mode : de = fe, de === "navigate")
        throw T.errors.exception({
          header: "Request constructor",
          message: "invalid request mode navigate."
        });
      if (de != null && (ne.mode = de), se.credentials !== void 0 && (ne.credentials = se.credentials), se.cache !== void 0 && (ne.cache = se.cache), ne.cache === "only-if-cached" && ne.mode !== "same-origin")
        throw new TypeError(
          "'only-if-cached' can be set only with 'same-origin' mode"
        );
      if (se.redirect !== void 0 && (ne.redirect = se.redirect), se.integrity != null && (ne.integrity = String(se.integrity)), se.keepalive !== void 0 && (ne.keepalive = !!se.keepalive), se.method !== void 0) {
        let q = se.method;
        const ie = f[q];
        if (ie !== void 0)
          ne.method = ie;
        else {
          if (!C(q))
            throw new TypeError(`'${q}' is not a valid HTTP method.`);
          const Ee = q.toUpperCase();
          if (b.has(Ee))
            throw new TypeError(`'${q}' HTTP method is unsupported.`);
          q = E[Ee] ?? q, ne.method = q;
        }
        !j && ne.method === "patch" && (process.emitWarning("Using `patch` is highly likely to result in a `405 Method Not Allowed`. `PATCH` is much more likely to succeed.", {
          code: "UNDICI-FETCH-patch"
        }), j = !0);
      }
      se.signal !== void 0 && (pe = se.signal), this[y] = ne;
      const _e = new AbortController();
      if (this[m] = _e.signal, pe != null) {
        if (!pe || typeof pe.aborted != "boolean" || typeof pe.addEventListener != "function")
          throw new TypeError(
            "Failed to construct 'Request': member signal is not of type AbortSignal."
          );
        if (pe.aborted)
          _e.abort(pe.reason);
        else {
          this[Be] = _e;
          const q = new WeakRef(_e), ie = we(q);
          try {
            (typeof oe == "function" && oe(pe) === he || ae(pe, "abort").length >= he) && ge(1500, pe);
          } catch {
          }
          h.addAbortListener(pe, ie), Qe.register(_e, { signal: pe, abort: ie }, ie);
        }
      }
      if (this[I] = new A(v), B(this[I], ne.headersList), g(this[I], "request"), de === "no-cors") {
        if (!U.has(ne.method))
          throw new TypeError(
            `'${ne.method} is unsupported in no-cors mode.`
          );
        g(this[I], "request-no-cors");
      }
      if (be) {
        const q = i(this[I]), ie = se.headers !== void 0 ? se.headers : new c(q);
        if (q.clear(), ie instanceof c) {
          for (const { name: Ee, value: Ie } of ie.rawValues())
            q.append(Ee, Ie, !1);
          q.cookies = ie.cookies;
        } else
          n(this[I], ie);
      }
      const Pe = Z instanceof W ? Z[y].body : null;
      if ((se.body != null || Pe != null) && (ne.method === "GET" || ne.method === "HEAD"))
        throw new TypeError("Request with GET/HEAD method cannot have body.");
      let Je = null;
      if (se.body != null) {
        const [q, ie] = e(
          se.body,
          ne.keepalive
        );
        Je = q, ie && !i(this[I]).contains("content-type", !0) && this[I].append("content-type", ie);
      }
      const X = Je ?? Pe;
      if (X != null && X.source == null) {
        if (Je != null && se.duplex == null)
          throw new TypeError("RequestInit: duplex option is required when sending a body.");
        if (ne.mode !== "same-origin" && ne.mode !== "cors")
          throw new TypeError(
            'If request is made from ReadableStream, mode should be "same-origin" or "cors"'
          );
        ne.useCORSPreflightFlag = !0;
      }
      let R = X;
      if (Je == null && Pe != null) {
        if (o(Z))
          throw new TypeError(
            "Cannot construct a Request with a Request object that has already been used."
          );
        const q = new TransformStream();
        Pe.stream.pipeThrough(q), R = {
          source: Pe.source,
          length: Pe.length,
          stream: q.readable
        };
      }
      this[y].body = R;
    }
    // Returns request’s HTTP method, which is "GET" by default.
    get method() {
      return T.brandCheck(this, W), this[y].method;
    }
    // Returns the URL of request as a string.
    get url() {
      return T.brandCheck(this, W), L(this[y].url);
    }
    // Returns a Headers object consisting of the headers associated with request.
    // Note that headers added in the network layer by the user agent will not
    // be accounted for in this object, e.g., the "Host" header.
    get headers() {
      return T.brandCheck(this, W), this[I];
    }
    // Returns the kind of resource requested by request, e.g., "document"
    // or "script".
    get destination() {
      return T.brandCheck(this, W), this[y].destination;
    }
    // Returns the referrer of request. Its value can be a same-origin URL if
    // explicitly set in init, the empty string to indicate no referrer, and
    // "about:client" when defaulting to the global’s default. This is used
    // during fetching to determine the value of the `Referer` header of the
    // request being made.
    get referrer() {
      return T.brandCheck(this, W), this[y].referrer === "no-referrer" ? "" : this[y].referrer === "client" ? "about:client" : this[y].referrer.toString();
    }
    // Returns the referrer policy associated with request.
    // This is used during fetching to compute the value of the request’s
    // referrer.
    get referrerPolicy() {
      return T.brandCheck(this, W), this[y].referrerPolicy;
    }
    // Returns the mode associated with request, which is a string indicating
    // whether the request will use CORS, or will be restricted to same-origin
    // URLs.
    get mode() {
      return T.brandCheck(this, W), this[y].mode;
    }
    // Returns the credentials mode associated with request,
    // which is a string indicating whether credentials will be sent with the
    // request always, never, or only when sent to a same-origin URL.
    get credentials() {
      return this[y].credentials;
    }
    // Returns the cache mode associated with request,
    // which is a string indicating how the request will
    // interact with the browser’s cache when fetching.
    get cache() {
      return T.brandCheck(this, W), this[y].cache;
    }
    // Returns the redirect mode associated with request,
    // which is a string indicating how redirects for the
    // request will be handled during fetching. A request
    // will follow redirects by default.
    get redirect() {
      return T.brandCheck(this, W), this[y].redirect;
    }
    // Returns request’s subresource integrity metadata, which is a
    // cryptographic hash of the resource being fetched. Its value
    // consists of multiple hashes separated by whitespace. [SRI]
    get integrity() {
      return T.brandCheck(this, W), this[y].integrity;
    }
    // Returns a boolean indicating whether or not request can outlive the
    // global in which it was created.
    get keepalive() {
      return T.brandCheck(this, W), this[y].keepalive;
    }
    // Returns a boolean indicating whether or not request is for a reload
    // navigation.
    get isReloadNavigation() {
      return T.brandCheck(this, W), this[y].reloadNavigation;
    }
    // Returns a boolean indicating whether or not request is for a history
    // navigation (a.k.a. back-forward navigation).
    get isHistoryNavigation() {
      return T.brandCheck(this, W), this[y].historyNavigation;
    }
    // Returns the signal associated with request, which is an AbortSignal
    // object indicating whether or not request has been aborted, and its
    // abort event handler.
    get signal() {
      return T.brandCheck(this, W), this[m];
    }
    get body() {
      return T.brandCheck(this, W), this[y].body ? this[y].body.stream : null;
    }
    get bodyUsed() {
      return T.brandCheck(this, W), !!this[y].body && h.isDisturbed(this[y].body.stream);
    }
    get duplex() {
      return T.brandCheck(this, W), "half";
    }
    // Returns a clone of request.
    clone() {
      if (T.brandCheck(this, W), o(this))
        throw new TypeError("unusable");
      const Z = J(this[y]), se = new AbortController();
      if (this.signal.aborted)
        se.abort(this.signal.reason);
      else {
        let le = ye.get(this.signal);
        le === void 0 && (le = /* @__PURE__ */ new Set(), ye.set(this.signal, le));
        const ne = new WeakRef(se);
        le.add(ne), h.addAbortListener(
          se.signal,
          we(ne)
        );
      }
      return _(Z, se.signal, Q(this[I]));
    }
    [u.inspect.custom](Z, se) {
      se.depth === null && (se.depth = 2), se.colors ??= !0;
      const le = {
        method: this.method,
        url: this.url,
        headers: this.headers,
        destination: this.destination,
        referrer: this.referrer,
        referrerPolicy: this.referrerPolicy,
        mode: this.mode,
        credentials: this.credentials,
        cache: this.cache,
        redirect: this.redirect,
        integrity: this.integrity,
        keepalive: this.keepalive,
        isReloadNavigation: this.isReloadNavigation,
        isHistoryNavigation: this.isHistoryNavigation,
        signal: this.signal
      };
      return `Request ${u.formatWithOptions(se, le)}`;
    }
  }
  r(W);
  function re(P) {
    return {
      method: P.method ?? "GET",
      localURLsOnly: P.localURLsOnly ?? !1,
      unsafeRequest: P.unsafeRequest ?? !1,
      body: P.body ?? null,
      client: P.client ?? null,
      reservedClient: P.reservedClient ?? null,
      replacesClientId: P.replacesClientId ?? "",
      window: P.window ?? "client",
      keepalive: P.keepalive ?? !1,
      serviceWorkers: P.serviceWorkers ?? "all",
      initiator: P.initiator ?? "",
      destination: P.destination ?? "",
      priority: P.priority ?? null,
      origin: P.origin ?? "client",
      policyContainer: P.policyContainer ?? "client",
      referrer: P.referrer ?? "client",
      referrerPolicy: P.referrerPolicy ?? "",
      mode: P.mode ?? "no-cors",
      useCORSPreflightFlag: P.useCORSPreflightFlag ?? !1,
      credentials: P.credentials ?? "same-origin",
      useCredentials: P.useCredentials ?? !1,
      cache: P.cache ?? "default",
      redirect: P.redirect ?? "follow",
      integrity: P.integrity ?? "",
      cryptoGraphicsNonceMetadata: P.cryptoGraphicsNonceMetadata ?? "",
      parserMetadata: P.parserMetadata ?? "",
      reloadNavigation: P.reloadNavigation ?? !1,
      historyNavigation: P.historyNavigation ?? !1,
      userActivation: P.userActivation ?? !1,
      taintedOrigin: P.taintedOrigin ?? !1,
      redirectCount: P.redirectCount ?? 0,
      responseTainting: P.responseTainting ?? "basic",
      preventNoCacheCacheControlHeaderModification: P.preventNoCacheCacheControlHeaderModification ?? !1,
      done: P.done ?? !1,
      timingAllowFailed: P.timingAllowFailed ?? !1,
      urlList: P.urlList,
      url: P.urlList[0],
      headersList: P.headersList ? new c(P.headersList) : new c()
    };
  }
  function J(P) {
    const Z = re({ ...P, body: null });
    return P.body != null && (Z.body = t(Z, P.body)), Z;
  }
  function _(P, Z, se) {
    const le = new W(v);
    return le[y] = P, le[m] = Z, le[I] = new A(v), B(le[I], P.headersList), g(le[I], se), le;
  }
  return Object.defineProperties(W.prototype, {
    method: s,
    url: s,
    headers: s,
    redirect: s,
    clone: s,
    signal: s,
    duplex: s,
    destination: s,
    body: s,
    bodyUsed: s,
    isHistoryNavigation: s,
    isReloadNavigation: s,
    keepalive: s,
    integrity: s,
    cache: s,
    credentials: s,
    attribute: s,
    referrerPolicy: s,
    referrer: s,
    mode: s,
    [Symbol.toStringTag]: {
      value: "Request",
      configurable: !0
    }
  }), T.converters.Request = T.interfaceConverter(
    W
  ), T.converters.RequestInfo = function(P, Z, se) {
    return typeof P == "string" ? T.converters.USVString(P, Z, se) : P instanceof W ? T.converters.Request(P, Z, se) : T.converters.USVString(P, Z, se);
  }, T.converters.AbortSignal = T.interfaceConverter(
    AbortSignal
  ), T.converters.RequestInit = T.dictionaryConverter([
    {
      key: "method",
      converter: T.converters.ByteString
    },
    {
      key: "headers",
      converter: T.converters.HeadersInit
    },
    {
      key: "body",
      converter: T.nullableConverter(
        T.converters.BodyInit
      )
    },
    {
      key: "referrer",
      converter: T.converters.USVString
    },
    {
      key: "referrerPolicy",
      converter: T.converters.DOMString,
      // https://w3c.github.io/webappsec-referrer-policy/#referrer-policy
      allowedValues: G
    },
    {
      key: "mode",
      converter: T.converters.DOMString,
      // https://fetch.spec.whatwg.org/#concept-request-mode
      allowedValues: N
    },
    {
      key: "credentials",
      converter: T.converters.DOMString,
      // https://fetch.spec.whatwg.org/#requestcredentials
      allowedValues: d
    },
    {
      key: "cache",
      converter: T.converters.DOMString,
      // https://fetch.spec.whatwg.org/#requestcache
      allowedValues: l
    },
    {
      key: "redirect",
      converter: T.converters.DOMString,
      // https://fetch.spec.whatwg.org/#requestredirect
      allowedValues: M
    },
    {
      key: "integrity",
      converter: T.converters.DOMString
    },
    {
      key: "keepalive",
      converter: T.converters.boolean
    },
    {
      key: "signal",
      converter: T.nullableConverter(
        (P) => T.converters.AbortSignal(
          P,
          "RequestInit",
          "signal",
          { strict: !1 }
        )
      )
    },
    {
      key: "window",
      converter: T.converters.any
    },
    {
      key: "duplex",
      converter: T.converters.DOMString,
      allowedValues: p
    },
    {
      key: "dispatcher",
      // undici specific option
      converter: T.converters.any
    }
  ]), Cr = { Request: W, makeRequest: re, fromInnerRequest: _, cloneRequest: J }, Cr;
}
var dr, vo;
function At() {
  if (vo) return dr;
  vo = 1;
  const {
    makeNetworkError: e,
    makeAppropriateNetworkError: r,
    filterResponse: t,
    makeResponse: o,
    fromInnerResponse: A
  } = et(), { HeadersList: n } = wA(), { Request: c, cloneRequest: g } = GA(), Q = ts, {
    bytesMatch: B,
    makePolicyContainer: i,
    clonePolicyContainer: a,
    requestBadPort: h,
    TAOCheck: u,
    appendRequestOriginHeader: C,
    responseLocationURL: w,
    requestCurrentURL: D,
    setRequestReferrerPolicyOnRedirect: b,
    tryUpgradeRequestToAPotentiallyTrustworthyURL: U,
    createOpaqueTimingInfo: G,
    appendFetchMetadata: M,
    corsCheck: N,
    crossOriginResourcePolicyCheck: d,
    determineRequestsReferrer: l,
    coarsenedSharedCurrentTime: p,
    createDeferredPromise: s,
    isBlobLike: E,
    sameOrigin: f,
    isCancelled: I,
    isAborted: m,
    isErrorLike: y,
    fullyReadBody: S,
    readableStreamClose: T,
    isomorphicEncode: L,
    urlIsLocal: v,
    urlIsHttpHttpsScheme: $,
    urlHasHttpsScheme: oe,
    clampAndCoarsenConnectionTimingInfo: ge,
    simpleRangeHeaderValue: ae,
    buildContentRange: he,
    createInflate: Be,
    extractMimeType: Qe
  } = rA(), { kState: ye, kDispatcher: we } = IA(), j = He, { safelyExtractBody: W, extractBody: re } = SA(), {
    redirectStatusSet: J,
    nullBodyStatus: _,
    safeMethodsSet: P,
    requestBodyHeader: Z,
    subresourceSet: se
  } = KA(), le = kA, { Readable: ne, pipeline: fe, finished: Me } = tA, { addAbortListener: pe, isErrored: Le, isReadable: ke, bufferToLowerCasedHeaderName: be } = Ue(), { dataURLProcessor: de, serializeAMimeType: _e, minimizeSupportedMimeType: Pe } = eA(), { getGlobalDispatcher: Je } = is(), { webidl: X } = Xe(), { STATUS_CODES: R } = qA, q = ["GET", "HEAD"], ie = typeof __UNDICI_IS_NODE__ < "u" || typeof esbuildDetection < "u" ? "node" : "undici";
  let Ee;
  class Ie extends le {
    constructor(V) {
      super(), this.dispatcher = V, this.connection = null, this.dump = !1, this.state = "ongoing";
    }
    terminate(V) {
      this.state === "ongoing" && (this.state = "terminated", this.connection?.destroy(V), this.emit("terminated", V));
    }
    // https://fetch.spec.whatwg.org/#fetch-controller-abort
    abort(V) {
      this.state === "ongoing" && (this.state = "aborted", V || (V = new DOMException("The operation was aborted.", "AbortError")), this.serializedAbortReason = V, this.connection?.destroy(V), this.emit("terminated", V));
    }
  }
  function De(k) {
    qe(k, "fetch");
  }
  function ve(k, V = void 0) {
    X.argumentLengthCheck(arguments, 1, "globalThis.fetch");
    let H = s(), x;
    try {
      x = new c(k, V);
    } catch (xe) {
      return H.reject(xe), H.promise;
    }
    const te = x[ye];
    if (x.signal.aborted)
      return Ce(H, te, null, x.signal.reason), H.promise;
    te.client.globalObject?.constructor?.name === "ServiceWorkerGlobalScope" && (te.serviceWorkers = "none");
    let ce = null, Fe = !1, Ge = null;
    return pe(
      x.signal,
      () => {
        Fe = !0, j(Ge != null), Ge.abort(x.signal.reason);
        const xe = ce?.deref();
        Ce(H, te, xe, x.signal.reason);
      }
    ), Ge = Y({
      request: te,
      processResponseEndOfBody: De,
      processResponse: (xe) => {
        if (!Fe) {
          if (xe.aborted) {
            Ce(H, te, ce, Ge.serializedAbortReason);
            return;
          }
          if (xe.type === "error") {
            H.reject(new TypeError("fetch failed", { cause: xe.error }));
            return;
          }
          ce = new WeakRef(A(xe, "immutable")), H.resolve(ce.deref()), H = null;
        }
      },
      dispatcher: x[we]
      // undici
    }), H.promise;
  }
  function qe(k, V = "other") {
    if (k.type === "error" && k.aborted || !k.urlList?.length)
      return;
    const H = k.urlList[0];
    let x = k.timingInfo, te = k.cacheState;
    $(H) && x !== null && (k.timingAllowPassed || (x = G({
      startTime: x.startTime
    }), te = ""), x.endTime = p(), k.timingInfo = x, Ze(
      x,
      H.href,
      V,
      globalThis,
      te
    ));
  }
  const Ze = performance.markResourceTiming;
  function Ce(k, V, H, x) {
    if (k && k.reject(x), V.body != null && ke(V.body?.stream) && V.body.stream.cancel(x).catch((z) => {
      if (z.code !== "ERR_INVALID_STATE")
        throw z;
    }), H == null)
      return;
    const te = H[ye];
    te.body != null && ke(te.body?.stream) && te.body.stream.cancel(x).catch((z) => {
      if (z.code !== "ERR_INVALID_STATE")
        throw z;
    });
  }
  function Y({
    request: k,
    processRequestBodyChunkLength: V,
    processRequestEndOfBody: H,
    processResponse: x,
    processResponseEndOfBody: te,
    processResponseConsumeBody: z,
    useParallelQueue: ce = !1,
    dispatcher: Fe = Je()
    // undici
  }) {
    j(Fe);
    let Ge = null, Ne = !1;
    k.client != null && (Ge = k.client.globalObject, Ne = k.client.crossOriginIsolatedCapability);
    const xe = p(Ne), oA = G({
      startTime: xe
    }), Te = {
      controller: new Ie(Fe),
      request: k,
      timingInfo: oA,
      processRequestBodyChunkLength: V,
      processRequestEndOfBody: H,
      processResponse: x,
      processResponseConsumeBody: z,
      processResponseEndOfBody: te,
      taskDestination: Ge,
      crossOriginIsolatedCapability: Ne
    };
    return j(!k.body || k.body.stream), k.window === "client" && (k.window = k.client?.globalObject?.constructor?.name === "Window" ? k.client : "no-window"), k.origin === "client" && (k.origin = k.client.origin), k.policyContainer === "client" && (k.client != null ? k.policyContainer = a(
      k.client.policyContainer
    ) : k.policyContainer = i()), k.headersList.contains("accept", !0) || k.headersList.append("accept", "*/*", !0), k.headersList.contains("accept-language", !0) || k.headersList.append("accept-language", "*", !0), k.priority, se.has(k.destination), ee(Te).catch((Ke) => {
      Te.controller.terminate(Ke);
    }), Te.controller;
  }
  async function ee(k, V = !1) {
    const H = k.request;
    let x = null;
    if (H.localURLsOnly && !v(D(H)) && (x = e("local URLs only")), U(H), h(H) === "blocked" && (x = e("bad port")), H.referrerPolicy === "" && (H.referrerPolicy = H.policyContainer.referrerPolicy), H.referrer !== "no-referrer" && (H.referrer = l(H)), x === null && (x = await (async () => {
      const z = D(H);
      return (
        // - request’s current URL’s origin is same origin with request’s origin,
        //   and request’s response tainting is "basic"
        f(z, H.url) && H.responseTainting === "basic" || // request’s current URL’s scheme is "data"
        z.protocol === "data:" || // - request’s mode is "navigate" or "websocket"
        H.mode === "navigate" || H.mode === "websocket" ? (H.responseTainting = "basic", await K(k)) : H.mode === "same-origin" ? e('request mode cannot be "same-origin"') : H.mode === "no-cors" ? H.redirect !== "follow" ? e(
          'redirect mode cannot be "follow" for "no-cors" request'
        ) : (H.responseTainting = "opaque", await K(k)) : $(D(H)) ? (H.responseTainting = "cors", await Re(k)) : e("URL scheme must be a HTTP(S) scheme")
      );
    })()), V)
      return x;
    x.status !== 0 && !x.internalResponse && (H.responseTainting, H.responseTainting === "basic" ? x = t(x, "basic") : H.responseTainting === "cors" ? x = t(x, "cors") : H.responseTainting === "opaque" ? x = t(x, "opaque") : j(!1));
    let te = x.status === 0 ? x : x.internalResponse;
    if (te.urlList.length === 0 && te.urlList.push(...H.urlList), H.timingAllowFailed || (x.timingAllowPassed = !0), x.type === "opaque" && te.status === 206 && te.rangeRequested && !H.headers.contains("range", !0) && (x = te = e()), x.status !== 0 && (H.method === "HEAD" || H.method === "CONNECT" || _.includes(te.status)) && (te.body = null, k.controller.dump = !0), H.integrity) {
      const z = (Fe) => ue(k, e(Fe));
      if (H.responseTainting === "opaque" || x.body == null) {
        z(x.error);
        return;
      }
      const ce = (Fe) => {
        if (!B(Fe, H.integrity)) {
          z("integrity mismatch");
          return;
        }
        x.body = W(Fe)[0], ue(k, x);
      };
      await S(x.body, ce, z);
    } else
      ue(k, x);
  }
  function K(k) {
    if (I(k) && k.request.redirectCount === 0)
      return Promise.resolve(r(k));
    const { request: V } = k, { protocol: H } = D(V);
    switch (H) {
      case "about:":
        return Promise.resolve(e("about scheme is not supported"));
      case "blob:": {
        Ee || (Ee = sA.resolveObjectURL);
        const x = D(V);
        if (x.search.length !== 0)
          return Promise.resolve(e("NetworkError when attempting to fetch resource."));
        const te = Ee(x.toString());
        if (V.method !== "GET" || !E(te))
          return Promise.resolve(e("invalid method"));
        const z = o(), ce = te.size, Fe = L(`${ce}`), Ge = te.type;
        if (V.headersList.contains("range", !0)) {
          z.rangeRequested = !0;
          const Ne = V.headersList.get("range", !0), xe = ae(Ne, !0);
          if (xe === "failure")
            return Promise.resolve(e("failed to fetch the data URL"));
          let { rangeStartValue: oA, rangeEndValue: Te } = xe;
          if (oA === null)
            oA = ce - Te, Te = oA + Te - 1;
          else {
            if (oA >= ce)
              return Promise.resolve(e("Range start is greater than the blob's size."));
            (Te === null || Te >= ce) && (Te = ce - 1);
          }
          const Ke = te.slice(oA, Te, Ge), AA = re(Ke);
          z.body = AA[0];
          const We = L(`${Ke.size}`), aA = he(oA, Te, ce);
          z.status = 206, z.statusText = "Partial Content", z.headersList.set("content-length", We, !0), z.headersList.set("content-type", Ge, !0), z.headersList.set("content-range", aA, !0);
        } else {
          const Ne = re(te);
          z.statusText = "OK", z.body = Ne[0], z.headersList.set("content-length", Fe, !0), z.headersList.set("content-type", Ge, !0);
        }
        return Promise.resolve(z);
      }
      case "data:": {
        const x = D(V), te = de(x);
        if (te === "failure")
          return Promise.resolve(e("failed to fetch the data URL"));
        const z = _e(te.mimeType);
        return Promise.resolve(o({
          statusText: "OK",
          headersList: [
            ["content-type", { name: "Content-Type", value: z }]
          ],
          body: W(te.body)[0]
        }));
      }
      case "file:":
        return Promise.resolve(e("not implemented... yet..."));
      case "http:":
      case "https:":
        return Re(k).catch((x) => e(x));
      default:
        return Promise.resolve(e("unknown scheme"));
    }
  }
  function Ae(k, V) {
    k.request.done = !0, k.processResponseDone != null && queueMicrotask(() => k.processResponseDone(V));
  }
  function ue(k, V) {
    let H = k.timingInfo;
    const x = () => {
      const z = Date.now();
      k.request.destination === "document" && (k.controller.fullTimingInfo = H), k.controller.reportTimingSteps = () => {
        if (k.request.url.protocol !== "https:")
          return;
        H.endTime = z;
        let Fe = V.cacheState;
        const Ge = V.bodyInfo;
        V.timingAllowPassed || (H = G(H), Fe = "");
        let Ne = 0;
        if (k.request.mode !== "navigator" || !V.hasCrossOriginRedirects) {
          Ne = V.status;
          const xe = Qe(V.headersList);
          xe !== "failure" && (Ge.contentType = Pe(xe));
        }
        k.request.initiatorType != null && Ze(H, k.request.url.href, k.request.initiatorType, globalThis, Fe, Ge, Ne);
      };
      const ce = () => {
        k.request.done = !0, k.processResponseEndOfBody != null && queueMicrotask(() => k.processResponseEndOfBody(V)), k.request.initiatorType != null && k.controller.reportTimingSteps();
      };
      queueMicrotask(() => ce());
    };
    k.processResponse != null && queueMicrotask(() => {
      k.processResponse(V), k.processResponse = null;
    });
    const te = V.type === "error" ? V : V.internalResponse ?? V;
    te.body == null ? x() : Me(te.body.stream, () => {
      x();
    });
  }
  async function Re(k) {
    const V = k.request;
    let H = null, x = null;
    const te = k.timingInfo;
    if (V.serviceWorkers, H === null) {
      if (V.redirect === "follow" && (V.serviceWorkers = "none"), x = H = await F(k), V.responseTainting === "cors" && N(V, H) === "failure")
        return e("cors failure");
      u(V, H) === "failure" && (V.timingAllowFailed = !0);
    }
    return (V.responseTainting === "opaque" || H.type === "opaque") && d(
      V.origin,
      V.client,
      V.destination,
      x
    ) === "blocked" ? e("blocked") : (J.has(x.status) && (V.redirect !== "manual" && k.controller.connection.destroy(void 0, !1), V.redirect === "error" ? H = e("unexpected redirect") : V.redirect === "manual" ? H = x : V.redirect === "follow" ? H = await Se(k, H) : j(!1)), H.timingInfo = te, H);
  }
  function Se(k, V) {
    const H = k.request, x = V.internalResponse ? V.internalResponse : V;
    let te;
    try {
      if (te = w(
        x,
        D(H).hash
      ), te == null)
        return V;
    } catch (ce) {
      return Promise.resolve(e(ce));
    }
    if (!$(te))
      return Promise.resolve(e("URL scheme must be a HTTP(S) scheme"));
    if (H.redirectCount === 20)
      return Promise.resolve(e("redirect count exceeded"));
    if (H.redirectCount += 1, H.mode === "cors" && (te.username || te.password) && !f(H, te))
      return Promise.resolve(e('cross origin not allowed for request mode "cors"'));
    if (H.responseTainting === "cors" && (te.username || te.password))
      return Promise.resolve(e(
        'URL cannot contain credentials for request mode "cors"'
      ));
    if (x.status !== 303 && H.body != null && H.body.source == null)
      return Promise.resolve(e());
    if ([301, 302].includes(x.status) && H.method === "POST" || x.status === 303 && !q.includes(H.method)) {
      H.method = "GET", H.body = null;
      for (const ce of Z)
        H.headersList.delete(ce);
    }
    f(D(H), te) || (H.headersList.delete("authorization", !0), H.headersList.delete("proxy-authorization", !0), H.headersList.delete("cookie", !0), H.headersList.delete("host", !0)), H.body != null && (j(H.body.source != null), H.body = W(H.body.source)[0]);
    const z = k.timingInfo;
    return z.redirectEndTime = z.postRedirectStartTime = p(k.crossOriginIsolatedCapability), z.redirectStartTime === 0 && (z.redirectStartTime = z.startTime), H.urlList.push(te), b(H, x), ee(k, !0);
  }
  async function F(k, V = !1, H = !1) {
    const x = k.request;
    let te = null, z = null, ce = null;
    x.window === "no-window" && x.redirect === "error" ? (te = k, z = x) : (z = g(x), te = { ...k }, te.request = z);
    const Fe = x.credentials === "include" || x.credentials === "same-origin" && x.responseTainting === "basic", Ge = z.body ? z.body.length : null;
    let Ne = null;
    if (z.body == null && ["POST", "PUT"].includes(z.method) && (Ne = "0"), Ge != null && (Ne = L(`${Ge}`)), Ne != null && z.headersList.append("content-length", Ne, !0), Ge != null && z.keepalive, z.referrer instanceof URL && z.headersList.append("referer", L(z.referrer.href), !0), C(z), M(z), z.headersList.contains("user-agent", !0) || z.headersList.append("user-agent", ie), z.cache === "default" && (z.headersList.contains("if-modified-since", !0) || z.headersList.contains("if-none-match", !0) || z.headersList.contains("if-unmodified-since", !0) || z.headersList.contains("if-match", !0) || z.headersList.contains("if-range", !0)) && (z.cache = "no-store"), z.cache === "no-cache" && !z.preventNoCacheCacheControlHeaderModification && !z.headersList.contains("cache-control", !0) && z.headersList.append("cache-control", "max-age=0", !0), (z.cache === "no-store" || z.cache === "reload") && (z.headersList.contains("pragma", !0) || z.headersList.append("pragma", "no-cache", !0), z.headersList.contains("cache-control", !0) || z.headersList.append("cache-control", "no-cache", !0)), z.headersList.contains("range", !0) && z.headersList.append("accept-encoding", "identity", !0), z.headersList.contains("accept-encoding", !0) || (oe(D(z)) ? z.headersList.append("accept-encoding", "br, gzip, deflate", !0) : z.headersList.append("accept-encoding", "gzip, deflate", !0)), z.headersList.delete("host", !0), z.cache = "no-store", z.cache !== "no-store" && z.cache, ce == null) {
      if (z.cache === "only-if-cached")
        return e("only if cached");
      const xe = await O(
        te,
        Fe,
        H
      );
      !P.has(z.method) && xe.status >= 200 && xe.status <= 399, ce == null && (ce = xe);
    }
    if (ce.urlList = [...z.urlList], z.headersList.contains("range", !0) && (ce.rangeRequested = !0), ce.requestIncludesCredentials = Fe, ce.status === 407)
      return x.window === "no-window" ? e() : I(k) ? r(k) : e("proxy authentication required");
    if (
      // response’s status is 421
      ce.status === 421 && // isNewConnectionFetch is false
      !H && // request’s body is null, or request’s body is non-null and request’s body’s source is non-null
      (x.body == null || x.body.source != null)
    ) {
      if (I(k))
        return r(k);
      k.controller.connection.destroy(), ce = await F(
        k,
        V,
        !0
      );
    }
    return ce;
  }
  async function O(k, V = !1, H = !1) {
    j(!k.controller.connection || k.controller.connection.destroyed), k.controller.connection = {
      abort: null,
      destroyed: !1,
      destroy(Te, Ke = !0) {
        this.destroyed || (this.destroyed = !0, Ke && this.abort?.(Te ?? new DOMException("The operation was aborted.", "AbortError")));
      }
    };
    const x = k.request;
    let te = null;
    const z = k.timingInfo;
    x.cache = "no-store", x.mode;
    let ce = null;
    if (x.body == null && k.processRequestEndOfBody)
      queueMicrotask(() => k.processRequestEndOfBody());
    else if (x.body != null) {
      const Te = async function* (We) {
        I(k) || (yield We, k.processRequestBodyChunkLength?.(We.byteLength));
      }, Ke = () => {
        I(k) || k.processRequestEndOfBody && k.processRequestEndOfBody();
      }, AA = (We) => {
        I(k) || (We.name === "AbortError" ? k.controller.abort() : k.controller.terminate(We));
      };
      ce = (async function* () {
        try {
          for await (const We of x.body.stream)
            yield* Te(We);
          Ke();
        } catch (We) {
          AA(We);
        }
      })();
    }
    try {
      const { body: Te, status: Ke, statusText: AA, headersList: We, socket: aA } = await oA({ body: ce });
      if (aA)
        te = o({ status: Ke, statusText: AA, headersList: We, socket: aA });
      else {
        const ze = Te[Symbol.asyncIterator]();
        k.controller.next = () => ze.next(), te = o({ status: Ke, statusText: AA, headersList: We });
      }
    } catch (Te) {
      return Te.name === "AbortError" ? (k.controller.connection.destroy(), r(k, Te)) : e(Te);
    }
    const Fe = async () => {
      await k.controller.resume();
    }, Ge = (Te) => {
      I(k) || k.controller.abort(Te);
    }, Ne = new ReadableStream(
      {
        async start(Te) {
          k.controller.controller = Te;
        },
        async pull(Te) {
          await Fe();
        },
        async cancel(Te) {
          await Ge(Te);
        },
        type: "bytes"
      }
    );
    te.body = { stream: Ne, source: null, length: null }, k.controller.onAborted = xe, k.controller.on("terminated", xe), k.controller.resume = async () => {
      for (; ; ) {
        let Te, Ke;
        try {
          const { done: We, value: aA } = await k.controller.next();
          if (m(k))
            break;
          Te = We ? void 0 : aA;
        } catch (We) {
          k.controller.ended && !z.encodedBodySize ? Te = void 0 : (Te = We, Ke = !0);
        }
        if (Te === void 0) {
          T(k.controller.controller), Ae(k, te);
          return;
        }
        if (z.decodedBodySize += Te?.byteLength ?? 0, Ke) {
          k.controller.terminate(Te);
          return;
        }
        const AA = new Uint8Array(Te);
        if (AA.byteLength && k.controller.controller.enqueue(AA), Le(Ne)) {
          k.controller.terminate();
          return;
        }
        if (k.controller.controller.desiredSize <= 0)
          return;
      }
    };
    function xe(Te) {
      m(k) ? (te.aborted = !0, ke(Ne) && k.controller.controller.error(
        k.controller.serializedAbortReason
      )) : ke(Ne) && k.controller.controller.error(new TypeError("terminated", {
        cause: y(Te) ? Te : void 0
      })), k.controller.connection.destroy();
    }
    return te;
    function oA({ body: Te }) {
      const Ke = D(x), AA = k.controller.dispatcher;
      return new Promise((We, aA) => AA.dispatch(
        {
          path: Ke.pathname + Ke.search,
          origin: Ke.origin,
          method: x.method,
          body: AA.isMockActive ? x.body && (x.body.source || x.body.stream) : Te,
          headers: x.headersList.entries,
          maxRedirections: 0,
          upgrade: x.mode === "websocket" ? "websocket" : void 0
        },
        {
          body: null,
          abort: null,
          onConnect(ze) {
            const { connection: je } = k.controller;
            z.finalConnectionTimingInfo = ge(void 0, z.postRedirectStartTime, k.crossOriginIsolatedCapability), je.destroyed ? ze(new DOMException("The operation was aborted.", "AbortError")) : (k.controller.on("terminated", ze), this.abort = je.abort = ze), z.finalNetworkRequestStartTime = p(k.crossOriginIsolatedCapability);
          },
          onResponseStarted() {
            z.finalNetworkResponseStartTime = p(k.crossOriginIsolatedCapability);
          },
          onHeaders(ze, je, nt, YA) {
            if (ze < 200)
              return;
            let EA = "";
            const JA = new n();
            for (let nA = 0; nA < je.length; nA += 2)
              JA.append(be(je[nA]), je[nA + 1].toString("latin1"), !0);
            EA = JA.get("location", !0), this.body = new ne({ read: nt });
            const CA = [], mi = EA && x.redirect === "follow" && J.has(ze);
            if (x.method !== "HEAD" && x.method !== "CONNECT" && !_.includes(ze) && !mi) {
              const nA = JA.get("content-encoding", !0), HA = nA ? nA.toLowerCase().split(",") : [], hs = 5;
              if (HA.length > hs)
                return aA(new Error(`too many content-encodings in response: ${HA.length}, maximum allowed is ${hs}`)), !0;
              for (let it = HA.length - 1; it >= 0; --it) {
                const VA = HA[it].trim();
                if (VA === "x-gzip" || VA === "gzip")
                  CA.push(Q.createGunzip({
                    // Be less strict when decoding compressed responses, since sometimes
                    // servers send slightly invalid responses that are still accepted
                    // by common browsers.
                    // Always using Z_SYNC_FLUSH is what cURL does.
                    flush: Q.constants.Z_SYNC_FLUSH,
                    finishFlush: Q.constants.Z_SYNC_FLUSH
                  }));
                else if (VA === "deflate")
                  CA.push(Be({
                    flush: Q.constants.Z_SYNC_FLUSH,
                    finishFlush: Q.constants.Z_SYNC_FLUSH
                  }));
                else if (VA === "br")
                  CA.push(Q.createBrotliDecompress({
                    flush: Q.constants.BROTLI_OPERATION_FLUSH,
                    finishFlush: Q.constants.BROTLI_OPERATION_FLUSH
                  }));
                else {
                  CA.length = 0;
                  break;
                }
              }
            }
            const Bs = this.onError.bind(this);
            return We({
              status: ze,
              statusText: YA,
              headersList: JA,
              body: CA.length ? fe(this.body, ...CA, (nA) => {
                nA && this.onError(nA);
              }).on("error", Bs) : this.body.on("error", Bs)
            }), !0;
          },
          onData(ze) {
            if (k.controller.dump)
              return;
            const je = ze;
            return z.encodedBodySize += je.byteLength, this.body.push(je);
          },
          onComplete() {
            this.abort && k.controller.off("terminated", this.abort), k.controller.onAborted && k.controller.off("terminated", k.controller.onAborted), k.controller.ended = !0, this.body.push(null);
          },
          onError(ze) {
            this.abort && k.controller.off("terminated", this.abort), this.body?.destroy(ze), k.controller.terminate(ze), aA(ze);
          },
          onUpgrade(ze, je, nt) {
            if (ze !== 101)
              return;
            const YA = new n();
            for (let EA = 0; EA < je.length; EA += 2)
              YA.append(be(je[EA]), je[EA + 1].toString("latin1"), !0);
            return We({
              status: ze,
              statusText: R[ze],
              headersList: YA,
              socket: nt
            }), !0;
          }
        }
      ));
    }
  }
  return dr = {
    fetch: ve,
    Fetch: Ie,
    fetching: Y,
    finalizeAndReportTiming: qe
  }, dr;
}
var fr, Yo;
function ri() {
  return Yo || (Yo = 1, fr = {
    kState: /* @__PURE__ */ Symbol("FileReader state"),
    kResult: /* @__PURE__ */ Symbol("FileReader result"),
    kError: /* @__PURE__ */ Symbol("FileReader error"),
    kLastProgressEventFired: /* @__PURE__ */ Symbol("FileReader last progress event fired timestamp"),
    kEvents: /* @__PURE__ */ Symbol("FileReader events"),
    kAborted: /* @__PURE__ */ Symbol("FileReader aborted")
  }), fr;
}
var pr, Jo;
function da() {
  if (Jo) return pr;
  Jo = 1;
  const { webidl: e } = Xe(), r = /* @__PURE__ */ Symbol("ProgressEvent state");
  class t extends Event {
    constructor(A, n = {}) {
      A = e.converters.DOMString(A, "ProgressEvent constructor", "type"), n = e.converters.ProgressEventInit(n ?? {}), super(A, n), this[r] = {
        lengthComputable: n.lengthComputable,
        loaded: n.loaded,
        total: n.total
      };
    }
    get lengthComputable() {
      return e.brandCheck(this, t), this[r].lengthComputable;
    }
    get loaded() {
      return e.brandCheck(this, t), this[r].loaded;
    }
    get total() {
      return e.brandCheck(this, t), this[r].total;
    }
  }
  return e.converters.ProgressEventInit = e.dictionaryConverter([
    {
      key: "lengthComputable",
      converter: e.converters.boolean,
      defaultValue: () => !1
    },
    {
      key: "loaded",
      converter: e.converters["unsigned long long"],
      defaultValue: () => 0
    },
    {
      key: "total",
      converter: e.converters["unsigned long long"],
      defaultValue: () => 0
    },
    {
      key: "bubbles",
      converter: e.converters.boolean,
      defaultValue: () => !1
    },
    {
      key: "cancelable",
      converter: e.converters.boolean,
      defaultValue: () => !1
    },
    {
      key: "composed",
      converter: e.converters.boolean,
      defaultValue: () => !1
    }
  ]), pr = {
    ProgressEvent: t
  }, pr;
}
var wr, Ho;
function fa() {
  if (Ho) return wr;
  Ho = 1;
  function e(r) {
    if (!r)
      return "failure";
    switch (r.trim().toLowerCase()) {
      case "unicode-1-1-utf-8":
      case "unicode11utf8":
      case "unicode20utf8":
      case "utf-8":
      case "utf8":
      case "x-unicode20utf8":
        return "UTF-8";
      case "866":
      case "cp866":
      case "csibm866":
      case "ibm866":
        return "IBM866";
      case "csisolatin2":
      case "iso-8859-2":
      case "iso-ir-101":
      case "iso8859-2":
      case "iso88592":
      case "iso_8859-2":
      case "iso_8859-2:1987":
      case "l2":
      case "latin2":
        return "ISO-8859-2";
      case "csisolatin3":
      case "iso-8859-3":
      case "iso-ir-109":
      case "iso8859-3":
      case "iso88593":
      case "iso_8859-3":
      case "iso_8859-3:1988":
      case "l3":
      case "latin3":
        return "ISO-8859-3";
      case "csisolatin4":
      case "iso-8859-4":
      case "iso-ir-110":
      case "iso8859-4":
      case "iso88594":
      case "iso_8859-4":
      case "iso_8859-4:1988":
      case "l4":
      case "latin4":
        return "ISO-8859-4";
      case "csisolatincyrillic":
      case "cyrillic":
      case "iso-8859-5":
      case "iso-ir-144":
      case "iso8859-5":
      case "iso88595":
      case "iso_8859-5":
      case "iso_8859-5:1988":
        return "ISO-8859-5";
      case "arabic":
      case "asmo-708":
      case "csiso88596e":
      case "csiso88596i":
      case "csisolatinarabic":
      case "ecma-114":
      case "iso-8859-6":
      case "iso-8859-6-e":
      case "iso-8859-6-i":
      case "iso-ir-127":
      case "iso8859-6":
      case "iso88596":
      case "iso_8859-6":
      case "iso_8859-6:1987":
        return "ISO-8859-6";
      case "csisolatingreek":
      case "ecma-118":
      case "elot_928":
      case "greek":
      case "greek8":
      case "iso-8859-7":
      case "iso-ir-126":
      case "iso8859-7":
      case "iso88597":
      case "iso_8859-7":
      case "iso_8859-7:1987":
      case "sun_eu_greek":
        return "ISO-8859-7";
      case "csiso88598e":
      case "csisolatinhebrew":
      case "hebrew":
      case "iso-8859-8":
      case "iso-8859-8-e":
      case "iso-ir-138":
      case "iso8859-8":
      case "iso88598":
      case "iso_8859-8":
      case "iso_8859-8:1988":
      case "visual":
        return "ISO-8859-8";
      case "csiso88598i":
      case "iso-8859-8-i":
      case "logical":
        return "ISO-8859-8-I";
      case "csisolatin6":
      case "iso-8859-10":
      case "iso-ir-157":
      case "iso8859-10":
      case "iso885910":
      case "l6":
      case "latin6":
        return "ISO-8859-10";
      case "iso-8859-13":
      case "iso8859-13":
      case "iso885913":
        return "ISO-8859-13";
      case "iso-8859-14":
      case "iso8859-14":
      case "iso885914":
        return "ISO-8859-14";
      case "csisolatin9":
      case "iso-8859-15":
      case "iso8859-15":
      case "iso885915":
      case "iso_8859-15":
      case "l9":
        return "ISO-8859-15";
      case "iso-8859-16":
        return "ISO-8859-16";
      case "cskoi8r":
      case "koi":
      case "koi8":
      case "koi8-r":
      case "koi8_r":
        return "KOI8-R";
      case "koi8-ru":
      case "koi8-u":
        return "KOI8-U";
      case "csmacintosh":
      case "mac":
      case "macintosh":
      case "x-mac-roman":
        return "macintosh";
      case "iso-8859-11":
      case "iso8859-11":
      case "iso885911":
      case "tis-620":
      case "windows-874":
        return "windows-874";
      case "cp1250":
      case "windows-1250":
      case "x-cp1250":
        return "windows-1250";
      case "cp1251":
      case "windows-1251":
      case "x-cp1251":
        return "windows-1251";
      case "ansi_x3.4-1968":
      case "ascii":
      case "cp1252":
      case "cp819":
      case "csisolatin1":
      case "ibm819":
      case "iso-8859-1":
      case "iso-ir-100":
      case "iso8859-1":
      case "iso88591":
      case "iso_8859-1":
      case "iso_8859-1:1987":
      case "l1":
      case "latin1":
      case "us-ascii":
      case "windows-1252":
      case "x-cp1252":
        return "windows-1252";
      case "cp1253":
      case "windows-1253":
      case "x-cp1253":
        return "windows-1253";
      case "cp1254":
      case "csisolatin5":
      case "iso-8859-9":
      case "iso-ir-148":
      case "iso8859-9":
      case "iso88599":
      case "iso_8859-9":
      case "iso_8859-9:1989":
      case "l5":
      case "latin5":
      case "windows-1254":
      case "x-cp1254":
        return "windows-1254";
      case "cp1255":
      case "windows-1255":
      case "x-cp1255":
        return "windows-1255";
      case "cp1256":
      case "windows-1256":
      case "x-cp1256":
        return "windows-1256";
      case "cp1257":
      case "windows-1257":
      case "x-cp1257":
        return "windows-1257";
      case "cp1258":
      case "windows-1258":
      case "x-cp1258":
        return "windows-1258";
      case "x-mac-cyrillic":
      case "x-mac-ukrainian":
        return "x-mac-cyrillic";
      case "chinese":
      case "csgb2312":
      case "csiso58gb231280":
      case "gb2312":
      case "gb_2312":
      case "gb_2312-80":
      case "gbk":
      case "iso-ir-58":
      case "x-gbk":
        return "GBK";
      case "gb18030":
        return "gb18030";
      case "big5":
      case "big5-hkscs":
      case "cn-big5":
      case "csbig5":
      case "x-x-big5":
        return "Big5";
      case "cseucpkdfmtjapanese":
      case "euc-jp":
      case "x-euc-jp":
        return "EUC-JP";
      case "csiso2022jp":
      case "iso-2022-jp":
        return "ISO-2022-JP";
      case "csshiftjis":
      case "ms932":
      case "ms_kanji":
      case "shift-jis":
      case "shift_jis":
      case "sjis":
      case "windows-31j":
      case "x-sjis":
        return "Shift_JIS";
      case "cseuckr":
      case "csksc56011987":
      case "euc-kr":
      case "iso-ir-149":
      case "korean":
      case "ks_c_5601-1987":
      case "ks_c_5601-1989":
      case "ksc5601":
      case "ksc_5601":
      case "windows-949":
        return "EUC-KR";
      case "csiso2022kr":
      case "hz-gb-2312":
      case "iso-2022-cn":
      case "iso-2022-cn-ext":
      case "iso-2022-kr":
      case "replacement":
        return "replacement";
      case "unicodefffe":
      case "utf-16be":
        return "UTF-16BE";
      case "csunicode":
      case "iso-10646-ucs-2":
      case "ucs-2":
      case "unicode":
      case "unicodefeff":
      case "utf-16":
      case "utf-16le":
        return "UTF-16LE";
      case "x-user-defined":
        return "x-user-defined";
      default:
        return "failure";
    }
  }
  return wr = {
    getEncoding: e
  }, wr;
}
var mr, Vo;
function pa() {
  if (Vo) return mr;
  Vo = 1;
  const {
    kState: e,
    kError: r,
    kResult: t,
    kAborted: o,
    kLastProgressEventFired: A
  } = ri(), { ProgressEvent: n } = da(), { getEncoding: c } = fa(), { serializeAMimeType: g, parseMIMEType: Q } = eA(), { types: B } = $e, { StringDecoder: i } = Hi, { btoa: a } = sA, h = {
    enumerable: !0,
    writable: !1,
    configurable: !1
  };
  function u(G, M, N, d) {
    if (G[e] === "loading")
      throw new DOMException("Invalid state", "InvalidStateError");
    G[e] = "loading", G[t] = null, G[r] = null;
    const p = M.stream().getReader(), s = [];
    let E = p.read(), f = !0;
    (async () => {
      for (; !G[o]; )
        try {
          const { done: I, value: m } = await E;
          if (f && !G[o] && queueMicrotask(() => {
            C("loadstart", G);
          }), f = !1, !I && B.isUint8Array(m))
            s.push(m), (G[A] === void 0 || Date.now() - G[A] >= 50) && !G[o] && (G[A] = Date.now(), queueMicrotask(() => {
              C("progress", G);
            })), E = p.read();
          else if (I) {
            queueMicrotask(() => {
              G[e] = "done";
              try {
                const y = w(s, N, M.type, d);
                if (G[o])
                  return;
                G[t] = y, C("load", G);
              } catch (y) {
                G[r] = y, C("error", G);
              }
              G[e] !== "loading" && C("loadend", G);
            });
            break;
          }
        } catch (I) {
          if (G[o])
            return;
          queueMicrotask(() => {
            G[e] = "done", G[r] = I, C("error", G), G[e] !== "loading" && C("loadend", G);
          });
          break;
        }
    })();
  }
  function C(G, M) {
    const N = new n(G, {
      bubbles: !1,
      cancelable: !1
    });
    M.dispatchEvent(N);
  }
  function w(G, M, N, d) {
    switch (M) {
      case "DataURL": {
        let l = "data:";
        const p = Q(N || "application/octet-stream");
        p !== "failure" && (l += g(p)), l += ";base64,";
        const s = new i("latin1");
        for (const E of G)
          l += a(s.write(E));
        return l += a(s.end()), l;
      }
      case "Text": {
        let l = "failure";
        if (d && (l = c(d)), l === "failure" && N) {
          const p = Q(N);
          p !== "failure" && (l = c(p.parameters.get("charset")));
        }
        return l === "failure" && (l = "UTF-8"), D(G, l);
      }
      case "ArrayBuffer":
        return U(G).buffer;
      case "BinaryString": {
        let l = "";
        const p = new i("latin1");
        for (const s of G)
          l += p.write(s);
        return l += p.end(), l;
      }
    }
  }
  function D(G, M) {
    const N = U(G), d = b(N);
    let l = 0;
    d !== null && (M = d, l = d === "UTF-8" ? 3 : 2);
    const p = N.slice(l);
    return new TextDecoder(M).decode(p);
  }
  function b(G) {
    const [M, N, d] = G;
    return M === 239 && N === 187 && d === 191 ? "UTF-8" : M === 254 && N === 255 ? "UTF-16BE" : M === 255 && N === 254 ? "UTF-16LE" : null;
  }
  function U(G) {
    const M = G.reduce((d, l) => d + l.byteLength, 0);
    let N = 0;
    return G.reduce((d, l) => (d.set(l, N), N += l.byteLength, d), new Uint8Array(M));
  }
  return mr = {
    staticPropertyDescriptors: h,
    readOperation: u,
    fireAProgressEvent: C
  }, mr;
}
var yr, Po;
function wa() {
  if (Po) return yr;
  Po = 1;
  const {
    staticPropertyDescriptors: e,
    readOperation: r,
    fireAProgressEvent: t
  } = pa(), {
    kState: o,
    kError: A,
    kResult: n,
    kEvents: c,
    kAborted: g
  } = ri(), { webidl: Q } = Xe(), { kEnumerableProperty: B } = Ue();
  class i extends EventTarget {
    constructor() {
      super(), this[o] = "empty", this[n] = null, this[A] = null, this[c] = {
        loadend: null,
        error: null,
        abort: null,
        load: null,
        progress: null,
        loadstart: null
      };
    }
    /**
     * @see https://w3c.github.io/FileAPI/#dfn-readAsArrayBuffer
     * @param {import('buffer').Blob} blob
     */
    readAsArrayBuffer(h) {
      Q.brandCheck(this, i), Q.argumentLengthCheck(arguments, 1, "FileReader.readAsArrayBuffer"), h = Q.converters.Blob(h, { strict: !1 }), r(this, h, "ArrayBuffer");
    }
    /**
     * @see https://w3c.github.io/FileAPI/#readAsBinaryString
     * @param {import('buffer').Blob} blob
     */
    readAsBinaryString(h) {
      Q.brandCheck(this, i), Q.argumentLengthCheck(arguments, 1, "FileReader.readAsBinaryString"), h = Q.converters.Blob(h, { strict: !1 }), r(this, h, "BinaryString");
    }
    /**
     * @see https://w3c.github.io/FileAPI/#readAsDataText
     * @param {import('buffer').Blob} blob
     * @param {string?} encoding
     */
    readAsText(h, u = void 0) {
      Q.brandCheck(this, i), Q.argumentLengthCheck(arguments, 1, "FileReader.readAsText"), h = Q.converters.Blob(h, { strict: !1 }), u !== void 0 && (u = Q.converters.DOMString(u, "FileReader.readAsText", "encoding")), r(this, h, "Text", u);
    }
    /**
     * @see https://w3c.github.io/FileAPI/#dfn-readAsDataURL
     * @param {import('buffer').Blob} blob
     */
    readAsDataURL(h) {
      Q.brandCheck(this, i), Q.argumentLengthCheck(arguments, 1, "FileReader.readAsDataURL"), h = Q.converters.Blob(h, { strict: !1 }), r(this, h, "DataURL");
    }
    /**
     * @see https://w3c.github.io/FileAPI/#dfn-abort
     */
    abort() {
      if (this[o] === "empty" || this[o] === "done") {
        this[n] = null;
        return;
      }
      this[o] === "loading" && (this[o] = "done", this[n] = null), this[g] = !0, t("abort", this), this[o] !== "loading" && t("loadend", this);
    }
    /**
     * @see https://w3c.github.io/FileAPI/#dom-filereader-readystate
     */
    get readyState() {
      switch (Q.brandCheck(this, i), this[o]) {
        case "empty":
          return this.EMPTY;
        case "loading":
          return this.LOADING;
        case "done":
          return this.DONE;
      }
    }
    /**
     * @see https://w3c.github.io/FileAPI/#dom-filereader-result
     */
    get result() {
      return Q.brandCheck(this, i), this[n];
    }
    /**
     * @see https://w3c.github.io/FileAPI/#dom-filereader-error
     */
    get error() {
      return Q.brandCheck(this, i), this[A];
    }
    get onloadend() {
      return Q.brandCheck(this, i), this[c].loadend;
    }
    set onloadend(h) {
      Q.brandCheck(this, i), this[c].loadend && this.removeEventListener("loadend", this[c].loadend), typeof h == "function" ? (this[c].loadend = h, this.addEventListener("loadend", h)) : this[c].loadend = null;
    }
    get onerror() {
      return Q.brandCheck(this, i), this[c].error;
    }
    set onerror(h) {
      Q.brandCheck(this, i), this[c].error && this.removeEventListener("error", this[c].error), typeof h == "function" ? (this[c].error = h, this.addEventListener("error", h)) : this[c].error = null;
    }
    get onloadstart() {
      return Q.brandCheck(this, i), this[c].loadstart;
    }
    set onloadstart(h) {
      Q.brandCheck(this, i), this[c].loadstart && this.removeEventListener("loadstart", this[c].loadstart), typeof h == "function" ? (this[c].loadstart = h, this.addEventListener("loadstart", h)) : this[c].loadstart = null;
    }
    get onprogress() {
      return Q.brandCheck(this, i), this[c].progress;
    }
    set onprogress(h) {
      Q.brandCheck(this, i), this[c].progress && this.removeEventListener("progress", this[c].progress), typeof h == "function" ? (this[c].progress = h, this.addEventListener("progress", h)) : this[c].progress = null;
    }
    get onload() {
      return Q.brandCheck(this, i), this[c].load;
    }
    set onload(h) {
      Q.brandCheck(this, i), this[c].load && this.removeEventListener("load", this[c].load), typeof h == "function" ? (this[c].load = h, this.addEventListener("load", h)) : this[c].load = null;
    }
    get onabort() {
      return Q.brandCheck(this, i), this[c].abort;
    }
    set onabort(h) {
      Q.brandCheck(this, i), this[c].abort && this.removeEventListener("abort", this[c].abort), typeof h == "function" ? (this[c].abort = h, this.addEventListener("abort", h)) : this[c].abort = null;
    }
  }
  return i.EMPTY = i.prototype.EMPTY = 0, i.LOADING = i.prototype.LOADING = 1, i.DONE = i.prototype.DONE = 2, Object.defineProperties(i.prototype, {
    EMPTY: e,
    LOADING: e,
    DONE: e,
    readAsArrayBuffer: B,
    readAsBinaryString: B,
    readAsText: B,
    readAsDataURL: B,
    abort: B,
    readyState: B,
    result: B,
    error: B,
    onloadstart: B,
    onprogress: B,
    onload: B,
    onabort: B,
    onerror: B,
    onloadend: B,
    [Symbol.toStringTag]: {
      value: "FileReader",
      writable: !1,
      enumerable: !1,
      configurable: !0
    }
  }), Object.defineProperties(i, {
    EMPTY: e,
    LOADING: e,
    DONE: e
  }), yr = {
    FileReader: i
  }, yr;
}
var Dr, xo;
function cs() {
  return xo || (xo = 1, Dr = {
    kConstruct: Oe().kConstruct
  }), Dr;
}
var Rr, Oo;
function ma() {
  if (Oo) return Rr;
  Oo = 1;
  const e = He, { URLSerializer: r } = eA(), { isValidHeaderName: t } = rA();
  function o(n, c, g = !1) {
    const Q = r(n, g), B = r(c, g);
    return Q === B;
  }
  function A(n) {
    e(n !== null);
    const c = [];
    for (let g of n.split(","))
      g = g.trim(), t(g) && c.push(g);
    return c;
  }
  return Rr = {
    urlEquals: o,
    getFieldValues: A
  }, Rr;
}
var kr, _o;
function ya() {
  if (_o) return kr;
  _o = 1;
  const { kConstruct: e } = cs(), { urlEquals: r, getFieldValues: t } = ma(), { kEnumerableProperty: o, isDisturbed: A } = Ue(), { webidl: n } = Xe(), { Response: c, cloneResponse: g, fromInnerResponse: Q } = et(), { Request: B, fromInnerRequest: i } = GA(), { kState: a } = IA(), { fetching: h } = At(), { urlIsHttpHttpsScheme: u, createDeferredPromise: C, readAllBytes: w } = rA(), D = He;
  class b {
    /**
     * @see https://w3c.github.io/ServiceWorker/#dfn-relevant-request-response-list
     * @type {requestResponseList}
     */
    #e;
    constructor() {
      arguments[0] !== e && n.illegalConstructor(), n.util.markAsUncloneable(this), this.#e = arguments[1];
    }
    async match(M, N = {}) {
      n.brandCheck(this, b);
      const d = "Cache.match";
      n.argumentLengthCheck(arguments, 1, d), M = n.converters.RequestInfo(M, d, "request"), N = n.converters.CacheQueryOptions(N, d, "options");
      const l = this.#t(M, N, 1);
      if (l.length !== 0)
        return l[0];
    }
    async matchAll(M = void 0, N = {}) {
      n.brandCheck(this, b);
      const d = "Cache.matchAll";
      return M !== void 0 && (M = n.converters.RequestInfo(M, d, "request")), N = n.converters.CacheQueryOptions(N, d, "options"), this.#t(M, N);
    }
    async add(M) {
      n.brandCheck(this, b);
      const N = "Cache.add";
      n.argumentLengthCheck(arguments, 1, N), M = n.converters.RequestInfo(M, N, "request");
      const d = [M];
      return await this.addAll(d);
    }
    async addAll(M) {
      n.brandCheck(this, b);
      const N = "Cache.addAll";
      n.argumentLengthCheck(arguments, 1, N);
      const d = [], l = [];
      for (let S of M) {
        if (S === void 0)
          throw n.errors.conversionFailed({
            prefix: N,
            argument: "Argument 1",
            types: ["undefined is not allowed"]
          });
        if (S = n.converters.RequestInfo(S), typeof S == "string")
          continue;
        const T = S[a];
        if (!u(T.url) || T.method !== "GET")
          throw n.errors.exception({
            header: N,
            message: "Expected http/s scheme when method is not GET."
          });
      }
      const p = [];
      for (const S of M) {
        const T = new B(S)[a];
        if (!u(T.url))
          throw n.errors.exception({
            header: N,
            message: "Expected http/s scheme."
          });
        T.initiator = "fetch", T.destination = "subresource", l.push(T);
        const L = C();
        p.push(h({
          request: T,
          processResponse(v) {
            if (v.type === "error" || v.status === 206 || v.status < 200 || v.status > 299)
              L.reject(n.errors.exception({
                header: "Cache.addAll",
                message: "Received an invalid status code or the request failed."
              }));
            else if (v.headersList.contains("vary")) {
              const $ = t(v.headersList.get("vary"));
              for (const oe of $)
                if (oe === "*") {
                  L.reject(n.errors.exception({
                    header: "Cache.addAll",
                    message: "invalid vary field value"
                  }));
                  for (const ge of p)
                    ge.abort();
                  return;
                }
            }
          },
          processResponseEndOfBody(v) {
            if (v.aborted) {
              L.reject(new DOMException("aborted", "AbortError"));
              return;
            }
            L.resolve(v);
          }
        })), d.push(L.promise);
      }
      const E = await Promise.all(d), f = [];
      let I = 0;
      for (const S of E) {
        const T = {
          type: "put",
          // 7.3.2
          request: l[I],
          // 7.3.3
          response: S
          // 7.3.4
        };
        f.push(T), I++;
      }
      const m = C();
      let y = null;
      try {
        this.#A(f);
      } catch (S) {
        y = S;
      }
      return queueMicrotask(() => {
        y === null ? m.resolve(void 0) : m.reject(y);
      }), m.promise;
    }
    async put(M, N) {
      n.brandCheck(this, b);
      const d = "Cache.put";
      n.argumentLengthCheck(arguments, 2, d), M = n.converters.RequestInfo(M, d, "request"), N = n.converters.Response(N, d, "response");
      let l = null;
      if (M instanceof B ? l = M[a] : l = new B(M)[a], !u(l.url) || l.method !== "GET")
        throw n.errors.exception({
          header: d,
          message: "Expected an http/s scheme when method is not GET"
        });
      const p = N[a];
      if (p.status === 206)
        throw n.errors.exception({
          header: d,
          message: "Got 206 status"
        });
      if (p.headersList.contains("vary")) {
        const T = t(p.headersList.get("vary"));
        for (const L of T)
          if (L === "*")
            throw n.errors.exception({
              header: d,
              message: "Got * vary field value"
            });
      }
      if (p.body && (A(p.body.stream) || p.body.stream.locked))
        throw n.errors.exception({
          header: d,
          message: "Response body is locked or disturbed"
        });
      const s = g(p), E = C();
      if (p.body != null) {
        const L = p.body.stream.getReader();
        w(L).then(E.resolve, E.reject);
      } else
        E.resolve(void 0);
      const f = [], I = {
        type: "put",
        // 14.
        request: l,
        // 15.
        response: s
        // 16.
      };
      f.push(I);
      const m = await E.promise;
      s.body != null && (s.body.source = m);
      const y = C();
      let S = null;
      try {
        this.#A(f);
      } catch (T) {
        S = T;
      }
      return queueMicrotask(() => {
        S === null ? y.resolve() : y.reject(S);
      }), y.promise;
    }
    async delete(M, N = {}) {
      n.brandCheck(this, b);
      const d = "Cache.delete";
      n.argumentLengthCheck(arguments, 1, d), M = n.converters.RequestInfo(M, d, "request"), N = n.converters.CacheQueryOptions(N, d, "options");
      let l = null;
      if (M instanceof B) {
        if (l = M[a], l.method !== "GET" && !N.ignoreMethod)
          return !1;
      } else
        D(typeof M == "string"), l = new B(M)[a];
      const p = [], s = {
        type: "delete",
        request: l,
        options: N
      };
      p.push(s);
      const E = C();
      let f = null, I;
      try {
        I = this.#A(p);
      } catch (m) {
        f = m;
      }
      return queueMicrotask(() => {
        f === null ? E.resolve(!!I?.length) : E.reject(f);
      }), E.promise;
    }
    /**
     * @see https://w3c.github.io/ServiceWorker/#dom-cache-keys
     * @param {any} request
     * @param {import('../../types/cache').CacheQueryOptions} options
     * @returns {Promise<readonly Request[]>}
     */
    async keys(M = void 0, N = {}) {
      n.brandCheck(this, b);
      const d = "Cache.keys";
      M !== void 0 && (M = n.converters.RequestInfo(M, d, "request")), N = n.converters.CacheQueryOptions(N, d, "options");
      let l = null;
      if (M !== void 0)
        if (M instanceof B) {
          if (l = M[a], l.method !== "GET" && !N.ignoreMethod)
            return [];
        } else typeof M == "string" && (l = new B(M)[a]);
      const p = C(), s = [];
      if (M === void 0)
        for (const E of this.#e)
          s.push(E[0]);
      else {
        const E = this.#s(l, N);
        for (const f of E)
          s.push(f[0]);
      }
      return queueMicrotask(() => {
        const E = [];
        for (const f of s) {
          const I = i(
            f,
            new AbortController().signal,
            "immutable"
          );
          E.push(I);
        }
        p.resolve(Object.freeze(E));
      }), p.promise;
    }
    /**
     * @see https://w3c.github.io/ServiceWorker/#batch-cache-operations-algorithm
     * @param {CacheBatchOperation[]} operations
     * @returns {requestResponseList}
     */
    #A(M) {
      const N = this.#e, d = [...N], l = [], p = [];
      try {
        for (const s of M) {
          if (s.type !== "delete" && s.type !== "put")
            throw n.errors.exception({
              header: "Cache.#batchCacheOperations",
              message: 'operation type does not match "delete" or "put"'
            });
          if (s.type === "delete" && s.response != null)
            throw n.errors.exception({
              header: "Cache.#batchCacheOperations",
              message: "delete operation should not have an associated response"
            });
          if (this.#s(s.request, s.options, l).length)
            throw new DOMException("???", "InvalidStateError");
          let E;
          if (s.type === "delete") {
            if (E = this.#s(s.request, s.options), E.length === 0)
              return [];
            for (const f of E) {
              const I = N.indexOf(f);
              D(I !== -1), N.splice(I, 1);
            }
          } else if (s.type === "put") {
            if (s.response == null)
              throw n.errors.exception({
                header: "Cache.#batchCacheOperations",
                message: "put operation should have an associated response"
              });
            const f = s.request;
            if (!u(f.url))
              throw n.errors.exception({
                header: "Cache.#batchCacheOperations",
                message: "expected http or https scheme"
              });
            if (f.method !== "GET")
              throw n.errors.exception({
                header: "Cache.#batchCacheOperations",
                message: "not get method"
              });
            if (s.options != null)
              throw n.errors.exception({
                header: "Cache.#batchCacheOperations",
                message: "options must not be defined"
              });
            E = this.#s(s.request);
            for (const I of E) {
              const m = N.indexOf(I);
              D(m !== -1), N.splice(m, 1);
            }
            N.push([s.request, s.response]), l.push([s.request, s.response]);
          }
          p.push([s.request, s.response]);
        }
        return p;
      } catch (s) {
        throw this.#e.length = 0, this.#e = d, s;
      }
    }
    /**
     * @see https://w3c.github.io/ServiceWorker/#query-cache
     * @param {any} requestQuery
     * @param {import('../../types/cache').CacheQueryOptions} options
     * @param {requestResponseList} targetStorage
     * @returns {requestResponseList}
     */
    #s(M, N, d) {
      const l = [], p = d ?? this.#e;
      for (const s of p) {
        const [E, f] = s;
        this.#r(M, E, f, N) && l.push(s);
      }
      return l;
    }
    /**
     * @see https://w3c.github.io/ServiceWorker/#request-matches-cached-item-algorithm
     * @param {any} requestQuery
     * @param {any} request
     * @param {any | null} response
     * @param {import('../../types/cache').CacheQueryOptions | undefined} options
     * @returns {boolean}
     */
    #r(M, N, d = null, l) {
      const p = new URL(M.url), s = new URL(N.url);
      if (l?.ignoreSearch && (s.search = "", p.search = ""), !r(p, s, !0))
        return !1;
      if (d == null || l?.ignoreVary || !d.headersList.contains("vary"))
        return !0;
      const E = t(d.headersList.get("vary"));
      for (const f of E) {
        if (f === "*")
          return !1;
        const I = N.headersList.get(f), m = M.headersList.get(f);
        if (I !== m)
          return !1;
      }
      return !0;
    }
    #t(M, N, d = 1 / 0) {
      let l = null;
      if (M !== void 0)
        if (M instanceof B) {
          if (l = M[a], l.method !== "GET" && !N.ignoreMethod)
            return [];
        } else typeof M == "string" && (l = new B(M)[a]);
      const p = [];
      if (M === void 0)
        for (const E of this.#e)
          p.push(E[1]);
      else {
        const E = this.#s(l, N);
        for (const f of E)
          p.push(f[1]);
      }
      const s = [];
      for (const E of p) {
        const f = Q(E, "immutable");
        if (s.push(f.clone()), s.length >= d)
          break;
      }
      return Object.freeze(s);
    }
  }
  Object.defineProperties(b.prototype, {
    [Symbol.toStringTag]: {
      value: "Cache",
      configurable: !0
    },
    match: o,
    matchAll: o,
    add: o,
    addAll: o,
    put: o,
    delete: o,
    keys: o
  });
  const U = [
    {
      key: "ignoreSearch",
      converter: n.converters.boolean,
      defaultValue: () => !1
    },
    {
      key: "ignoreMethod",
      converter: n.converters.boolean,
      defaultValue: () => !1
    },
    {
      key: "ignoreVary",
      converter: n.converters.boolean,
      defaultValue: () => !1
    }
  ];
  return n.converters.CacheQueryOptions = n.dictionaryConverter(U), n.converters.MultiCacheQueryOptions = n.dictionaryConverter([
    ...U,
    {
      key: "cacheName",
      converter: n.converters.DOMString
    }
  ]), n.converters.Response = n.interfaceConverter(c), n.converters["sequence<RequestInfo>"] = n.sequenceConverter(
    n.converters.RequestInfo
  ), kr = {
    Cache: b
  }, kr;
}
var br, Wo;
function Da() {
  if (Wo) return br;
  Wo = 1;
  const { kConstruct: e } = cs(), { Cache: r } = ya(), { webidl: t } = Xe(), { kEnumerableProperty: o } = Ue();
  class A {
    /**
     * @see https://w3c.github.io/ServiceWorker/#dfn-relevant-name-to-cache-map
     * @type {Map<string, import('./cache').requestResponseList}
     */
    #e = /* @__PURE__ */ new Map();
    constructor() {
      arguments[0] !== e && t.illegalConstructor(), t.util.markAsUncloneable(this);
    }
    async match(c, g = {}) {
      if (t.brandCheck(this, A), t.argumentLengthCheck(arguments, 1, "CacheStorage.match"), c = t.converters.RequestInfo(c), g = t.converters.MultiCacheQueryOptions(g), g.cacheName != null) {
        if (this.#e.has(g.cacheName)) {
          const Q = this.#e.get(g.cacheName);
          return await new r(e, Q).match(c, g);
        }
      } else
        for (const Q of this.#e.values()) {
          const i = await new r(e, Q).match(c, g);
          if (i !== void 0)
            return i;
        }
    }
    /**
     * @see https://w3c.github.io/ServiceWorker/#cache-storage-has
     * @param {string} cacheName
     * @returns {Promise<boolean>}
     */
    async has(c) {
      t.brandCheck(this, A);
      const g = "CacheStorage.has";
      return t.argumentLengthCheck(arguments, 1, g), c = t.converters.DOMString(c, g, "cacheName"), this.#e.has(c);
    }
    /**
     * @see https://w3c.github.io/ServiceWorker/#dom-cachestorage-open
     * @param {string} cacheName
     * @returns {Promise<Cache>}
     */
    async open(c) {
      t.brandCheck(this, A);
      const g = "CacheStorage.open";
      if (t.argumentLengthCheck(arguments, 1, g), c = t.converters.DOMString(c, g, "cacheName"), this.#e.has(c)) {
        const B = this.#e.get(c);
        return new r(e, B);
      }
      const Q = [];
      return this.#e.set(c, Q), new r(e, Q);
    }
    /**
     * @see https://w3c.github.io/ServiceWorker/#cache-storage-delete
     * @param {string} cacheName
     * @returns {Promise<boolean>}
     */
    async delete(c) {
      t.brandCheck(this, A);
      const g = "CacheStorage.delete";
      return t.argumentLengthCheck(arguments, 1, g), c = t.converters.DOMString(c, g, "cacheName"), this.#e.delete(c);
    }
    /**
     * @see https://w3c.github.io/ServiceWorker/#cache-storage-keys
     * @returns {Promise<string[]>}
     */
    async keys() {
      return t.brandCheck(this, A), [...this.#e.keys()];
    }
  }
  return Object.defineProperties(A.prototype, {
    [Symbol.toStringTag]: {
      value: "CacheStorage",
      configurable: !0
    },
    match: o,
    has: o,
    open: o,
    delete: o,
    keys: o
  }), br = {
    CacheStorage: A
  }, br;
}
var Fr, qo;
function Ra() {
  return qo || (qo = 1, Fr = {
    maxAttributeValueSize: 1024,
    maxNameValuePairSize: 4096
  }), Fr;
}
var Tr, zo;
function si() {
  if (zo) return Tr;
  zo = 1;
  function e(a) {
    for (let h = 0; h < a.length; ++h) {
      const u = a.charCodeAt(h);
      if (u >= 0 && u <= 8 || u >= 10 && u <= 31 || u === 127)
        return !0;
    }
    return !1;
  }
  function r(a) {
    for (let h = 0; h < a.length; ++h) {
      const u = a.charCodeAt(h);
      if (u < 33 || // exclude CTLs (0-31), SP and HT
      u > 126 || // exclude non-ascii and DEL
      u === 34 || // "
      u === 40 || // (
      u === 41 || // )
      u === 60 || // <
      u === 62 || // >
      u === 64 || // @
      u === 44 || // ,
      u === 59 || // ;
      u === 58 || // :
      u === 92 || // \
      u === 47 || // /
      u === 91 || // [
      u === 93 || // ]
      u === 63 || // ?
      u === 61 || // =
      u === 123 || // {
      u === 125)
        throw new Error("Invalid cookie name");
    }
  }
  function t(a) {
    let h = a.length, u = 0;
    if (a[0] === '"') {
      if (h === 1 || a[h - 1] !== '"')
        throw new Error("Invalid cookie value");
      --h, ++u;
    }
    for (; u < h; ) {
      const C = a.charCodeAt(u++);
      if (C < 33 || // exclude CTLs (0-31)
      C > 126 || // non-ascii and DEL (127)
      C === 34 || // "
      C === 44 || // ,
      C === 59 || // ;
      C === 92)
        throw new Error("Invalid cookie value");
    }
  }
  function o(a) {
    for (let h = 0; h < a.length; ++h) {
      const u = a.charCodeAt(h);
      if (u < 32 || // exclude CTLs (0-31)
      u === 127 || // DEL
      u === 59)
        throw new Error("Invalid cookie path");
    }
  }
  function A(a) {
    if (a.startsWith("-") || a.endsWith(".") || a.endsWith("-"))
      throw new Error("Invalid cookie domain");
  }
  const n = [
    "Sun",
    "Mon",
    "Tue",
    "Wed",
    "Thu",
    "Fri",
    "Sat"
  ], c = [
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec"
  ], g = Array(61).fill(0).map((a, h) => h.toString().padStart(2, "0"));
  function Q(a) {
    return typeof a == "number" && (a = new Date(a)), `${n[a.getUTCDay()]}, ${g[a.getUTCDate()]} ${c[a.getUTCMonth()]} ${a.getUTCFullYear()} ${g[a.getUTCHours()]}:${g[a.getUTCMinutes()]}:${g[a.getUTCSeconds()]} GMT`;
  }
  function B(a) {
    if (a < 0)
      throw new Error("Invalid cookie max-age");
  }
  function i(a) {
    if (a.name.length === 0)
      return null;
    r(a.name), t(a.value);
    const h = [`${a.name}=${a.value}`];
    a.name.startsWith("__Secure-") && (a.secure = !0), a.name.startsWith("__Host-") && (a.secure = !0, a.domain = null, a.path = "/"), a.secure && h.push("Secure"), a.httpOnly && h.push("HttpOnly"), typeof a.maxAge == "number" && (B(a.maxAge), h.push(`Max-Age=${a.maxAge}`)), a.domain && (A(a.domain), h.push(`Domain=${a.domain}`)), a.path && (o(a.path), h.push(`Path=${a.path}`)), a.expires && a.expires.toString() !== "Invalid Date" && h.push(`Expires=${Q(a.expires)}`), a.sameSite && h.push(`SameSite=${a.sameSite}`);
    for (const u of a.unparsed) {
      if (!u.includes("="))
        throw new Error("Invalid unparsed");
      const [C, ...w] = u.split("=");
      h.push(`${C.trim()}=${w.join("=")}`);
    }
    return h.join("; ");
  }
  return Tr = {
    isCTLExcludingHtab: e,
    validateCookieName: r,
    validateCookiePath: o,
    validateCookieValue: t,
    toIMFDate: Q,
    stringify: i
  }, Tr;
}
var Sr, Zo;
function ka() {
  if (Zo) return Sr;
  Zo = 1;
  const { maxNameValuePairSize: e, maxAttributeValueSize: r } = Ra(), { isCTLExcludingHtab: t } = si(), { collectASequenceOfCodePointsFast: o } = eA(), A = He;
  function n(g) {
    if (t(g))
      return null;
    let Q = "", B = "", i = "", a = "";
    if (g.includes(";")) {
      const h = { position: 0 };
      Q = o(";", g, h), B = g.slice(h.position);
    } else
      Q = g;
    if (!Q.includes("="))
      a = Q;
    else {
      const h = { position: 0 };
      i = o(
        "=",
        Q,
        h
      ), a = Q.slice(h.position + 1);
    }
    return i = i.trim(), a = a.trim(), i.length + a.length > e ? null : {
      name: i,
      value: a,
      ...c(B)
    };
  }
  function c(g, Q = {}) {
    if (g.length === 0)
      return Q;
    A(g[0] === ";"), g = g.slice(1);
    let B = "";
    g.includes(";") ? (B = o(
      ";",
      g,
      { position: 0 }
    ), g = g.slice(B.length)) : (B = g, g = "");
    let i = "", a = "";
    if (B.includes("=")) {
      const u = { position: 0 };
      i = o(
        "=",
        B,
        u
      ), a = B.slice(u.position + 1);
    } else
      i = B;
    if (i = i.trim(), a = a.trim(), a.length > r)
      return c(g, Q);
    const h = i.toLowerCase();
    if (h === "expires") {
      const u = new Date(a);
      Q.expires = u;
    } else if (h === "max-age") {
      const u = a.charCodeAt(0);
      if ((u < 48 || u > 57) && a[0] !== "-" || !/^\d+$/.test(a))
        return c(g, Q);
      const C = Number(a);
      Q.maxAge = C;
    } else if (h === "domain") {
      let u = a;
      u[0] === "." && (u = u.slice(1)), u = u.toLowerCase(), Q.domain = u;
    } else if (h === "path") {
      let u = "";
      a.length === 0 || a[0] !== "/" ? u = "/" : u = a, Q.path = u;
    } else if (h === "secure")
      Q.secure = !0;
    else if (h === "httponly")
      Q.httpOnly = !0;
    else if (h === "samesite") {
      let u = "Default";
      const C = a.toLowerCase();
      C.includes("none") && (u = "None"), C.includes("strict") && (u = "Strict"), C.includes("lax") && (u = "Lax"), Q.sameSite = u;
    } else
      Q.unparsed ??= [], Q.unparsed.push(`${i}=${a}`);
    return c(g, Q);
  }
  return Sr = {
    parseSetCookie: n,
    parseUnparsedAttributes: c
  }, Sr;
}
var Ur, Ko;
function ba() {
  if (Ko) return Ur;
  Ko = 1;
  const { parseSetCookie: e } = ka(), { stringify: r } = si(), { webidl: t } = Xe(), { Headers: o } = wA();
  function A(Q) {
    t.argumentLengthCheck(arguments, 1, "getCookies"), t.brandCheck(Q, o, { strict: !1 });
    const B = Q.get("cookie"), i = {};
    if (!B)
      return i;
    for (const a of B.split(";")) {
      const [h, ...u] = a.split("=");
      i[h.trim()] = u.join("=");
    }
    return i;
  }
  function n(Q, B, i) {
    t.brandCheck(Q, o, { strict: !1 });
    const a = "deleteCookie";
    t.argumentLengthCheck(arguments, 2, a), B = t.converters.DOMString(B, a, "name"), i = t.converters.DeleteCookieAttributes(i), g(Q, {
      name: B,
      value: "",
      expires: /* @__PURE__ */ new Date(0),
      ...i
    });
  }
  function c(Q) {
    t.argumentLengthCheck(arguments, 1, "getSetCookies"), t.brandCheck(Q, o, { strict: !1 });
    const B = Q.getSetCookie();
    return B ? B.map((i) => e(i)) : [];
  }
  function g(Q, B) {
    t.argumentLengthCheck(arguments, 2, "setCookie"), t.brandCheck(Q, o, { strict: !1 }), B = t.converters.Cookie(B);
    const i = r(B);
    i && Q.append("Set-Cookie", i);
  }
  return t.converters.DeleteCookieAttributes = t.dictionaryConverter([
    {
      converter: t.nullableConverter(t.converters.DOMString),
      key: "path",
      defaultValue: () => null
    },
    {
      converter: t.nullableConverter(t.converters.DOMString),
      key: "domain",
      defaultValue: () => null
    }
  ]), t.converters.Cookie = t.dictionaryConverter([
    {
      converter: t.converters.DOMString,
      key: "name"
    },
    {
      converter: t.converters.DOMString,
      key: "value"
    },
    {
      converter: t.nullableConverter((Q) => typeof Q == "number" ? t.converters["unsigned long long"](Q) : new Date(Q)),
      key: "expires",
      defaultValue: () => null
    },
    {
      converter: t.nullableConverter(t.converters["long long"]),
      key: "maxAge",
      defaultValue: () => null
    },
    {
      converter: t.nullableConverter(t.converters.DOMString),
      key: "domain",
      defaultValue: () => null
    },
    {
      converter: t.nullableConverter(t.converters.DOMString),
      key: "path",
      defaultValue: () => null
    },
    {
      converter: t.nullableConverter(t.converters.boolean),
      key: "secure",
      defaultValue: () => null
    },
    {
      converter: t.nullableConverter(t.converters.boolean),
      key: "httpOnly",
      defaultValue: () => null
    },
    {
      converter: t.converters.USVString,
      key: "sameSite",
      allowedValues: ["Strict", "Lax", "None"]
    },
    {
      converter: t.sequenceConverter(t.converters.DOMString),
      key: "unparsed",
      defaultValue: () => new Array(0)
    }
  ]), Ur = {
    getCookies: A,
    deleteCookie: n,
    getSetCookies: c,
    setCookie: g
  }, Ur;
}
var Nr, Xo;
function vA() {
  if (Xo) return Nr;
  Xo = 1;
  const { webidl: e } = Xe(), { kEnumerableProperty: r } = Ue(), { kConstruct: t } = Oe(), { MessagePort: o } = Pn;
  class A extends Event {
    #e;
    constructor(i, a = {}) {
      if (i === t) {
        super(arguments[1], arguments[2]), e.util.markAsUncloneable(this);
        return;
      }
      const h = "MessageEvent constructor";
      e.argumentLengthCheck(arguments, 1, h), i = e.converters.DOMString(i, h, "type"), a = e.converters.MessageEventInit(a, h, "eventInitDict"), super(i, a), this.#e = a, e.util.markAsUncloneable(this);
    }
    get data() {
      return e.brandCheck(this, A), this.#e.data;
    }
    get origin() {
      return e.brandCheck(this, A), this.#e.origin;
    }
    get lastEventId() {
      return e.brandCheck(this, A), this.#e.lastEventId;
    }
    get source() {
      return e.brandCheck(this, A), this.#e.source;
    }
    get ports() {
      return e.brandCheck(this, A), Object.isFrozen(this.#e.ports) || Object.freeze(this.#e.ports), this.#e.ports;
    }
    initMessageEvent(i, a = !1, h = !1, u = null, C = "", w = "", D = null, b = []) {
      return e.brandCheck(this, A), e.argumentLengthCheck(arguments, 1, "MessageEvent.initMessageEvent"), new A(i, {
        bubbles: a,
        cancelable: h,
        data: u,
        origin: C,
        lastEventId: w,
        source: D,
        ports: b
      });
    }
    static createFastMessageEvent(i, a) {
      const h = new A(t, i, a);
      return h.#e = a, h.#e.data ??= null, h.#e.origin ??= "", h.#e.lastEventId ??= "", h.#e.source ??= null, h.#e.ports ??= [], h;
    }
  }
  const { createFastMessageEvent: n } = A;
  delete A.createFastMessageEvent;
  class c extends Event {
    #e;
    constructor(i, a = {}) {
      const h = "CloseEvent constructor";
      e.argumentLengthCheck(arguments, 1, h), i = e.converters.DOMString(i, h, "type"), a = e.converters.CloseEventInit(a), super(i, a), this.#e = a, e.util.markAsUncloneable(this);
    }
    get wasClean() {
      return e.brandCheck(this, c), this.#e.wasClean;
    }
    get code() {
      return e.brandCheck(this, c), this.#e.code;
    }
    get reason() {
      return e.brandCheck(this, c), this.#e.reason;
    }
  }
  class g extends Event {
    #e;
    constructor(i, a) {
      const h = "ErrorEvent constructor";
      e.argumentLengthCheck(arguments, 1, h), super(i, a), e.util.markAsUncloneable(this), i = e.converters.DOMString(i, h, "type"), a = e.converters.ErrorEventInit(a ?? {}), this.#e = a;
    }
    get message() {
      return e.brandCheck(this, g), this.#e.message;
    }
    get filename() {
      return e.brandCheck(this, g), this.#e.filename;
    }
    get lineno() {
      return e.brandCheck(this, g), this.#e.lineno;
    }
    get colno() {
      return e.brandCheck(this, g), this.#e.colno;
    }
    get error() {
      return e.brandCheck(this, g), this.#e.error;
    }
  }
  Object.defineProperties(A.prototype, {
    [Symbol.toStringTag]: {
      value: "MessageEvent",
      configurable: !0
    },
    data: r,
    origin: r,
    lastEventId: r,
    source: r,
    ports: r,
    initMessageEvent: r
  }), Object.defineProperties(c.prototype, {
    [Symbol.toStringTag]: {
      value: "CloseEvent",
      configurable: !0
    },
    reason: r,
    code: r,
    wasClean: r
  }), Object.defineProperties(g.prototype, {
    [Symbol.toStringTag]: {
      value: "ErrorEvent",
      configurable: !0
    },
    message: r,
    filename: r,
    lineno: r,
    colno: r,
    error: r
  }), e.converters.MessagePort = e.interfaceConverter(o), e.converters["sequence<MessagePort>"] = e.sequenceConverter(
    e.converters.MessagePort
  );
  const Q = [
    {
      key: "bubbles",
      converter: e.converters.boolean,
      defaultValue: () => !1
    },
    {
      key: "cancelable",
      converter: e.converters.boolean,
      defaultValue: () => !1
    },
    {
      key: "composed",
      converter: e.converters.boolean,
      defaultValue: () => !1
    }
  ];
  return e.converters.MessageEventInit = e.dictionaryConverter([
    ...Q,
    {
      key: "data",
      converter: e.converters.any,
      defaultValue: () => null
    },
    {
      key: "origin",
      converter: e.converters.USVString,
      defaultValue: () => ""
    },
    {
      key: "lastEventId",
      converter: e.converters.DOMString,
      defaultValue: () => ""
    },
    {
      key: "source",
      // Node doesn't implement WindowProxy or ServiceWorker, so the only
      // valid value for source is a MessagePort.
      converter: e.nullableConverter(e.converters.MessagePort),
      defaultValue: () => null
    },
    {
      key: "ports",
      converter: e.converters["sequence<MessagePort>"],
      defaultValue: () => new Array(0)
    }
  ]), e.converters.CloseEventInit = e.dictionaryConverter([
    ...Q,
    {
      key: "wasClean",
      converter: e.converters.boolean,
      defaultValue: () => !1
    },
    {
      key: "code",
      converter: e.converters["unsigned short"],
      defaultValue: () => 0
    },
    {
      key: "reason",
      converter: e.converters.USVString,
      defaultValue: () => ""
    }
  ]), e.converters.ErrorEventInit = e.dictionaryConverter([
    ...Q,
    {
      key: "message",
      converter: e.converters.DOMString,
      defaultValue: () => ""
    },
    {
      key: "filename",
      converter: e.converters.USVString,
      defaultValue: () => ""
    },
    {
      key: "lineno",
      converter: e.converters["unsigned long"],
      defaultValue: () => 0
    },
    {
      key: "colno",
      converter: e.converters["unsigned long"],
      defaultValue: () => 0
    },
    {
      key: "error",
      converter: e.converters.any
    }
  ]), Nr = {
    MessageEvent: A,
    CloseEvent: c,
    ErrorEvent: g,
    createFastMessageEvent: n
  }, Nr;
}
var Mr, jo;
function mA() {
  if (jo) return Mr;
  jo = 1;
  const e = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", r = {
    enumerable: !0,
    writable: !1,
    configurable: !1
  }, t = {
    CONNECTING: 0,
    OPEN: 1,
    CLOSING: 2,
    CLOSED: 3
  }, o = {
    NOT_SENT: 0,
    PROCESSING: 1,
    SENT: 2
  }, A = {
    CONTINUATION: 0,
    TEXT: 1,
    BINARY: 2,
    CLOSE: 8,
    PING: 9,
    PONG: 10
  }, n = 2 ** 16 - 1, c = {
    INFO: 0,
    PAYLOADLENGTH_16: 2,
    PAYLOADLENGTH_64: 3,
    READ_DATA: 4
  }, g = Buffer.allocUnsafe(0);
  return Mr = {
    uid: e,
    sentCloseFrameState: o,
    staticPropertyDescriptors: r,
    states: t,
    opcodes: A,
    maxUnsigned16Bit: n,
    parserStates: c,
    emptyBuffer: g,
    sendHints: {
      string: 1,
      typedArray: 2,
      arrayBuffer: 3,
      blob: 4
    }
  }, Mr;
}
var Lr, $o;
function tt() {
  return $o || ($o = 1, Lr = {
    kWebSocketURL: /* @__PURE__ */ Symbol("url"),
    kReadyState: /* @__PURE__ */ Symbol("ready state"),
    kController: /* @__PURE__ */ Symbol("controller"),
    kResponse: /* @__PURE__ */ Symbol("response"),
    kBinaryType: /* @__PURE__ */ Symbol("binary type"),
    kSentClose: /* @__PURE__ */ Symbol("sent close"),
    kReceivedClose: /* @__PURE__ */ Symbol("received close"),
    kByteParser: /* @__PURE__ */ Symbol("byte parser")
  }), Lr;
}
var Gr, en;
function rt() {
  if (en) return Gr;
  en = 1;
  const { kReadyState: e, kController: r, kResponse: t, kBinaryType: o, kWebSocketURL: A } = tt(), { states: n, opcodes: c } = mA(), { ErrorEvent: g, createFastMessageEvent: Q } = vA(), { isUtf8: B } = sA, { collectASequenceOfCodePointsFast: i, removeHTTPWhitespace: a } = eA();
  function h(S) {
    return S[e] === n.CONNECTING;
  }
  function u(S) {
    return S[e] === n.OPEN;
  }
  function C(S) {
    return S[e] === n.CLOSING;
  }
  function w(S) {
    return S[e] === n.CLOSED;
  }
  function D(S, T, L = ($, oe) => new Event($, oe), v = {}) {
    const $ = L(S, v);
    T.dispatchEvent($);
  }
  function b(S, T, L) {
    if (S[e] !== n.OPEN)
      return;
    let v;
    if (T === c.TEXT)
      try {
        v = y(L);
      } catch {
        N(S, "Received invalid UTF-8 in text frame.");
        return;
      }
    else T === c.BINARY && (S[o] === "blob" ? v = new Blob([L]) : v = U(L));
    D("message", S, Q, {
      origin: S[A].origin,
      data: v
    });
  }
  function U(S) {
    return S.byteLength === S.buffer.byteLength ? S.buffer : S.buffer.slice(S.byteOffset, S.byteOffset + S.byteLength);
  }
  function G(S) {
    if (S.length === 0)
      return !1;
    for (let T = 0; T < S.length; ++T) {
      const L = S.charCodeAt(T);
      if (L < 33 || // CTL, contains SP (0x20) and HT (0x09)
      L > 126 || L === 34 || // "
      L === 40 || // (
      L === 41 || // )
      L === 44 || // ,
      L === 47 || // /
      L === 58 || // :
      L === 59 || // ;
      L === 60 || // <
      L === 61 || // =
      L === 62 || // >
      L === 63 || // ?
      L === 64 || // @
      L === 91 || // [
      L === 92 || // \
      L === 93 || // ]
      L === 123 || // {
      L === 125)
        return !1;
    }
    return !0;
  }
  function M(S) {
    return S >= 1e3 && S < 1015 ? S !== 1004 && // reserved
    S !== 1005 && // "MUST NOT be set as a status code"
    S !== 1006 : S >= 3e3 && S <= 4999;
  }
  function N(S, T) {
    const { [r]: L, [t]: v } = S;
    L.abort(), v?.socket && !v.socket.destroyed && v.socket.destroy(), T && D("error", S, ($, oe) => new g($, oe), {
      error: new Error(T),
      message: T
    });
  }
  function d(S) {
    return S === c.CLOSE || S === c.PING || S === c.PONG;
  }
  function l(S) {
    return S === c.CONTINUATION;
  }
  function p(S) {
    return S === c.TEXT || S === c.BINARY;
  }
  function s(S) {
    return p(S) || l(S) || d(S);
  }
  function E(S) {
    const T = { position: 0 }, L = /* @__PURE__ */ new Map();
    for (; T.position < S.length; ) {
      const v = i(";", S, T), [$, oe = ""] = v.split("=");
      L.set(
        a($, !0, !1),
        a(oe, !1, !0)
      ), T.position++;
    }
    return L;
  }
  function f(S) {
    for (let T = 0; T < S.length; T++) {
      const L = S.charCodeAt(T);
      if (L < 48 || L > 57)
        return !1;
    }
    return !0;
  }
  const I = typeof process.versions.icu == "string", m = I ? new TextDecoder("utf-8", { fatal: !0 }) : void 0, y = I ? m.decode.bind(m) : function(S) {
    if (B(S))
      return S.toString("utf-8");
    throw new TypeError("Invalid utf-8 received.");
  };
  return Gr = {
    isConnecting: h,
    isEstablished: u,
    isClosing: C,
    isClosed: w,
    fireEvent: D,
    isValidSubprotocol: G,
    isValidStatusCode: M,
    failWebsocketConnection: N,
    websocketMessageReceived: b,
    utf8Decode: y,
    isControlFrame: d,
    isContinuationFrame: l,
    isTextBinaryFrame: p,
    isValidOpcode: s,
    parseExtensions: E,
    isValidClientWindowBits: f
  }, Gr;
}
var vr, An;
function gs() {
  if (An) return vr;
  An = 1;
  const { maxUnsigned16Bit: e } = mA(), r = 16386;
  let t, o = null, A = r;
  try {
    t = require("node:crypto");
  } catch {
    t = {
      // not full compatibility, but minimum.
      randomFillSync: function(Q, B, i) {
        for (let a = 0; a < Q.length; ++a)
          Q[a] = Math.random() * 255 | 0;
        return Q;
      }
    };
  }
  function n() {
    return A === r && (A = 0, t.randomFillSync(o ??= Buffer.allocUnsafe(r), 0, r)), [o[A++], o[A++], o[A++], o[A++]];
  }
  class c {
    /**
     * @param {Buffer|undefined} data
     */
    constructor(Q) {
      this.frameData = Q;
    }
    createFrame(Q) {
      const B = this.frameData, i = n(), a = B?.byteLength ?? 0;
      let h = a, u = 6;
      a > e ? (u += 8, h = 127) : a > 125 && (u += 2, h = 126);
      const C = Buffer.allocUnsafe(a + u);
      C[0] = C[1] = 0, C[0] |= 128, C[0] = (C[0] & 240) + Q;
      C[u - 4] = i[0], C[u - 3] = i[1], C[u - 2] = i[2], C[u - 1] = i[3], C[1] = h, h === 126 ? C.writeUInt16BE(a, 2) : h === 127 && (C[2] = C[3] = 0, C.writeUIntBE(a, 4, 6)), C[1] |= 128;
      for (let w = 0; w < a; ++w)
        C[u + w] = B[w] ^ i[w & 3];
      return C;
    }
  }
  return vr = {
    WebsocketFrameSend: c
  }, vr;
}
var Yr, tn;
function oi() {
  if (tn) return Yr;
  tn = 1;
  const { uid: e, states: r, sentCloseFrameState: t, emptyBuffer: o, opcodes: A } = mA(), {
    kReadyState: n,
    kSentClose: c,
    kByteParser: g,
    kReceivedClose: Q,
    kResponse: B
  } = tt(), { fireEvent: i, failWebsocketConnection: a, isClosing: h, isClosed: u, isEstablished: C, parseExtensions: w } = rt(), { channels: D } = FA(), { CloseEvent: b } = vA(), { makeRequest: U } = GA(), { fetching: G } = At(), { Headers: M, getHeadersList: N } = wA(), { getDecodeSplit: d } = rA(), { WebsocketFrameSend: l } = gs();
  let p;
  try {
    p = require("node:crypto");
  } catch {
  }
  function s(y, S, T, L, v, $) {
    const oe = y;
    oe.protocol = y.protocol === "ws:" ? "http:" : "https:";
    const ge = U({
      urlList: [oe],
      client: T,
      serviceWorkers: "none",
      referrer: "no-referrer",
      mode: "websocket",
      credentials: "include",
      cache: "no-store",
      redirect: "error"
    });
    if ($.headers) {
      const Qe = N(new M($.headers));
      ge.headersList = Qe;
    }
    const ae = p.randomBytes(16).toString("base64");
    ge.headersList.append("sec-websocket-key", ae), ge.headersList.append("sec-websocket-version", "13");
    for (const Qe of S)
      ge.headersList.append("sec-websocket-protocol", Qe);
    return ge.headersList.append("sec-websocket-extensions", "permessage-deflate; client_max_window_bits"), G({
      request: ge,
      useParallelQueue: !0,
      dispatcher: $.dispatcher,
      processResponse(Qe) {
        if (Qe.type === "error" || Qe.status !== 101) {
          a(L, "Received network error or non-101 status code.");
          return;
        }
        if (S.length !== 0 && !Qe.headersList.get("Sec-WebSocket-Protocol")) {
          a(L, "Server did not respond with sent protocols.");
          return;
        }
        if (Qe.headersList.get("Upgrade")?.toLowerCase() !== "websocket") {
          a(L, 'Server did not set Upgrade header to "websocket".');
          return;
        }
        if (Qe.headersList.get("Connection")?.toLowerCase() !== "upgrade") {
          a(L, 'Server did not set Connection header to "upgrade".');
          return;
        }
        const ye = Qe.headersList.get("Sec-WebSocket-Accept"), we = p.createHash("sha1").update(ae + e).digest("base64");
        if (ye !== we) {
          a(L, "Incorrect hash received in Sec-WebSocket-Accept header.");
          return;
        }
        const j = Qe.headersList.get("Sec-WebSocket-Extensions");
        let W;
        if (j !== null && (W = w(j), !W.has("permessage-deflate"))) {
          a(L, "Sec-WebSocket-Extensions header does not match.");
          return;
        }
        const re = Qe.headersList.get("Sec-WebSocket-Protocol");
        if (re !== null && !d("sec-websocket-protocol", ge.headersList).includes(re)) {
          a(L, "Protocol was not set in the opening handshake.");
          return;
        }
        Qe.socket.on("data", f), Qe.socket.on("close", I), Qe.socket.on("error", m), D.open.hasSubscribers && D.open.publish({
          address: Qe.socket.address(),
          protocol: re,
          extensions: j
        }), v(Qe, W);
      }
    });
  }
  function E(y, S, T, L) {
    if (!(h(y) || u(y))) if (!C(y))
      a(y, "Connection was closed before it was established."), y[n] = r.CLOSING;
    else if (y[c] === t.NOT_SENT) {
      y[c] = t.PROCESSING;
      const v = new l();
      S !== void 0 && T === void 0 ? (v.frameData = Buffer.allocUnsafe(2), v.frameData.writeUInt16BE(S, 0)) : S !== void 0 && T !== void 0 ? (v.frameData = Buffer.allocUnsafe(2 + L), v.frameData.writeUInt16BE(S, 0), v.frameData.write(T, 2, "utf-8")) : v.frameData = o, y[B].socket.write(v.createFrame(A.CLOSE)), y[c] = t.SENT, y[n] = r.CLOSING;
    } else
      y[n] = r.CLOSING;
  }
  function f(y) {
    this.ws[g].write(y) || this.pause();
  }
  function I() {
    const { ws: y } = this, { [B]: S } = y;
    S.socket.off("data", f), S.socket.off("close", I), S.socket.off("error", m);
    const T = y[c] === t.SENT && y[Q];
    let L = 1005, v = "";
    const $ = y[g].closingInfo;
    $ && !$.error ? (L = $.code ?? 1005, v = $.reason) : y[Q] || (L = 1006), y[n] = r.CLOSED, i("close", y, (oe, ge) => new b(oe, ge), {
      wasClean: T,
      code: L,
      reason: v
    }), D.close.hasSubscribers && D.close.publish({
      websocket: y,
      code: L,
      reason: v
    });
  }
  function m(y) {
    const { ws: S } = this;
    S[n] = r.CLOSING, D.socketError.hasSubscribers && D.socketError.publish(y), this.destroy();
  }
  return Yr = {
    establishWebSocketConnection: s,
    closeWebSocketConnection: E
  }, Yr;
}
var Jr, rn;
function Fa() {
  if (rn) return Jr;
  rn = 1;
  const { createInflateRaw: e, Z_DEFAULT_WINDOWBITS: r } = ts, { isValidClientWindowBits: t } = rt(), o = Buffer.from([0, 0, 255, 255]), A = /* @__PURE__ */ Symbol("kBuffer"), n = /* @__PURE__ */ Symbol("kLength");
  class c {
    /** @type {import('node:zlib').InflateRaw} */
    #e;
    #A = {};
    constructor(Q) {
      this.#A.serverNoContextTakeover = Q.has("server_no_context_takeover"), this.#A.serverMaxWindowBits = Q.get("server_max_window_bits");
    }
    decompress(Q, B, i) {
      if (!this.#e) {
        let a = r;
        if (this.#A.serverMaxWindowBits) {
          if (!t(this.#A.serverMaxWindowBits)) {
            i(new Error("Invalid server_max_window_bits"));
            return;
          }
          a = Number.parseInt(this.#A.serverMaxWindowBits);
        }
        this.#e = e({ windowBits: a }), this.#e[A] = [], this.#e[n] = 0, this.#e.on("data", (h) => {
          this.#e[A].push(h), this.#e[n] += h.length;
        }), this.#e.on("error", (h) => {
          this.#e = null, i(h);
        });
      }
      this.#e.write(Q), B && this.#e.write(o), this.#e.flush(() => {
        const a = Buffer.concat(this.#e[A], this.#e[n]);
        this.#e[A].length = 0, this.#e[n] = 0, i(null, a);
      });
    }
  }
  return Jr = { PerMessageDeflate: c }, Jr;
}
var Hr, sn;
function Ta() {
  if (sn) return Hr;
  sn = 1;
  const { Writable: e } = tA, r = He, { parserStates: t, opcodes: o, states: A, emptyBuffer: n, sentCloseFrameState: c } = mA(), { kReadyState: g, kSentClose: Q, kResponse: B, kReceivedClose: i } = tt(), { channels: a } = FA(), {
    isValidStatusCode: h,
    isValidOpcode: u,
    failWebsocketConnection: C,
    websocketMessageReceived: w,
    utf8Decode: D,
    isControlFrame: b,
    isTextBinaryFrame: U,
    isContinuationFrame: G
  } = rt(), { WebsocketFrameSend: M } = gs(), { closeWebSocketConnection: N } = oi(), { PerMessageDeflate: d } = Fa();
  class l extends e {
    #e = [];
    #A = 0;
    #s = !1;
    #r = t.INFO;
    #t = {};
    #o = [];
    /** @type {Map<string, PerMessageDeflate>} */
    #n;
    constructor(s, E) {
      super(), this.ws = s, this.#n = E ?? /* @__PURE__ */ new Map(), this.#n.has("permessage-deflate") && this.#n.set("permessage-deflate", new d(E));
    }
    /**
     * @param {Buffer} chunk
     * @param {() => void} callback
     */
    _write(s, E, f) {
      this.#e.push(s), this.#A += s.length, this.#s = !0, this.run(f);
    }
    /**
     * Runs whenever a new chunk is received.
     * Callback is called whenever there are no more chunks buffering,
     * or not enough bytes are buffered to parse.
     */
    run(s) {
      for (; this.#s; )
        if (this.#r === t.INFO) {
          if (this.#A < 2)
            return s();
          const E = this.consume(2), f = (E[0] & 128) !== 0, I = E[0] & 15, m = (E[1] & 128) === 128, y = !f && I !== o.CONTINUATION, S = E[1] & 127, T = E[0] & 64, L = E[0] & 32, v = E[0] & 16;
          if (!u(I))
            return C(this.ws, "Invalid opcode received"), s();
          if (m)
            return C(this.ws, "Frame cannot be masked"), s();
          if (T !== 0 && !this.#n.has("permessage-deflate")) {
            C(this.ws, "Expected RSV1 to be clear.");
            return;
          }
          if (L !== 0 || v !== 0) {
            C(this.ws, "RSV1, RSV2, RSV3 must be clear");
            return;
          }
          if (y && !U(I)) {
            C(this.ws, "Invalid frame type was fragmented.");
            return;
          }
          if (U(I) && this.#o.length > 0) {
            C(this.ws, "Expected continuation frame");
            return;
          }
          if (this.#t.fragmented && y) {
            C(this.ws, "Fragmented frame exceeded 125 bytes.");
            return;
          }
          if ((S > 125 || y) && b(I)) {
            C(this.ws, "Control frame either too large or fragmented");
            return;
          }
          if (G(I) && this.#o.length === 0 && !this.#t.compressed) {
            C(this.ws, "Unexpected continuation frame");
            return;
          }
          S <= 125 ? (this.#t.payloadLength = S, this.#r = t.READ_DATA) : S === 126 ? this.#r = t.PAYLOADLENGTH_16 : S === 127 && (this.#r = t.PAYLOADLENGTH_64), U(I) && (this.#t.binaryType = I, this.#t.compressed = T !== 0), this.#t.opcode = I, this.#t.masked = m, this.#t.fin = f, this.#t.fragmented = y;
        } else if (this.#r === t.PAYLOADLENGTH_16) {
          if (this.#A < 2)
            return s();
          const E = this.consume(2);
          this.#t.payloadLength = E.readUInt16BE(0), this.#r = t.READ_DATA;
        } else if (this.#r === t.PAYLOADLENGTH_64) {
          if (this.#A < 8)
            return s();
          const E = this.consume(8), f = E.readUInt32BE(0);
          if (f > 2 ** 31 - 1) {
            C(this.ws, "Received payload length > 2^31 bytes.");
            return;
          }
          const I = E.readUInt32BE(4);
          this.#t.payloadLength = (f << 8) + I, this.#r = t.READ_DATA;
        } else if (this.#r === t.READ_DATA) {
          if (this.#A < this.#t.payloadLength)
            return s();
          const E = this.consume(this.#t.payloadLength);
          if (b(this.#t.opcode))
            this.#s = this.parseControlFrame(E), this.#r = t.INFO;
          else if (this.#t.compressed) {
            this.#n.get("permessage-deflate").decompress(E, this.#t.fin, (f, I) => {
              if (f) {
                N(this.ws, 1007, f.message, f.message.length);
                return;
              }
              if (this.#o.push(I), !this.#t.fin) {
                this.#r = t.INFO, this.#s = !0, this.run(s);
                return;
              }
              w(this.ws, this.#t.binaryType, Buffer.concat(this.#o)), this.#s = !0, this.#r = t.INFO, this.#o.length = 0, this.run(s);
            }), this.#s = !1;
            break;
          } else {
            if (this.#o.push(E), !this.#t.fragmented && this.#t.fin) {
              const f = Buffer.concat(this.#o);
              w(this.ws, this.#t.binaryType, f), this.#o.length = 0;
            }
            this.#r = t.INFO;
          }
        }
    }
    /**
     * Take n bytes from the buffered Buffers
     * @param {number} n
     * @returns {Buffer}
     */
    consume(s) {
      if (s > this.#A)
        throw new Error("Called consume() before buffers satiated.");
      if (s === 0)
        return n;
      if (this.#e[0].length === s)
        return this.#A -= this.#e[0].length, this.#e.shift();
      const E = Buffer.allocUnsafe(s);
      let f = 0;
      for (; f !== s; ) {
        const I = this.#e[0], { length: m } = I;
        if (m + f === s) {
          E.set(this.#e.shift(), f);
          break;
        } else if (m + f > s) {
          E.set(I.subarray(0, s - f), f), this.#e[0] = I.subarray(s - f);
          break;
        } else
          E.set(this.#e.shift(), f), f += I.length;
      }
      return this.#A -= s, E;
    }
    parseCloseBody(s) {
      r(s.length !== 1);
      let E;
      if (s.length >= 2 && (E = s.readUInt16BE(0)), E !== void 0 && !h(E))
        return { code: 1002, reason: "Invalid status code", error: !0 };
      let f = s.subarray(2);
      f[0] === 239 && f[1] === 187 && f[2] === 191 && (f = f.subarray(3));
      try {
        f = D(f);
      } catch {
        return { code: 1007, reason: "Invalid UTF-8", error: !0 };
      }
      return { code: E, reason: f, error: !1 };
    }
    /**
     * Parses control frames.
     * @param {Buffer} body
     */
    parseControlFrame(s) {
      const { opcode: E, payloadLength: f } = this.#t;
      if (E === o.CLOSE) {
        if (f === 1)
          return C(this.ws, "Received close frame with a 1-byte body."), !1;
        if (this.#t.closeInfo = this.parseCloseBody(s), this.#t.closeInfo.error) {
          const { code: I, reason: m } = this.#t.closeInfo;
          return N(this.ws, I, m, m.length), C(this.ws, m), !1;
        }
        if (this.ws[Q] !== c.SENT) {
          let I = n;
          this.#t.closeInfo.code && (I = Buffer.allocUnsafe(2), I.writeUInt16BE(this.#t.closeInfo.code, 0));
          const m = new M(I);
          this.ws[B].socket.write(
            m.createFrame(o.CLOSE),
            (y) => {
              y || (this.ws[Q] = c.SENT);
            }
          );
        }
        return this.ws[g] = A.CLOSING, this.ws[i] = !0, !1;
      } else if (E === o.PING) {
        if (!this.ws[i]) {
          const I = new M(s);
          this.ws[B].socket.write(I.createFrame(o.PONG)), a.ping.hasSubscribers && a.ping.publish({
            payload: s
          });
        }
      } else E === o.PONG && a.pong.hasSubscribers && a.pong.publish({
        payload: s
      });
      return !0;
    }
    get closingInfo() {
      return this.#t.closeInfo;
    }
  }
  return Hr = {
    ByteParser: l
  }, Hr;
}
var Vr, on;
function Sa() {
  if (on) return Vr;
  on = 1;
  const { WebsocketFrameSend: e } = gs(), { opcodes: r, sendHints: t } = mA(), o = zn(), A = Buffer[Symbol.species];
  class n {
    /**
     * @type {FixedQueue}
     */
    #e = new o();
    /**
     * @type {boolean}
     */
    #A = !1;
    /** @type {import('node:net').Socket} */
    #s;
    constructor(B) {
      this.#s = B;
    }
    add(B, i, a) {
      if (a !== t.blob) {
        const u = c(B, a);
        if (!this.#A)
          this.#s.write(u, i);
        else {
          const C = {
            promise: null,
            callback: i,
            frame: u
          };
          this.#e.push(C);
        }
        return;
      }
      const h = {
        promise: B.arrayBuffer().then((u) => {
          h.promise = null, h.frame = c(u, a);
        }),
        callback: i,
        frame: null
      };
      this.#e.push(h), this.#A || this.#r();
    }
    async #r() {
      this.#A = !0;
      const B = this.#e;
      for (; !B.isEmpty(); ) {
        const i = B.shift();
        i.promise !== null && await i.promise, this.#s.write(i.frame, i.callback), i.callback = i.frame = null;
      }
      this.#A = !1;
    }
  }
  function c(Q, B) {
    return new e(g(Q, B)).createFrame(B === t.string ? r.TEXT : r.BINARY);
  }
  function g(Q, B) {
    switch (B) {
      case t.string:
        return Buffer.from(Q);
      case t.arrayBuffer:
      case t.blob:
        return new A(Q);
      case t.typedArray:
        return new A(Q.buffer, Q.byteOffset, Q.byteLength);
    }
  }
  return Vr = { SendQueue: n }, Vr;
}
var Pr, nn;
function Ua() {
  if (nn) return Pr;
  nn = 1;
  const { webidl: e } = Xe(), { URLSerializer: r } = eA(), { environmentSettingsObject: t } = rA(), { staticPropertyDescriptors: o, states: A, sentCloseFrameState: n, sendHints: c } = mA(), {
    kWebSocketURL: g,
    kReadyState: Q,
    kController: B,
    kBinaryType: i,
    kResponse: a,
    kSentClose: h,
    kByteParser: u
  } = tt(), {
    isConnecting: C,
    isEstablished: w,
    isClosing: D,
    isValidSubprotocol: b,
    fireEvent: U
  } = rt(), { establishWebSocketConnection: G, closeWebSocketConnection: M } = oi(), { ByteParser: N } = Ta(), { kEnumerableProperty: d, isBlobLike: l } = Ue(), { getGlobalDispatcher: p } = is(), { types: s } = $e, { ErrorEvent: E, CloseEvent: f } = vA(), { SendQueue: I } = Sa();
  class m extends EventTarget {
    #e = {
      open: null,
      error: null,
      close: null,
      message: null
    };
    #A = 0;
    #s = "";
    #r = "";
    /** @type {SendQueue} */
    #t;
    /**
     * @param {string} url
     * @param {string|string[]} protocols
     */
    constructor(L, v = []) {
      super(), e.util.markAsUncloneable(this);
      const $ = "WebSocket constructor";
      e.argumentLengthCheck(arguments, 1, $);
      const oe = e.converters["DOMString or sequence<DOMString> or WebSocketInit"](v, $, "options");
      L = e.converters.USVString(L, $, "url"), v = oe.protocols;
      const ge = t.settingsObject.baseUrl;
      let ae;
      try {
        ae = new URL(L, ge);
      } catch (Be) {
        throw new DOMException(Be, "SyntaxError");
      }
      if (ae.protocol === "http:" ? ae.protocol = "ws:" : ae.protocol === "https:" && (ae.protocol = "wss:"), ae.protocol !== "ws:" && ae.protocol !== "wss:")
        throw new DOMException(
          `Expected a ws: or wss: protocol, got ${ae.protocol}`,
          "SyntaxError"
        );
      if (ae.hash || ae.href.endsWith("#"))
        throw new DOMException("Got fragment", "SyntaxError");
      if (typeof v == "string" && (v = [v]), v.length !== new Set(v.map((Be) => Be.toLowerCase())).size)
        throw new DOMException("Invalid Sec-WebSocket-Protocol value", "SyntaxError");
      if (v.length > 0 && !v.every((Be) => b(Be)))
        throw new DOMException("Invalid Sec-WebSocket-Protocol value", "SyntaxError");
      this[g] = new URL(ae.href);
      const he = t.settingsObject;
      this[B] = G(
        ae,
        v,
        he,
        this,
        (Be, Qe) => this.#o(Be, Qe),
        oe
      ), this[Q] = m.CONNECTING, this[h] = n.NOT_SENT, this[i] = "blob";
    }
    /**
     * @see https://websockets.spec.whatwg.org/#dom-websocket-close
     * @param {number|undefined} code
     * @param {string|undefined} reason
     */
    close(L = void 0, v = void 0) {
      e.brandCheck(this, m);
      const $ = "WebSocket.close";
      if (L !== void 0 && (L = e.converters["unsigned short"](L, $, "code", { clamp: !0 })), v !== void 0 && (v = e.converters.USVString(v, $, "reason")), L !== void 0 && L !== 1e3 && (L < 3e3 || L > 4999))
        throw new DOMException("invalid code", "InvalidAccessError");
      let oe = 0;
      if (v !== void 0 && (oe = Buffer.byteLength(v), oe > 123))
        throw new DOMException(
          `Reason must be less than 123 bytes; received ${oe}`,
          "SyntaxError"
        );
      M(this, L, v, oe);
    }
    /**
     * @see https://websockets.spec.whatwg.org/#dom-websocket-send
     * @param {NodeJS.TypedArray|ArrayBuffer|Blob|string} data
     */
    send(L) {
      e.brandCheck(this, m);
      const v = "WebSocket.send";
      if (e.argumentLengthCheck(arguments, 1, v), L = e.converters.WebSocketSendData(L, v, "data"), C(this))
        throw new DOMException("Sent before connected.", "InvalidStateError");
      if (!(!w(this) || D(this)))
        if (typeof L == "string") {
          const $ = Buffer.byteLength(L);
          this.#A += $, this.#t.add(L, () => {
            this.#A -= $;
          }, c.string);
        } else s.isArrayBuffer(L) ? (this.#A += L.byteLength, this.#t.add(L, () => {
          this.#A -= L.byteLength;
        }, c.arrayBuffer)) : ArrayBuffer.isView(L) ? (this.#A += L.byteLength, this.#t.add(L, () => {
          this.#A -= L.byteLength;
        }, c.typedArray)) : l(L) && (this.#A += L.size, this.#t.add(L, () => {
          this.#A -= L.size;
        }, c.blob));
    }
    get readyState() {
      return e.brandCheck(this, m), this[Q];
    }
    get bufferedAmount() {
      return e.brandCheck(this, m), this.#A;
    }
    get url() {
      return e.brandCheck(this, m), r(this[g]);
    }
    get extensions() {
      return e.brandCheck(this, m), this.#r;
    }
    get protocol() {
      return e.brandCheck(this, m), this.#s;
    }
    get onopen() {
      return e.brandCheck(this, m), this.#e.open;
    }
    set onopen(L) {
      e.brandCheck(this, m), this.#e.open && this.removeEventListener("open", this.#e.open), typeof L == "function" ? (this.#e.open = L, this.addEventListener("open", L)) : this.#e.open = null;
    }
    get onerror() {
      return e.brandCheck(this, m), this.#e.error;
    }
    set onerror(L) {
      e.brandCheck(this, m), this.#e.error && this.removeEventListener("error", this.#e.error), typeof L == "function" ? (this.#e.error = L, this.addEventListener("error", L)) : this.#e.error = null;
    }
    get onclose() {
      return e.brandCheck(this, m), this.#e.close;
    }
    set onclose(L) {
      e.brandCheck(this, m), this.#e.close && this.removeEventListener("close", this.#e.close), typeof L == "function" ? (this.#e.close = L, this.addEventListener("close", L)) : this.#e.close = null;
    }
    get onmessage() {
      return e.brandCheck(this, m), this.#e.message;
    }
    set onmessage(L) {
      e.brandCheck(this, m), this.#e.message && this.removeEventListener("message", this.#e.message), typeof L == "function" ? (this.#e.message = L, this.addEventListener("message", L)) : this.#e.message = null;
    }
    get binaryType() {
      return e.brandCheck(this, m), this[i];
    }
    set binaryType(L) {
      e.brandCheck(this, m), L !== "blob" && L !== "arraybuffer" ? this[i] = "blob" : this[i] = L;
    }
    /**
     * @see https://websockets.spec.whatwg.org/#feedback-from-the-protocol
     */
    #o(L, v) {
      this[a] = L;
      const $ = new N(this, v);
      $.on("drain", y), $.on("error", S.bind(this)), L.socket.ws = this, this[u] = $, this.#t = new I(L.socket), this[Q] = A.OPEN;
      const oe = L.headersList.get("sec-websocket-extensions");
      oe !== null && (this.#r = oe);
      const ge = L.headersList.get("sec-websocket-protocol");
      ge !== null && (this.#s = ge), U("open", this);
    }
  }
  m.CONNECTING = m.prototype.CONNECTING = A.CONNECTING, m.OPEN = m.prototype.OPEN = A.OPEN, m.CLOSING = m.prototype.CLOSING = A.CLOSING, m.CLOSED = m.prototype.CLOSED = A.CLOSED, Object.defineProperties(m.prototype, {
    CONNECTING: o,
    OPEN: o,
    CLOSING: o,
    CLOSED: o,
    url: d,
    readyState: d,
    bufferedAmount: d,
    onopen: d,
    onerror: d,
    onclose: d,
    close: d,
    onmessage: d,
    binaryType: d,
    send: d,
    extensions: d,
    protocol: d,
    [Symbol.toStringTag]: {
      value: "WebSocket",
      writable: !1,
      enumerable: !1,
      configurable: !0
    }
  }), Object.defineProperties(m, {
    CONNECTING: o,
    OPEN: o,
    CLOSING: o,
    CLOSED: o
  }), e.converters["sequence<DOMString>"] = e.sequenceConverter(
    e.converters.DOMString
  ), e.converters["DOMString or sequence<DOMString>"] = function(T, L, v) {
    return e.util.Type(T) === "Object" && Symbol.iterator in T ? e.converters["sequence<DOMString>"](T) : e.converters.DOMString(T, L, v);
  }, e.converters.WebSocketInit = e.dictionaryConverter([
    {
      key: "protocols",
      converter: e.converters["DOMString or sequence<DOMString>"],
      defaultValue: () => new Array(0)
    },
    {
      key: "dispatcher",
      converter: e.converters.any,
      defaultValue: () => p()
    },
    {
      key: "headers",
      converter: e.nullableConverter(e.converters.HeadersInit)
    }
  ]), e.converters["DOMString or sequence<DOMString> or WebSocketInit"] = function(T) {
    return e.util.Type(T) === "Object" && !(Symbol.iterator in T) ? e.converters.WebSocketInit(T) : { protocols: e.converters["DOMString or sequence<DOMString>"](T) };
  }, e.converters.WebSocketSendData = function(T) {
    if (e.util.Type(T) === "Object") {
      if (l(T))
        return e.converters.Blob(T, { strict: !1 });
      if (ArrayBuffer.isView(T) || s.isArrayBuffer(T))
        return e.converters.BufferSource(T);
    }
    return e.converters.USVString(T);
  };
  function y() {
    this.ws[a].socket.resume();
  }
  function S(T) {
    let L, v;
    T instanceof f ? (L = T.reason, v = T.code) : L = T.message, U("error", this, () => new E("error", { error: T, message: L })), M(this, v);
  }
  return Pr = {
    WebSocket: m
  }, Pr;
}
var xr, an;
function ni() {
  if (an) return xr;
  an = 1;
  function e(o) {
    return o.indexOf("\0") === -1;
  }
  function r(o) {
    if (o.length === 0) return !1;
    for (let A = 0; A < o.length; A++)
      if (o.charCodeAt(A) < 48 || o.charCodeAt(A) > 57) return !1;
    return !0;
  }
  function t(o) {
    return new Promise((A) => {
      setTimeout(A, o).unref();
    });
  }
  return xr = {
    isValidLastEventId: e,
    isASCIINumber: r,
    delay: t
  }, xr;
}
var Or, cn;
function Na() {
  if (cn) return Or;
  cn = 1;
  const { Transform: e } = tA, { isASCIINumber: r, isValidLastEventId: t } = ni(), o = [239, 187, 191], A = 10, n = 13, c = 58, g = 32;
  class Q extends e {
    /**
     * @type {eventSourceSettings}
     */
    state = null;
    /**
     * Leading byte-order-mark check.
     * @type {boolean}
     */
    checkBOM = !0;
    /**
     * @type {boolean}
     */
    crlfCheck = !1;
    /**
     * @type {boolean}
     */
    eventEndCheck = !1;
    /**
     * @type {Buffer}
     */
    buffer = null;
    pos = 0;
    event = {
      data: void 0,
      event: void 0,
      id: void 0,
      retry: void 0
    };
    /**
     * @param {object} options
     * @param {eventSourceSettings} options.eventSourceSettings
     * @param {Function} [options.push]
     */
    constructor(i = {}) {
      i.readableObjectMode = !0, super(i), this.state = i.eventSourceSettings || {}, i.push && (this.push = i.push);
    }
    /**
     * @param {Buffer} chunk
     * @param {string} _encoding
     * @param {Function} callback
     * @returns {void}
     */
    _transform(i, a, h) {
      if (i.length === 0) {
        h();
        return;
      }
      if (this.buffer ? this.buffer = Buffer.concat([this.buffer, i]) : this.buffer = i, this.checkBOM)
        switch (this.buffer.length) {
          case 1:
            if (this.buffer[0] === o[0]) {
              h();
              return;
            }
            this.checkBOM = !1, h();
            return;
          case 2:
            if (this.buffer[0] === o[0] && this.buffer[1] === o[1]) {
              h();
              return;
            }
            this.checkBOM = !1;
            break;
          case 3:
            if (this.buffer[0] === o[0] && this.buffer[1] === o[1] && this.buffer[2] === o[2]) {
              this.buffer = Buffer.alloc(0), this.checkBOM = !1, h();
              return;
            }
            this.checkBOM = !1;
            break;
          default:
            this.buffer[0] === o[0] && this.buffer[1] === o[1] && this.buffer[2] === o[2] && (this.buffer = this.buffer.subarray(3)), this.checkBOM = !1;
            break;
        }
      for (; this.pos < this.buffer.length; ) {
        if (this.eventEndCheck) {
          if (this.crlfCheck) {
            if (this.buffer[this.pos] === A) {
              this.buffer = this.buffer.subarray(this.pos + 1), this.pos = 0, this.crlfCheck = !1;
              continue;
            }
            this.crlfCheck = !1;
          }
          if (this.buffer[this.pos] === A || this.buffer[this.pos] === n) {
            this.buffer[this.pos] === n && (this.crlfCheck = !0), this.buffer = this.buffer.subarray(this.pos + 1), this.pos = 0, (this.event.data !== void 0 || this.event.event || this.event.id || this.event.retry) && this.processEvent(this.event), this.clearEvent();
            continue;
          }
          this.eventEndCheck = !1;
          continue;
        }
        if (this.buffer[this.pos] === A || this.buffer[this.pos] === n) {
          this.buffer[this.pos] === n && (this.crlfCheck = !0), this.parseLine(this.buffer.subarray(0, this.pos), this.event), this.buffer = this.buffer.subarray(this.pos + 1), this.pos = 0, this.eventEndCheck = !0;
          continue;
        }
        this.pos++;
      }
      h();
    }
    /**
     * @param {Buffer} line
     * @param {EventStreamEvent} event
     */
    parseLine(i, a) {
      if (i.length === 0)
        return;
      const h = i.indexOf(c);
      if (h === 0)
        return;
      let u = "", C = "";
      if (h !== -1) {
        u = i.subarray(0, h).toString("utf8");
        let w = h + 1;
        i[w] === g && ++w, C = i.subarray(w).toString("utf8");
      } else
        u = i.toString("utf8"), C = "";
      switch (u) {
        case "data":
          a[u] === void 0 ? a[u] = C : a[u] += `
${C}`;
          break;
        case "retry":
          r(C) && (a[u] = C);
          break;
        case "id":
          t(C) && (a[u] = C);
          break;
        case "event":
          C.length > 0 && (a[u] = C);
          break;
      }
    }
    /**
     * @param {EventSourceStreamEvent} event
     */
    processEvent(i) {
      i.retry && r(i.retry) && (this.state.reconnectionTime = parseInt(i.retry, 10)), i.id && t(i.id) && (this.state.lastEventId = i.id), i.data !== void 0 && this.push({
        type: i.event || "message",
        options: {
          data: i.data,
          lastEventId: this.state.lastEventId,
          origin: this.state.origin
        }
      });
    }
    clearEvent() {
      this.event = {
        data: void 0,
        event: void 0,
        id: void 0,
        retry: void 0
      };
    }
  }
  return Or = {
    EventSourceStream: Q
  }, Or;
}
var _r, gn;
function Ma() {
  if (gn) return _r;
  gn = 1;
  const { pipeline: e } = tA, { fetching: r } = At(), { makeRequest: t } = GA(), { webidl: o } = Xe(), { EventSourceStream: A } = Na(), { parseMIMEType: n } = eA(), { createFastMessageEvent: c } = vA(), { isNetworkError: g } = et(), { delay: Q } = ni(), { kEnumerableProperty: B } = Ue(), { environmentSettingsObject: i } = rA();
  let a = !1;
  const h = 3e3, u = 0, C = 1, w = 2, D = "anonymous", b = "use-credentials";
  class U extends EventTarget {
    #e = {
      open: null,
      error: null,
      message: null
    };
    #A = null;
    #s = !1;
    #r = u;
    #t = null;
    #o = null;
    #n;
    /**
     * @type {import('./eventsource-stream').eventSourceSettings}
     */
    #i;
    /**
     * Creates a new EventSource object.
     * @param {string} url
     * @param {EventSourceInit} [eventSourceInitDict]
     * @see https://html.spec.whatwg.org/multipage/server-sent-events.html#the-eventsource-interface
     */
    constructor(N, d = {}) {
      super(), o.util.markAsUncloneable(this);
      const l = "EventSource constructor";
      o.argumentLengthCheck(arguments, 1, l), a || (a = !0, process.emitWarning("EventSource is experimental, expect them to change at any time.", {
        code: "UNDICI-ES"
      })), N = o.converters.USVString(N, l, "url"), d = o.converters.EventSourceInitDict(d, l, "eventSourceInitDict"), this.#n = d.dispatcher, this.#i = {
        lastEventId: "",
        reconnectionTime: h
      };
      const p = i;
      let s;
      try {
        s = new URL(N, p.settingsObject.baseUrl), this.#i.origin = s.origin;
      } catch (I) {
        throw new DOMException(I, "SyntaxError");
      }
      this.#A = s.href;
      let E = D;
      d.withCredentials && (E = b, this.#s = !0);
      const f = {
        redirect: "follow",
        keepalive: !0,
        // @see https://html.spec.whatwg.org/multipage/urls-and-fetching.html#cors-settings-attributes
        mode: "cors",
        credentials: E === "anonymous" ? "same-origin" : "omit",
        referrer: "no-referrer"
      };
      f.client = i.settingsObject, f.headersList = [["accept", { name: "accept", value: "text/event-stream" }]], f.cache = "no-store", f.initiator = "other", f.urlList = [new URL(this.#A)], this.#t = t(f), this.#a();
    }
    /**
     * Returns the state of this EventSource object's connection. It can have the
     * values described below.
     * @returns {0|1|2}
     * @readonly
     */
    get readyState() {
      return this.#r;
    }
    /**
     * Returns the URL providing the event stream.
     * @readonly
     * @returns {string}
     */
    get url() {
      return this.#A;
    }
    /**
     * Returns a boolean indicating whether the EventSource object was
     * instantiated with CORS credentials set (true), or not (false, the default).
     */
    get withCredentials() {
      return this.#s;
    }
    #a() {
      if (this.#r === w) return;
      this.#r = u;
      const N = {
        request: this.#t,
        dispatcher: this.#n
      }, d = (l) => {
        g(l) && (this.dispatchEvent(new Event("error")), this.close()), this.#c();
      };
      N.processResponseEndOfBody = d, N.processResponse = (l) => {
        if (g(l))
          if (l.aborted) {
            this.close(), this.dispatchEvent(new Event("error"));
            return;
          } else {
            this.#c();
            return;
          }
        const p = l.headersList.get("content-type", !0), s = p !== null ? n(p) : "failure", E = s !== "failure" && s.essence === "text/event-stream";
        if (l.status !== 200 || E === !1) {
          this.close(), this.dispatchEvent(new Event("error"));
          return;
        }
        this.#r = C, this.dispatchEvent(new Event("open")), this.#i.origin = l.urlList[l.urlList.length - 1].origin;
        const f = new A({
          eventSourceSettings: this.#i,
          push: (I) => {
            this.dispatchEvent(c(
              I.type,
              I.options
            ));
          }
        });
        e(
          l.body.stream,
          f,
          (I) => {
            I?.aborted === !1 && (this.close(), this.dispatchEvent(new Event("error")));
          }
        );
      }, this.#o = r(N);
    }
    /**
     * @see https://html.spec.whatwg.org/multipage/server-sent-events.html#sse-processing-model
     * @returns {Promise<void>}
     */
    async #c() {
      this.#r !== w && (this.#r = u, this.dispatchEvent(new Event("error")), await Q(this.#i.reconnectionTime), this.#r === u && (this.#i.lastEventId.length && this.#t.headersList.set("last-event-id", this.#i.lastEventId, !0), this.#a()));
    }
    /**
     * Closes the connection, if any, and sets the readyState attribute to
     * CLOSED.
     */
    close() {
      o.brandCheck(this, U), this.#r !== w && (this.#r = w, this.#o.abort(), this.#t = null);
    }
    get onopen() {
      return this.#e.open;
    }
    set onopen(N) {
      this.#e.open && this.removeEventListener("open", this.#e.open), typeof N == "function" ? (this.#e.open = N, this.addEventListener("open", N)) : this.#e.open = null;
    }
    get onmessage() {
      return this.#e.message;
    }
    set onmessage(N) {
      this.#e.message && this.removeEventListener("message", this.#e.message), typeof N == "function" ? (this.#e.message = N, this.addEventListener("message", N)) : this.#e.message = null;
    }
    get onerror() {
      return this.#e.error;
    }
    set onerror(N) {
      this.#e.error && this.removeEventListener("error", this.#e.error), typeof N == "function" ? (this.#e.error = N, this.addEventListener("error", N)) : this.#e.error = null;
    }
  }
  const G = {
    CONNECTING: {
      __proto__: null,
      configurable: !1,
      enumerable: !0,
      value: u,
      writable: !1
    },
    OPEN: {
      __proto__: null,
      configurable: !1,
      enumerable: !0,
      value: C,
      writable: !1
    },
    CLOSED: {
      __proto__: null,
      configurable: !1,
      enumerable: !0,
      value: w,
      writable: !1
    }
  };
  return Object.defineProperties(U, G), Object.defineProperties(U.prototype, G), Object.defineProperties(U.prototype, {
    close: B,
    onerror: B,
    onmessage: B,
    onopen: B,
    readyState: B,
    url: B,
    withCredentials: B
  }), o.converters.EventSourceInitDict = o.dictionaryConverter([
    {
      key: "withCredentials",
      converter: o.converters.boolean,
      defaultValue: () => !1
    },
    {
      key: "dispatcher",
      // undici only
      converter: o.converters.any
    }
  ]), _r = {
    EventSource: U,
    defaultReconnectionTime: h
  }, _r;
}
var ln;
function ii() {
  if (ln) return me;
  ln = 1;
  const e = UA(), r = zA(), t = NA(), o = ta(), A = MA(), n = Kn(), c = ra(), g = sa(), Q = Ye(), B = Ue(), { InvalidArgumentError: i } = Q, a = ga(), h = ZA(), u = Ai(), C = ua(), w = ti(), D = $n(), b = ns(), { getGlobalDispatcher: U, setGlobalDispatcher: G } = is(), M = as(), N = ss(), d = os();
  Object.assign(r.prototype, a), me.Dispatcher = r, me.Client = e, me.Pool = t, me.BalancedPool = o, me.Agent = A, me.ProxyAgent = n, me.EnvHttpProxyAgent = c, me.RetryAgent = g, me.RetryHandler = b, me.DecoratorHandler = M, me.RedirectHandler = N, me.createRedirectInterceptor = d, me.interceptors = {
    redirect: Qa(),
    retry: Ba(),
    dump: ha(),
    dns: Ia()
  }, me.buildConnector = h, me.errors = Q, me.util = {
    parseHeaders: B.parseHeaders,
    headerNameToString: B.headerNameToString
  };
  function l(he) {
    return (Be, Qe, ye) => {
      if (typeof Qe == "function" && (ye = Qe, Qe = null), !Be || typeof Be != "string" && typeof Be != "object" && !(Be instanceof URL))
        throw new i("invalid url");
      if (Qe != null && typeof Qe != "object")
        throw new i("invalid opts");
      if (Qe && Qe.path != null) {
        if (typeof Qe.path != "string")
          throw new i("invalid opts.path");
        let W = Qe.path;
        Qe.path.startsWith("/") || (W = `/${W}`), Be = new URL(B.parseOrigin(Be).origin + W);
      } else
        Qe || (Qe = typeof Be == "object" ? Be : {}), Be = B.parseURL(Be);
      const { agent: we, dispatcher: j = U() } = Qe;
      if (we)
        throw new i("unsupported opts.agent. Did you mean opts.client?");
      return he.call(j, {
        ...Qe,
        origin: Be.origin,
        path: Be.search ? `${Be.pathname}${Be.search}` : Be.pathname,
        method: Qe.method || (Qe.body ? "PUT" : "GET")
      }, ye);
    };
  }
  me.setGlobalDispatcher = G, me.getGlobalDispatcher = U;
  const p = At().fetch;
  me.fetch = async function(Be, Qe = void 0) {
    try {
      return await p(Be, Qe);
    } catch (ye) {
      throw ye && typeof ye == "object" && Error.captureStackTrace(ye), ye;
    }
  }, me.Headers = wA().Headers, me.Response = et().Response, me.Request = GA().Request, me.FormData = XA().FormData, me.File = globalThis.File ?? sA.File, me.FileReader = wa().FileReader;
  const { setGlobalOrigin: s, getGlobalOrigin: E } = Wn();
  me.setGlobalOrigin = s, me.getGlobalOrigin = E;
  const { CacheStorage: f } = Da(), { kConstruct: I } = cs();
  me.caches = new f(I);
  const { deleteCookie: m, getCookies: y, getSetCookies: S, setCookie: T } = ba();
  me.deleteCookie = m, me.getCookies = y, me.getSetCookies = S, me.setCookie = T;
  const { parseMIMEType: L, serializeAMimeType: v } = eA();
  me.parseMIMEType = L, me.serializeAMimeType = v;
  const { CloseEvent: $, ErrorEvent: oe, MessageEvent: ge } = vA();
  me.WebSocket = Ua().WebSocket, me.CloseEvent = $, me.ErrorEvent = oe, me.MessageEvent = ge, me.request = l(a.request), me.stream = l(a.stream), me.pipeline = l(a.pipeline), me.connect = l(a.connect), me.upgrade = l(a.upgrade), me.MockClient = u, me.MockPool = w, me.MockAgent = C, me.mockErrors = D;
  const { EventSource: ae } = Ma();
  return me.EventSource = ae, me;
}
var La = ii(), iA;
(function(e) {
  e[e.OK = 200] = "OK", e[e.MultipleChoices = 300] = "MultipleChoices", e[e.MovedPermanently = 301] = "MovedPermanently", e[e.ResourceMoved = 302] = "ResourceMoved", e[e.SeeOther = 303] = "SeeOther", e[e.NotModified = 304] = "NotModified", e[e.UseProxy = 305] = "UseProxy", e[e.SwitchProxy = 306] = "SwitchProxy", e[e.TemporaryRedirect = 307] = "TemporaryRedirect", e[e.PermanentRedirect = 308] = "PermanentRedirect", e[e.BadRequest = 400] = "BadRequest", e[e.Unauthorized = 401] = "Unauthorized", e[e.PaymentRequired = 402] = "PaymentRequired", e[e.Forbidden = 403] = "Forbidden", e[e.NotFound = 404] = "NotFound", e[e.MethodNotAllowed = 405] = "MethodNotAllowed", e[e.NotAcceptable = 406] = "NotAcceptable", e[e.ProxyAuthenticationRequired = 407] = "ProxyAuthenticationRequired", e[e.RequestTimeout = 408] = "RequestTimeout", e[e.Conflict = 409] = "Conflict", e[e.Gone = 410] = "Gone", e[e.TooManyRequests = 429] = "TooManyRequests", e[e.InternalServerError = 500] = "InternalServerError", e[e.NotImplemented = 501] = "NotImplemented", e[e.BadGateway = 502] = "BadGateway", e[e.ServiceUnavailable = 503] = "ServiceUnavailable", e[e.GatewayTimeout = 504] = "GatewayTimeout";
})(iA || (iA = {}));
var En;
(function(e) {
  e.Accept = "accept", e.ContentType = "content-type";
})(En || (En = {}));
var un;
(function(e) {
  e.ApplicationJson = "application/json";
})(un || (un = {}));
iA.MovedPermanently, iA.ResourceMoved, iA.SeeOther, iA.TemporaryRedirect, iA.PermanentRedirect;
iA.BadGateway, iA.ServiceUnavailable, iA.GatewayTimeout;
const { access: al, appendFile: cl, writeFile: gl } = Ri, { chmod: ll, copyFile: El, lstat: ul, mkdir: Ql, open: Bl, readdir: hl, rename: Il, rm: Cl, rmdir: dl, stat: fl, symlink: pl, unlink: wl } = Yn.promises;
process.platform;
Yn.constants.O_RDONLY;
process.platform;
vn.platform();
vn.arch();
var jr;
(function(e) {
  e[e.Success = 0] = "Success", e[e.Failure = 1] = "Failure";
})(jr || (jr = {}));
function Ga(e, r) {
  return (process.env[`INPUT_${e.replace(/ /g, "_").toUpperCase()}`] || "").trim();
}
function va(e) {
  process.exitCode = jr.Failure, Ya(e);
}
function Ya(e, r = {}) {
  Pi("error", Vi(r), e instanceof Error ? e.toString() : e);
}
const Ja = /^[v^~<>=]*?(\d+)(?:\.([x*]|\d+)(?:\.([x*]|\d+)(?:\.([x*]|\d+))?(?:-([\da-z\-]+(?:\.[\da-z\-]+)*))?(?:\+[\da-z\-]+(?:\.[\da-z\-]+)*)?)?)?$/i, Qn = (e) => {
  if (typeof e != "string")
    throw new TypeError("Invalid argument expected string");
  const r = e.match(Ja);
  if (!r)
    throw new Error(`Invalid argument not valid semver ('${e}' received)`);
  return r.shift(), r;
}, Bn = (e) => e === "*" || e === "x" || e === "X", hn = (e) => {
  const r = parseInt(e, 10);
  return isNaN(r) ? e : r;
}, Ha = (e, r) => typeof e != typeof r ? [String(e), String(r)] : [e, r], Va = (e, r) => {
  if (Bn(e) || Bn(r))
    return 0;
  const [t, o] = Ha(hn(e), hn(r));
  return t > o ? 1 : t < o ? -1 : 0;
}, In = (e, r) => {
  for (let t = 0; t < Math.max(e.length, r.length); t++) {
    const o = Va(e[t] || "0", r[t] || "0");
    if (o !== 0)
      return o;
  }
  return 0;
}, Pa = (e, r) => {
  const t = Qn(e), o = Qn(r), A = t.pop(), n = o.pop(), c = In(t, o);
  return c !== 0 ? c : A && n ? In(A.split("."), n.split(".")) : A || n ? A ? -1 : 1 : 0;
}, Wr = (e, r, t) => {
  xa(t);
  const o = Pa(e, r);
  return ai[t].includes(o);
}, ai = {
  ">": [1],
  ">=": [0, 1],
  "=": [0],
  "<=": [-1, 0],
  "<": [-1],
  "!=": [-1, 1]
}, Cn = Object.keys(ai), xa = (e) => {
  if (Cn.indexOf(e) === -1)
    throw new Error(`Invalid operator, expected one of ${Cn.join("|")}`);
};
function Oa(e, r) {
  var t = Object.setPrototypeOf;
  t ? t(e, r) : e.__proto__ = r;
}
function _a(e, r) {
  r === void 0 && (r = e.constructor);
  var t = Error.captureStackTrace;
  t && t(e, r);
}
var Wa = /* @__PURE__ */ (function() {
  var e = function(t, o) {
    return e = Object.setPrototypeOf || {
      __proto__: []
    } instanceof Array && function(A, n) {
      A.__proto__ = n;
    } || function(A, n) {
      for (var c in n)
        Object.prototype.hasOwnProperty.call(n, c) && (A[c] = n[c]);
    }, e(t, o);
  };
  return function(r, t) {
    if (typeof t != "function" && t !== null) throw new TypeError("Class extends value " + String(t) + " is not a constructor or null");
    e(r, t);
    function o() {
      this.constructor = r;
    }
    r.prototype = t === null ? Object.create(t) : (o.prototype = t.prototype, new o());
  };
})(), qa = (function(e) {
  Wa(r, e);
  function r(t, o) {
    var A = this.constructor, n = e.call(this, t, o) || this;
    return Object.defineProperty(n, "name", {
      value: A.name,
      enumerable: !1,
      configurable: !0
    }), Oa(n, A.prototype), _a(n), n;
  }
  return r;
})(Error);
class lA extends qa {
  constructor(r) {
    super(r);
  }
}
class za extends lA {
  constructor(r, t) {
    super(
      `Couldn't get the already existing issue #${String(r)}. Error message: ${t}`
    );
  }
}
class Za extends lA {
  constructor(r, t) {
    super(
      `Couldn't add a comment to issue #${String(r)}. Error message: ${t}`
    );
  }
}
class Ka extends lA {
  constructor(r) {
    super(`Couldn't create an issue. Error message: ${r}`);
  }
}
class Xa extends lA {
  constructor(r) {
    super(`Couldn't list issues. Error message: ${r}`);
  }
}
class ci extends lA {
  constructor(r, t) {
    super(
      `Couldn't update the existing issue #${String(r)}. Error message: ${t}`
    );
  }
}
class gi {
  /**
   * Hydrate the context from the environment
   */
  constructor() {
    var r, t, o;
    if (this.payload = {}, process.env.GITHUB_EVENT_PATH)
      if (ki(process.env.GITHUB_EVENT_PATH))
        this.payload = JSON.parse(bi(process.env.GITHUB_EVENT_PATH, { encoding: "utf8" }));
      else {
        const A = process.env.GITHUB_EVENT_PATH;
        process.stdout.write(`GITHUB_EVENT_PATH ${A} does not exist${Di}`);
      }
    this.eventName = process.env.GITHUB_EVENT_NAME, this.sha = process.env.GITHUB_SHA, this.ref = process.env.GITHUB_REF, this.workflow = process.env.GITHUB_WORKFLOW, this.action = process.env.GITHUB_ACTION, this.actor = process.env.GITHUB_ACTOR, this.job = process.env.GITHUB_JOB, this.runAttempt = parseInt(process.env.GITHUB_RUN_ATTEMPT, 10), this.runNumber = parseInt(process.env.GITHUB_RUN_NUMBER, 10), this.runId = parseInt(process.env.GITHUB_RUN_ID, 10), this.apiUrl = (r = process.env.GITHUB_API_URL) !== null && r !== void 0 ? r : "https://api.github.com", this.serverUrl = (t = process.env.GITHUB_SERVER_URL) !== null && t !== void 0 ? t : "https://github.com", this.graphqlUrl = (o = process.env.GITHUB_GRAPHQL_URL) !== null && o !== void 0 ? o : "https://api.github.com/graphql";
  }
  get issue() {
    const r = this.payload;
    return Object.assign(Object.assign({}, this.repo), { number: (r.issue || r.pull_request || r).number });
  }
  get repo() {
    if (process.env.GITHUB_REPOSITORY) {
      const [r, t] = process.env.GITHUB_REPOSITORY.split("/");
      return { owner: r, repo: t };
    }
    if (this.payload.repository)
      return {
        owner: this.payload.repository.owner.login,
        repo: this.payload.repository.name
      };
    throw new Error("context.repo requires a GITHUB_REPOSITORY environment variable like 'owner/repo'");
  }
}
var Ve = {}, DA = {}, dn;
function ja() {
  if (dn) return DA;
  dn = 1, Object.defineProperty(DA, "__esModule", { value: !0 }), DA.getProxyUrl = e, DA.checkBypass = r;
  function e(A) {
    const n = A.protocol === "https:";
    if (r(A))
      return;
    const c = n ? process.env.https_proxy || process.env.HTTPS_PROXY : process.env.http_proxy || process.env.HTTP_PROXY;
    if (c)
      try {
        return new o(c);
      } catch {
        if (!c.startsWith("http://") && !c.startsWith("https://"))
          return new o(`http://${c}`);
      }
    else
      return;
  }
  function r(A) {
    if (!A.hostname)
      return !1;
    const n = A.hostname;
    if (t(n))
      return !0;
    const c = process.env.no_proxy || process.env.NO_PROXY || "";
    if (!c)
      return !1;
    let g;
    A.port ? g = Number(A.port) : A.protocol === "http:" ? g = 80 : A.protocol === "https:" && (g = 443);
    const Q = [A.hostname.toUpperCase()];
    typeof g == "number" && Q.push(`${Q[0]}:${g}`);
    for (const B of c.split(",").map((i) => i.trim().toUpperCase()).filter((i) => i))
      if (B === "*" || Q.some((i) => i === B || i.endsWith(`.${B}`) || B.startsWith(".") && i.endsWith(`${B}`)))
        return !0;
    return !1;
  }
  function t(A) {
    const n = A.toLowerCase();
    return n === "localhost" || n.startsWith("127.") || n.startsWith("[::1]") || n.startsWith("[0:0:0:0:0:0:0:1]");
  }
  class o extends URL {
    constructor(n, c) {
      super(n, c), this._decodedUsername = decodeURIComponent(super.username), this._decodedPassword = decodeURIComponent(super.password);
    }
    get username() {
      return this._decodedUsername;
    }
    get password() {
      return this._decodedPassword;
    }
  }
  return DA;
}
var fn;
function $a() {
  if (fn) return Ve;
  fn = 1;
  var e = Ve && Ve.__createBinding || (Object.create ? (function(l, p, s, E) {
    E === void 0 && (E = s);
    var f = Object.getOwnPropertyDescriptor(p, s);
    (!f || ("get" in f ? !p.__esModule : f.writable || f.configurable)) && (f = { enumerable: !0, get: function() {
      return p[s];
    } }), Object.defineProperty(l, E, f);
  }) : (function(l, p, s, E) {
    E === void 0 && (E = s), l[E] = p[s];
  })), r = Ve && Ve.__setModuleDefault || (Object.create ? (function(l, p) {
    Object.defineProperty(l, "default", { enumerable: !0, value: p });
  }) : function(l, p) {
    l.default = p;
  }), t = Ve && Ve.__importStar || /* @__PURE__ */ (function() {
    var l = function(p) {
      return l = Object.getOwnPropertyNames || function(s) {
        var E = [];
        for (var f in s) Object.prototype.hasOwnProperty.call(s, f) && (E[E.length] = f);
        return E;
      }, l(p);
    };
    return function(p) {
      if (p && p.__esModule) return p;
      var s = {};
      if (p != null) for (var E = l(p), f = 0; f < E.length; f++) E[f] !== "default" && e(s, p, E[f]);
      return r(s, p), s;
    };
  })(), o = Ve && Ve.__awaiter || function(l, p, s, E) {
    function f(I) {
      return I instanceof s ? I : new s(function(m) {
        m(I);
      });
    }
    return new (s || (s = Promise))(function(I, m) {
      function y(L) {
        try {
          T(E.next(L));
        } catch (v) {
          m(v);
        }
      }
      function S(L) {
        try {
          T(E.throw(L));
        } catch (v) {
          m(v);
        }
      }
      function T(L) {
        L.done ? I(L.value) : f(L.value).then(y, S);
      }
      T((E = E.apply(l, p || [])).next());
    });
  };
  Object.defineProperty(Ve, "__esModule", { value: !0 }), Ve.HttpClient = Ve.HttpClientResponse = Ve.HttpClientError = Ve.MediaTypes = Ve.Headers = Ve.HttpCodes = void 0, Ve.getProxyUrl = h, Ve.isHttps = M;
  const A = t(Jn), n = t(Hn), c = t(ja()), g = t(On()), Q = ii();
  var B;
  (function(l) {
    l[l.OK = 200] = "OK", l[l.MultipleChoices = 300] = "MultipleChoices", l[l.MovedPermanently = 301] = "MovedPermanently", l[l.ResourceMoved = 302] = "ResourceMoved", l[l.SeeOther = 303] = "SeeOther", l[l.NotModified = 304] = "NotModified", l[l.UseProxy = 305] = "UseProxy", l[l.SwitchProxy = 306] = "SwitchProxy", l[l.TemporaryRedirect = 307] = "TemporaryRedirect", l[l.PermanentRedirect = 308] = "PermanentRedirect", l[l.BadRequest = 400] = "BadRequest", l[l.Unauthorized = 401] = "Unauthorized", l[l.PaymentRequired = 402] = "PaymentRequired", l[l.Forbidden = 403] = "Forbidden", l[l.NotFound = 404] = "NotFound", l[l.MethodNotAllowed = 405] = "MethodNotAllowed", l[l.NotAcceptable = 406] = "NotAcceptable", l[l.ProxyAuthenticationRequired = 407] = "ProxyAuthenticationRequired", l[l.RequestTimeout = 408] = "RequestTimeout", l[l.Conflict = 409] = "Conflict", l[l.Gone = 410] = "Gone", l[l.TooManyRequests = 429] = "TooManyRequests", l[l.InternalServerError = 500] = "InternalServerError", l[l.NotImplemented = 501] = "NotImplemented", l[l.BadGateway = 502] = "BadGateway", l[l.ServiceUnavailable = 503] = "ServiceUnavailable", l[l.GatewayTimeout = 504] = "GatewayTimeout";
  })(B || (Ve.HttpCodes = B = {}));
  var i;
  (function(l) {
    l.Accept = "accept", l.ContentType = "content-type";
  })(i || (Ve.Headers = i = {}));
  var a;
  (function(l) {
    l.ApplicationJson = "application/json";
  })(a || (Ve.MediaTypes = a = {}));
  function h(l) {
    const p = c.getProxyUrl(new URL(l));
    return p ? p.href : "";
  }
  const u = [
    B.MovedPermanently,
    B.ResourceMoved,
    B.SeeOther,
    B.TemporaryRedirect,
    B.PermanentRedirect
  ], C = [
    B.BadGateway,
    B.ServiceUnavailable,
    B.GatewayTimeout
  ], w = ["OPTIONS", "GET", "DELETE", "HEAD"], D = 10, b = 5;
  class U extends Error {
    constructor(p, s) {
      super(p), this.name = "HttpClientError", this.statusCode = s, Object.setPrototypeOf(this, U.prototype);
    }
  }
  Ve.HttpClientError = U;
  class G {
    constructor(p) {
      this.message = p;
    }
    readBody() {
      return o(this, void 0, void 0, function* () {
        return new Promise((p) => o(this, void 0, void 0, function* () {
          let s = Buffer.alloc(0);
          this.message.on("data", (E) => {
            s = Buffer.concat([s, E]);
          }), this.message.on("end", () => {
            p(s.toString());
          });
        }));
      });
    }
    readBodyBuffer() {
      return o(this, void 0, void 0, function* () {
        return new Promise((p) => o(this, void 0, void 0, function* () {
          const s = [];
          this.message.on("data", (E) => {
            s.push(E);
          }), this.message.on("end", () => {
            p(Buffer.concat(s));
          });
        }));
      });
    }
  }
  Ve.HttpClientResponse = G;
  function M(l) {
    return new URL(l).protocol === "https:";
  }
  class N {
    constructor(p, s, E) {
      this._ignoreSslError = !1, this._allowRedirects = !0, this._allowRedirectDowngrade = !1, this._maxRedirects = 50, this._allowRetries = !1, this._maxRetries = 1, this._keepAlive = !1, this._disposed = !1, this.userAgent = this._getUserAgentWithOrchestrationId(p), this.handlers = s || [], this.requestOptions = E, E && (E.ignoreSslError != null && (this._ignoreSslError = E.ignoreSslError), this._socketTimeout = E.socketTimeout, E.allowRedirects != null && (this._allowRedirects = E.allowRedirects), E.allowRedirectDowngrade != null && (this._allowRedirectDowngrade = E.allowRedirectDowngrade), E.maxRedirects != null && (this._maxRedirects = Math.max(E.maxRedirects, 0)), E.keepAlive != null && (this._keepAlive = E.keepAlive), E.allowRetries != null && (this._allowRetries = E.allowRetries), E.maxRetries != null && (this._maxRetries = E.maxRetries));
    }
    options(p, s) {
      return o(this, void 0, void 0, function* () {
        return this.request("OPTIONS", p, null, s || {});
      });
    }
    get(p, s) {
      return o(this, void 0, void 0, function* () {
        return this.request("GET", p, null, s || {});
      });
    }
    del(p, s) {
      return o(this, void 0, void 0, function* () {
        return this.request("DELETE", p, null, s || {});
      });
    }
    post(p, s, E) {
      return o(this, void 0, void 0, function* () {
        return this.request("POST", p, s, E || {});
      });
    }
    patch(p, s, E) {
      return o(this, void 0, void 0, function* () {
        return this.request("PATCH", p, s, E || {});
      });
    }
    put(p, s, E) {
      return o(this, void 0, void 0, function* () {
        return this.request("PUT", p, s, E || {});
      });
    }
    head(p, s) {
      return o(this, void 0, void 0, function* () {
        return this.request("HEAD", p, null, s || {});
      });
    }
    sendStream(p, s, E, f) {
      return o(this, void 0, void 0, function* () {
        return this.request(p, s, E, f);
      });
    }
    /**
     * Gets a typed object from an endpoint
     * Be aware that not found returns a null.  Other errors (4xx, 5xx) reject the promise
     */
    getJson(p) {
      return o(this, arguments, void 0, function* (s, E = {}) {
        E[i.Accept] = this._getExistingOrDefaultHeader(E, i.Accept, a.ApplicationJson);
        const f = yield this.get(s, E);
        return this._processResponse(f, this.requestOptions);
      });
    }
    postJson(p, s) {
      return o(this, arguments, void 0, function* (E, f, I = {}) {
        const m = JSON.stringify(f, null, 2);
        I[i.Accept] = this._getExistingOrDefaultHeader(I, i.Accept, a.ApplicationJson), I[i.ContentType] = this._getExistingOrDefaultContentTypeHeader(I, a.ApplicationJson);
        const y = yield this.post(E, m, I);
        return this._processResponse(y, this.requestOptions);
      });
    }
    putJson(p, s) {
      return o(this, arguments, void 0, function* (E, f, I = {}) {
        const m = JSON.stringify(f, null, 2);
        I[i.Accept] = this._getExistingOrDefaultHeader(I, i.Accept, a.ApplicationJson), I[i.ContentType] = this._getExistingOrDefaultContentTypeHeader(I, a.ApplicationJson);
        const y = yield this.put(E, m, I);
        return this._processResponse(y, this.requestOptions);
      });
    }
    patchJson(p, s) {
      return o(this, arguments, void 0, function* (E, f, I = {}) {
        const m = JSON.stringify(f, null, 2);
        I[i.Accept] = this._getExistingOrDefaultHeader(I, i.Accept, a.ApplicationJson), I[i.ContentType] = this._getExistingOrDefaultContentTypeHeader(I, a.ApplicationJson);
        const y = yield this.patch(E, m, I);
        return this._processResponse(y, this.requestOptions);
      });
    }
    /**
     * Makes a raw http request.
     * All other methods such as get, post, patch, and request ultimately call this.
     * Prefer get, del, post and patch
     */
    request(p, s, E, f) {
      return o(this, void 0, void 0, function* () {
        if (this._disposed)
          throw new Error("Client has already been disposed.");
        const I = new URL(s);
        let m = this._prepareRequest(p, I, f);
        const y = this._allowRetries && w.includes(p) ? this._maxRetries + 1 : 1;
        let S = 0, T;
        do {
          if (T = yield this.requestRaw(m, E), T && T.message && T.message.statusCode === B.Unauthorized) {
            let v;
            for (const $ of this.handlers)
              if ($.canHandleAuthentication(T)) {
                v = $;
                break;
              }
            return v ? v.handleAuthentication(this, m, E) : T;
          }
          let L = this._maxRedirects;
          for (; T.message.statusCode && u.includes(T.message.statusCode) && this._allowRedirects && L > 0; ) {
            const v = T.message.headers.location;
            if (!v)
              break;
            const $ = new URL(v);
            if (I.protocol === "https:" && I.protocol !== $.protocol && !this._allowRedirectDowngrade)
              throw new Error("Redirect from HTTPS to HTTP protocol. This downgrade is not allowed for security reasons. If you want to allow this behavior, set the allowRedirectDowngrade option to true.");
            if (yield T.readBody(), $.hostname !== I.hostname)
              for (const oe in f)
                oe.toLowerCase() === "authorization" && delete f[oe];
            m = this._prepareRequest(p, $, f), T = yield this.requestRaw(m, E), L--;
          }
          if (!T.message.statusCode || !C.includes(T.message.statusCode))
            return T;
          S += 1, S < y && (yield T.readBody(), yield this._performExponentialBackoff(S));
        } while (S < y);
        return T;
      });
    }
    /**
     * Needs to be called if keepAlive is set to true in request options.
     */
    dispose() {
      this._agent && this._agent.destroy(), this._disposed = !0;
    }
    /**
     * Raw request.
     * @param info
     * @param data
     */
    requestRaw(p, s) {
      return o(this, void 0, void 0, function* () {
        return new Promise((E, f) => {
          function I(m, y) {
            m ? f(m) : y ? E(y) : f(new Error("Unknown error"));
          }
          this.requestRawWithCallback(p, s, I);
        });
      });
    }
    /**
     * Raw request with callback.
     * @param info
     * @param data
     * @param onResult
     */
    requestRawWithCallback(p, s, E) {
      typeof s == "string" && (p.options.headers || (p.options.headers = {}), p.options.headers["Content-Length"] = Buffer.byteLength(s, "utf8"));
      let f = !1;
      function I(S, T) {
        f || (f = !0, E(S, T));
      }
      const m = p.httpModule.request(p.options, (S) => {
        const T = new G(S);
        I(void 0, T);
      });
      let y;
      m.on("socket", (S) => {
        y = S;
      }), m.setTimeout(this._socketTimeout || 3 * 6e4, () => {
        y && y.end(), I(new Error(`Request timeout: ${p.options.path}`));
      }), m.on("error", function(S) {
        I(S);
      }), s && typeof s == "string" && m.write(s, "utf8"), s && typeof s != "string" ? (s.on("close", function() {
        m.end();
      }), s.pipe(m)) : m.end();
    }
    /**
     * Gets an http agent. This function is useful when you need an http agent that handles
     * routing through a proxy server - depending upon the url and proxy environment variables.
     * @param serverUrl  The server URL where the request will be sent. For example, https://api.github.com
     */
    getAgent(p) {
      const s = new URL(p);
      return this._getAgent(s);
    }
    getAgentDispatcher(p) {
      const s = new URL(p), E = c.getProxyUrl(s);
      if (E && E.hostname)
        return this._getProxyAgentDispatcher(s, E);
    }
    _prepareRequest(p, s, E) {
      const f = {};
      f.parsedUrl = s;
      const I = f.parsedUrl.protocol === "https:";
      f.httpModule = I ? n : A;
      const m = I ? 443 : 80;
      if (f.options = {}, f.options.host = f.parsedUrl.hostname, f.options.port = f.parsedUrl.port ? parseInt(f.parsedUrl.port) : m, f.options.path = (f.parsedUrl.pathname || "") + (f.parsedUrl.search || ""), f.options.method = p, f.options.headers = this._mergeHeaders(E), this.userAgent != null && (f.options.headers["user-agent"] = this.userAgent), f.options.agent = this._getAgent(f.parsedUrl), this.handlers)
        for (const y of this.handlers)
          y.prepareRequest(f.options);
      return f;
    }
    _mergeHeaders(p) {
      return this.requestOptions && this.requestOptions.headers ? Object.assign({}, d(this.requestOptions.headers), d(p || {})) : d(p || {});
    }
    /**
     * Gets an existing header value or returns a default.
     * Handles converting number header values to strings since HTTP headers must be strings.
     * Note: This returns string | string[] since some headers can have multiple values.
     * For headers that must always be a single string (like Content-Type), use the
     * specialized _getExistingOrDefaultContentTypeHeader method instead.
     */
    _getExistingOrDefaultHeader(p, s, E) {
      let f;
      if (this.requestOptions && this.requestOptions.headers) {
        const m = d(this.requestOptions.headers)[s];
        m && (f = typeof m == "number" ? m.toString() : m);
      }
      const I = p[s];
      return I !== void 0 ? typeof I == "number" ? I.toString() : I : f !== void 0 ? f : E;
    }
    /**
     * Specialized version of _getExistingOrDefaultHeader for Content-Type header.
     * Always returns a single string (not an array) since Content-Type should be a single value.
     * Converts arrays to comma-separated strings and numbers to strings to ensure type safety.
     * This was split from _getExistingOrDefaultHeader to provide stricter typing for callers
     * that assign the result to places expecting a string (e.g., additionalHeaders[Headers.ContentType]).
     */
    _getExistingOrDefaultContentTypeHeader(p, s) {
      let E;
      if (this.requestOptions && this.requestOptions.headers) {
        const I = d(this.requestOptions.headers)[i.ContentType];
        I && (typeof I == "number" ? E = String(I) : Array.isArray(I) ? E = I.join(", ") : E = I);
      }
      const f = p[i.ContentType];
      return f !== void 0 ? typeof f == "number" ? String(f) : Array.isArray(f) ? f.join(", ") : f : E !== void 0 ? E : s;
    }
    _getAgent(p) {
      let s;
      const E = c.getProxyUrl(p), f = E && E.hostname;
      if (this._keepAlive && f && (s = this._proxyAgent), f || (s = this._agent), s)
        return s;
      const I = p.protocol === "https:";
      let m = 100;
      if (this.requestOptions && (m = this.requestOptions.maxSockets || A.globalAgent.maxSockets), E && E.hostname) {
        const y = {
          maxSockets: m,
          keepAlive: this._keepAlive,
          proxy: Object.assign(Object.assign({}, (E.username || E.password) && {
            proxyAuth: `${E.username}:${E.password}`
          }), { host: E.hostname, port: E.port })
        };
        let S;
        const T = E.protocol === "https:";
        I ? S = T ? g.httpsOverHttps : g.httpsOverHttp : S = T ? g.httpOverHttps : g.httpOverHttp, s = S(y), this._proxyAgent = s;
      }
      if (!s) {
        const y = { keepAlive: this._keepAlive, maxSockets: m };
        s = I ? new n.Agent(y) : new A.Agent(y), this._agent = s;
      }
      return I && this._ignoreSslError && (s.options = Object.assign(s.options || {}, {
        rejectUnauthorized: !1
      })), s;
    }
    _getProxyAgentDispatcher(p, s) {
      let E;
      if (this._keepAlive && (E = this._proxyAgentDispatcher), E)
        return E;
      const f = p.protocol === "https:";
      return E = new Q.ProxyAgent(Object.assign({ uri: s.href, pipelining: this._keepAlive ? 1 : 0 }, (s.username || s.password) && {
        token: `Basic ${Buffer.from(`${s.username}:${s.password}`).toString("base64")}`
      })), this._proxyAgentDispatcher = E, f && this._ignoreSslError && (E.options = Object.assign(E.options.requestTls || {}, {
        rejectUnauthorized: !1
      })), E;
    }
    _getUserAgentWithOrchestrationId(p) {
      const s = p || "actions/http-client", E = process.env.ACTIONS_ORCHESTRATION_ID;
      if (E) {
        const f = E.replace(/[^a-z0-9_.-]/gi, "_");
        return `${s} actions_orchestration_id/${f}`;
      }
      return s;
    }
    _performExponentialBackoff(p) {
      return o(this, void 0, void 0, function* () {
        p = Math.min(D, p);
        const s = b * Math.pow(2, p);
        return new Promise((E) => setTimeout(() => E(), s));
      });
    }
    _processResponse(p, s) {
      return o(this, void 0, void 0, function* () {
        return new Promise((E, f) => o(this, void 0, void 0, function* () {
          const I = p.message.statusCode || 0, m = {
            statusCode: I,
            result: null,
            headers: {}
          };
          I === B.NotFound && E(m);
          function y(L, v) {
            if (typeof v == "string") {
              const $ = new Date(v);
              if (!isNaN($.valueOf()))
                return $;
            }
            return v;
          }
          let S, T;
          try {
            T = yield p.readBody(), T && T.length > 0 && (s && s.deserializeDates ? S = JSON.parse(T, y) : S = JSON.parse(T), m.result = S), m.headers = p.message.headers;
          } catch {
          }
          if (I > 299) {
            let L;
            S && S.message ? L = S.message : T && T.length > 0 ? L = T : L = `Failed request: (${I})`;
            const v = new U(L, I);
            v.result = m.result, f(v);
          } else
            E(m);
        }));
      });
    }
  }
  Ve.HttpClient = N;
  const d = (l) => Object.keys(l).reduce((p, s) => (p[s.toLowerCase()] = l[s], p), {});
  return Ve;
}
var li = $a(), ec = function(e, r, t, o) {
  function A(n) {
    return n instanceof t ? n : new t(function(c) {
      c(n);
    });
  }
  return new (t || (t = Promise))(function(n, c) {
    function g(i) {
      try {
        B(o.next(i));
      } catch (a) {
        c(a);
      }
    }
    function Q(i) {
      try {
        B(o.throw(i));
      } catch (a) {
        c(a);
      }
    }
    function B(i) {
      i.done ? n(i.value) : A(i.value).then(g, Q);
    }
    B((o = o.apply(e, r || [])).next());
  });
};
function Ac(e, r) {
  if (!e && !r.auth)
    throw new Error("Parameter token or opts.auth is required");
  if (e && r.auth)
    throw new Error("Parameters token and opts.auth may not both be specified");
  return typeof r.auth == "string" ? r.auth : `token ${e}`;
}
function tc(e) {
  return new li.HttpClient().getAgent(e);
}
function rc(e) {
  return new li.HttpClient().getAgentDispatcher(e);
}
function sc(e) {
  const r = rc(e);
  return (o, A) => ec(this, void 0, void 0, function* () {
    return La.fetch(o, Object.assign(Object.assign({}, A), { dispatcher: r }));
  });
}
function oc() {
  return process.env.GITHUB_API_URL || "https://api.github.com";
}
function st() {
  return typeof navigator == "object" && "userAgent" in navigator ? navigator.userAgent : typeof process == "object" && process.version !== void 0 ? `Node.js/${process.version.substr(1)} (${process.platform}; ${process.arch})` : "<environment undetectable>";
}
function Ei(e, r, t, o) {
  if (typeof t != "function")
    throw new Error("method for before hook must be a function");
  return o || (o = {}), Array.isArray(r) ? r.reverse().reduce((A, n) => Ei.bind(null, e, n, A, o), t)() : Promise.resolve().then(() => e.registry[r] ? e.registry[r].reduce((A, n) => n.hook.bind(null, A, o), t)() : t(o));
}
function nc(e, r, t, o) {
  const A = o;
  e.registry[t] || (e.registry[t] = []), r === "before" && (o = (n, c) => Promise.resolve().then(A.bind(null, c)).then(n.bind(null, c))), r === "after" && (o = (n, c) => {
    let g;
    return Promise.resolve().then(n.bind(null, c)).then((Q) => (g = Q, A(g, c))).then(() => g);
  }), r === "error" && (o = (n, c) => Promise.resolve().then(n.bind(null, c)).catch((g) => A(g, c))), e.registry[t].push({
    hook: o,
    orig: A
  });
}
function ic(e, r, t) {
  if (!e.registry[r])
    return;
  const o = e.registry[r].map((A) => A.orig).indexOf(t);
  o !== -1 && e.registry[r].splice(o, 1);
}
const pn = Function.bind, wn = pn.bind(pn);
function ac(e, r, t) {
  const o = wn(ic, null).apply(
    null,
    [r]
  );
  e.api = { remove: o }, e.remove = o, ["before", "error", "after", "wrap"].forEach((A) => {
    const n = [r, A];
    e[A] = e.api[A] = wn(nc, null).apply(null, n);
  });
}
function cc() {
  const e = {
    registry: {}
  }, r = Ei.bind(null, e);
  return ac(r, e), r;
}
const gc = { Collection: cc };
var lc = "0.0.0-development", Ec = `octokit-endpoint.js/${lc} ${st()}`, uc = {
  method: "GET",
  baseUrl: "https://api.github.com",
  headers: {
    accept: "application/vnd.github.v3+json",
    "user-agent": Ec
  },
  mediaType: {
    format: ""
  }
};
function Qc(e) {
  return e ? Object.keys(e).reduce((r, t) => (r[t.toLowerCase()] = e[t], r), {}) : {};
}
function Bc(e) {
  if (typeof e != "object" || e === null || Object.prototype.toString.call(e) !== "[object Object]") return !1;
  const r = Object.getPrototypeOf(e);
  if (r === null) return !0;
  const t = Object.prototype.hasOwnProperty.call(r, "constructor") && r.constructor;
  return typeof t == "function" && t instanceof t && Function.prototype.call(t) === Function.prototype.call(e);
}
function ui(e, r) {
  const t = Object.assign({}, e);
  return Object.keys(r).forEach((o) => {
    Bc(r[o]) ? o in e ? t[o] = ui(e[o], r[o]) : Object.assign(t, { [o]: r[o] }) : Object.assign(t, { [o]: r[o] });
  }), t;
}
function mn(e) {
  for (const r in e)
    e[r] === void 0 && delete e[r];
  return e;
}
function $r(e, r, t) {
  if (typeof r == "string") {
    let [A, n] = r.split(" ");
    t = Object.assign(n ? { method: A, url: n } : { url: A }, t);
  } else
    t = Object.assign({}, r);
  t.headers = Qc(t.headers), mn(t), mn(t.headers);
  const o = ui(e || {}, t);
  return t.url === "/graphql" && (e && e.mediaType.previews?.length && (o.mediaType.previews = e.mediaType.previews.filter(
    (A) => !o.mediaType.previews.includes(A)
  ).concat(o.mediaType.previews)), o.mediaType.previews = (o.mediaType.previews || []).map((A) => A.replace(/-preview/, ""))), o;
}
function hc(e, r) {
  const t = /\?/.test(e) ? "&" : "?", o = Object.keys(r);
  return o.length === 0 ? e : e + t + o.map((A) => A === "q" ? "q=" + r.q.split("+").map(encodeURIComponent).join("+") : `${A}=${encodeURIComponent(r[A])}`).join("&");
}
var Ic = /\{[^{}}]+\}/g;
function Cc(e) {
  return e.replace(new RegExp("(?:^\\W+)|(?:(?<!\\W)\\W+$)", "g"), "").split(/,/);
}
function dc(e) {
  const r = e.match(Ic);
  return r ? r.map(Cc).reduce((t, o) => t.concat(o), []) : [];
}
function yn(e, r) {
  const t = { __proto__: null };
  for (const o of Object.keys(e))
    r.indexOf(o) === -1 && (t[o] = e[o]);
  return t;
}
function Qi(e) {
  return e.split(/(%[0-9A-Fa-f]{2})/g).map(function(r) {
    return /%[0-9A-Fa-f]/.test(r) || (r = encodeURI(r).replace(/%5B/g, "[").replace(/%5D/g, "]")), r;
  }).join("");
}
function pA(e) {
  return encodeURIComponent(e).replace(/[!'()*]/g, function(r) {
    return "%" + r.charCodeAt(0).toString(16).toUpperCase();
  });
}
function RA(e, r, t) {
  return r = e === "+" || e === "#" ? Qi(r) : pA(r), t ? pA(t) + "=" + r : r;
}
function dA(e) {
  return e != null;
}
function qr(e) {
  return e === ";" || e === "&" || e === "?";
}
function fc(e, r, t, o) {
  var A = e[t], n = [];
  if (dA(A) && A !== "")
    if (typeof A == "string" || typeof A == "number" || typeof A == "boolean")
      A = A.toString(), o && o !== "*" && (A = A.substring(0, parseInt(o, 10))), n.push(
        RA(r, A, qr(r) ? t : "")
      );
    else if (o === "*")
      Array.isArray(A) ? A.filter(dA).forEach(function(c) {
        n.push(
          RA(r, c, qr(r) ? t : "")
        );
      }) : Object.keys(A).forEach(function(c) {
        dA(A[c]) && n.push(RA(r, A[c], c));
      });
    else {
      const c = [];
      Array.isArray(A) ? A.filter(dA).forEach(function(g) {
        c.push(RA(r, g));
      }) : Object.keys(A).forEach(function(g) {
        dA(A[g]) && (c.push(pA(g)), c.push(RA(r, A[g].toString())));
      }), qr(r) ? n.push(pA(t) + "=" + c.join(",")) : c.length !== 0 && n.push(c.join(","));
    }
  else
    r === ";" ? dA(A) && n.push(pA(t)) : A === "" && (r === "&" || r === "?") ? n.push(pA(t) + "=") : A === "" && n.push("");
  return n;
}
function pc(e) {
  return {
    expand: wc.bind(null, e)
  };
}
function wc(e, r) {
  var t = ["+", "#", ".", "/", ";", "?", "&"];
  return e = e.replace(
    /\{([^\{\}]+)\}|([^\{\}]+)/g,
    function(o, A, n) {
      if (A) {
        let g = "";
        const Q = [];
        if (t.indexOf(A.charAt(0)) !== -1 && (g = A.charAt(0), A = A.substr(1)), A.split(/,/g).forEach(function(B) {
          var i = /([^:\*]*)(?::(\d+)|(\*))?/.exec(B);
          Q.push(fc(r, g, i[1], i[2] || i[3]));
        }), g && g !== "+") {
          var c = ",";
          return g === "?" ? c = "&" : g !== "#" && (c = g), (Q.length !== 0 ? g : "") + Q.join(c);
        } else
          return Q.join(",");
      } else
        return Qi(n);
    }
  ), e === "/" ? e : e.replace(/\/$/, "");
}
function Bi(e) {
  let r = e.method.toUpperCase(), t = (e.url || "/").replace(/:([a-z]\w+)/g, "{$1}"), o = Object.assign({}, e.headers), A, n = yn(e, [
    "method",
    "baseUrl",
    "url",
    "headers",
    "request",
    "mediaType"
  ]);
  const c = dc(t);
  t = pc(t).expand(n), /^http/.test(t) || (t = e.baseUrl + t);
  const g = Object.keys(e).filter((i) => c.includes(i)).concat("baseUrl"), Q = yn(n, g);
  if (!/application\/octet-stream/i.test(o.accept) && (e.mediaType.format && (o.accept = o.accept.split(/,/).map(
    (i) => i.replace(
      /application\/vnd(\.\w+)(\.v3)?(\.\w+)?(\+json)?$/,
      `application/vnd$1$2.${e.mediaType.format}`
    )
  ).join(",")), t.endsWith("/graphql") && e.mediaType.previews?.length)) {
    const i = o.accept.match(new RegExp("(?<![\\w-])[\\w-]+(?=-preview)", "g")) || [];
    o.accept = i.concat(e.mediaType.previews).map((a) => {
      const h = e.mediaType.format ? `.${e.mediaType.format}` : "+json";
      return `application/vnd.github.${a}-preview${h}`;
    }).join(",");
  }
  return ["GET", "HEAD"].includes(r) ? t = hc(t, Q) : "data" in Q ? A = Q.data : Object.keys(Q).length && (A = Q), !o["content-type"] && typeof A < "u" && (o["content-type"] = "application/json; charset=utf-8"), ["PATCH", "PUT"].includes(r) && typeof A > "u" && (A = ""), Object.assign(
    { method: r, url: t, headers: o },
    typeof A < "u" ? { body: A } : null,
    e.request ? { request: e.request } : null
  );
}
function mc(e, r, t) {
  return Bi($r(e, r, t));
}
function hi(e, r) {
  const t = $r(e, r), o = mc.bind(null, t);
  return Object.assign(o, {
    DEFAULTS: t,
    defaults: hi.bind(null, t),
    merge: $r.bind(null, t),
    parse: Bi
  });
}
var yc = hi(null, uc), fA = {}, Dn;
function Dc() {
  if (Dn) return fA;
  Dn = 1;
  const e = function() {
  };
  e.prototype = /* @__PURE__ */ Object.create(null);
  const r = /; *([!#$%&'*+.^\w`|~-]+)=("(?:[\v\u0020\u0021\u0023-\u005b\u005d-\u007e\u0080-\u00ff]|\\[\v\u0020-\u00ff])*"|[!#$%&'*+.^\w`|~-]+) */gu, t = /\\([\v\u0020-\u00ff])/gu, o = /^[!#$%&'*+.^\w|~-]+\/[!#$%&'*+.^\w|~-]+$/u, A = { type: "", parameters: new e() };
  Object.freeze(A.parameters), Object.freeze(A);
  function n(g) {
    if (typeof g != "string")
      throw new TypeError("argument header is required and must be a string");
    let Q = g.indexOf(";");
    const B = Q !== -1 ? g.slice(0, Q).trim() : g.trim();
    if (o.test(B) === !1)
      throw new TypeError("invalid media type");
    const i = {
      type: B.toLowerCase(),
      parameters: new e()
    };
    if (Q === -1)
      return i;
    let a, h, u;
    for (r.lastIndex = Q; h = r.exec(g); ) {
      if (h.index !== Q)
        throw new TypeError("invalid parameter format");
      Q += h[0].length, a = h[1].toLowerCase(), u = h[2], u[0] === '"' && (u = u.slice(1, u.length - 1), t.test(u) && (u = u.replace(t, "$1"))), i.parameters[a] = u;
    }
    if (Q !== g.length)
      throw new TypeError("invalid parameter format");
    return i;
  }
  function c(g) {
    if (typeof g != "string")
      return A;
    let Q = g.indexOf(";");
    const B = Q !== -1 ? g.slice(0, Q).trim() : g.trim();
    if (o.test(B) === !1)
      return A;
    const i = {
      type: B.toLowerCase(),
      parameters: new e()
    };
    if (Q === -1)
      return i;
    let a, h, u;
    for (r.lastIndex = Q; h = r.exec(g); ) {
      if (h.index !== Q)
        return A;
      Q += h[0].length, a = h[1].toLowerCase(), u = h[2], u[0] === '"' && (u = u.slice(1, u.length - 1), t.test(u) && (u = u.replace(t, "$1"))), i.parameters[a] = u;
    }
    return Q !== g.length ? A : i;
  }
  return fA.default = { parse: n, safeParse: c }, fA.parse = n, fA.safeParse = c, fA.defaultContentType = A, fA;
}
var Rc = Dc();
class OA extends Error {
  name;
  /**
   * http status code
   */
  status;
  /**
   * Request options that lead to the error.
   */
  request;
  /**
   * Response object if a response was received
   */
  response;
  constructor(r, t, o) {
    super(r, { cause: o.cause }), this.name = "HttpError", this.status = Number.parseInt(t), Number.isNaN(this.status) && (this.status = 0);
    "response" in o && (this.response = o.response);
    const A = Object.assign({}, o.request);
    o.request.headers.authorization && (A.headers = Object.assign({}, o.request.headers, {
      authorization: o.request.headers.authorization.replace(
        new RegExp("(?<! ) .*$"),
        " [REDACTED]"
      )
    })), A.url = A.url.replace(/\bclient_secret=\w+/g, "client_secret=[REDACTED]").replace(/\baccess_token=\w+/g, "access_token=[REDACTED]"), this.request = A;
  }
}
var kc = "10.0.7", bc = {
  headers: {
    "user-agent": `octokit-request.js/${kc} ${st()}`
  }
};
function Fc(e) {
  if (typeof e != "object" || e === null || Object.prototype.toString.call(e) !== "[object Object]") return !1;
  const r = Object.getPrototypeOf(e);
  if (r === null) return !0;
  const t = Object.prototype.hasOwnProperty.call(r, "constructor") && r.constructor;
  return typeof t == "function" && t instanceof t && Function.prototype.call(t) === Function.prototype.call(e);
}
var Rn = () => "";
async function kn(e) {
  const r = e.request?.fetch || globalThis.fetch;
  if (!r)
    throw new Error(
      "fetch is not set. Please pass a fetch implementation as new Octokit({ request: { fetch }}). Learn more at https://github.com/octokit/octokit.js/#fetch-missing"
    );
  const t = e.request?.log || console, o = e.request?.parseSuccessResponseBody !== !1, A = Fc(e.body) || Array.isArray(e.body) ? JSON.stringify(e.body) : e.body, n = Object.fromEntries(
    Object.entries(e.headers).map(([a, h]) => [
      a,
      String(h)
    ])
  );
  let c;
  try {
    c = await r(e.url, {
      method: e.method,
      body: A,
      redirect: e.request?.redirect,
      headers: n,
      signal: e.request?.signal,
      // duplex must be set if request.body is ReadableStream or Async Iterables.
      // See https://fetch.spec.whatwg.org/#dom-requestinit-duplex.
      ...e.body && { duplex: "half" }
    });
  } catch (a) {
    let h = "Unknown Error";
    if (a instanceof Error) {
      if (a.name === "AbortError")
        throw a.status = 500, a;
      h = a.message, a.name === "TypeError" && "cause" in a && (a.cause instanceof Error ? h = a.cause.message : typeof a.cause == "string" && (h = a.cause));
    }
    const u = new OA(h, 500, {
      request: e
    });
    throw u.cause = a, u;
  }
  const g = c.status, Q = c.url, B = {};
  for (const [a, h] of c.headers)
    B[a] = h;
  const i = {
    url: Q,
    status: g,
    headers: B,
    data: ""
  };
  if ("deprecation" in B) {
    const a = B.link && B.link.match(/<([^<>]+)>; rel="deprecation"/), h = a && a.pop();
    t.warn(
      `[@octokit/request] "${e.method} ${e.url}" is deprecated. It is scheduled to be removed on ${B.sunset}${h ? `. See ${h}` : ""}`
    );
  }
  if (g === 204 || g === 205)
    return i;
  if (e.method === "HEAD") {
    if (g < 400)
      return i;
    throw new OA(c.statusText, g, {
      response: i,
      request: e
    });
  }
  if (g === 304)
    throw i.data = await zr(c), new OA("Not modified", g, {
      response: i,
      request: e
    });
  if (g >= 400)
    throw i.data = await zr(c), new OA(Sc(i.data), g, {
      response: i,
      request: e
    });
  return i.data = o ? await zr(c) : c.body, i;
}
async function zr(e) {
  const r = e.headers.get("content-type");
  if (!r)
    return e.text().catch(Rn);
  const t = Rc.safeParse(r);
  if (Tc(t)) {
    let o = "";
    try {
      return o = await e.text(), JSON.parse(o);
    } catch {
      return o;
    }
  } else return t.type.startsWith("text/") || t.parameters.charset?.toLowerCase() === "utf-8" ? e.text().catch(Rn) : e.arrayBuffer().catch(
    /* v8 ignore next -- @preserve */
    () => new ArrayBuffer(0)
  );
}
function Tc(e) {
  return e.type === "application/json" || e.type === "application/scim+json";
}
function Sc(e) {
  if (typeof e == "string")
    return e;
  if (e instanceof ArrayBuffer)
    return "Unknown error";
  if ("message" in e) {
    const r = "documentation_url" in e ? ` - ${e.documentation_url}` : "";
    return Array.isArray(e.errors) ? `${e.message}: ${e.errors.map((t) => JSON.stringify(t)).join(", ")}${r}` : `${e.message}${r}`;
  }
  return `Unknown error: ${JSON.stringify(e)}`;
}
function es(e, r) {
  const t = e.defaults(r);
  return Object.assign(function(A, n) {
    const c = t.merge(A, n);
    if (!c.request || !c.request.hook)
      return kn(t.parse(c));
    const g = (Q, B) => kn(
      t.parse(t.merge(Q, B))
    );
    return Object.assign(g, {
      endpoint: t,
      defaults: es.bind(null, t)
    }), c.request.hook(g, c);
  }, {
    endpoint: t,
    defaults: es.bind(null, t)
  });
}
var As = es(yc, bc);
var Uc = "0.0.0-development";
function Nc(e) {
  return `Request failed due to following response errors:
` + e.errors.map((r) => ` - ${r.message}`).join(`
`);
}
var Mc = class extends Error {
  constructor(e, r, t) {
    super(Nc(t)), this.request = e, this.headers = r, this.response = t, this.errors = t.errors, this.data = t.data, Error.captureStackTrace && Error.captureStackTrace(this, this.constructor);
  }
  name = "GraphqlResponseError";
  errors;
  data;
}, Lc = [
  "method",
  "baseUrl",
  "url",
  "headers",
  "request",
  "query",
  "mediaType",
  "operationName"
], Gc = ["query", "method", "url"], bn = /\/api\/v3\/?$/;
function vc(e, r, t) {
  if (t) {
    if (typeof r == "string" && "query" in t)
      return Promise.reject(
        new Error('[@octokit/graphql] "query" cannot be used as variable name')
      );
    for (const c in t)
      if (Gc.includes(c))
        return Promise.reject(
          new Error(
            `[@octokit/graphql] "${c}" cannot be used as variable name`
          )
        );
  }
  const o = typeof r == "string" ? Object.assign({ query: r }, t) : r, A = Object.keys(
    o
  ).reduce((c, g) => Lc.includes(g) ? (c[g] = o[g], c) : (c.variables || (c.variables = {}), c.variables[g] = o[g], c), {}), n = o.baseUrl || e.endpoint.DEFAULTS.baseUrl;
  return bn.test(n) && (A.url = n.replace(bn, "/api/graphql")), e(A).then((c) => {
    if (c.data.errors) {
      const g = {};
      for (const Q of Object.keys(c.headers))
        g[Q] = c.headers[Q];
      throw new Mc(
        A,
        g,
        c.data
      );
    }
    return c.data.data;
  });
}
function ls(e, r) {
  const t = e.defaults(r);
  return Object.assign((A, n) => vc(t, A, n), {
    defaults: ls.bind(null, t),
    endpoint: t.endpoint
  });
}
ls(As, {
  headers: {
    "user-agent": `octokit-graphql.js/${Uc} ${st()}`
  },
  method: "POST",
  url: "/graphql"
});
function Yc(e) {
  return ls(e, {
    method: "POST",
    url: "/graphql"
  });
}
var Zr = "(?:[a-zA-Z0-9_-]+)", Fn = "\\.", Tn = new RegExp(`^${Zr}${Fn}${Zr}${Fn}${Zr}$`), Jc = Tn.test.bind(Tn);
async function Hc(e) {
  const r = Jc(e), t = e.startsWith("v1.") || e.startsWith("ghs_"), o = e.startsWith("ghu_");
  return {
    type: "token",
    token: e,
    tokenType: r ? "app" : t ? "installation" : o ? "user-to-server" : "oauth"
  };
}
function Vc(e) {
  return e.split(/\./).length === 3 ? `bearer ${e}` : `token ${e}`;
}
async function Pc(e, r, t, o) {
  const A = r.endpoint.merge(
    t,
    o
  );
  return A.headers.authorization = Vc(e), r(A);
}
var xc = function(r) {
  if (!r)
    throw new Error("[@octokit/auth-token] No token passed to createTokenAuth");
  if (typeof r != "string")
    throw new Error(
      "[@octokit/auth-token] Token passed to createTokenAuth is not a string"
    );
  return r = r.replace(/^(token|bearer) +/i, ""), Object.assign(Hc.bind(null, r), {
    hook: Pc.bind(null, r)
  });
};
const Ii = "7.0.6", Sn = () => {
}, Oc = console.warn.bind(console), _c = console.error.bind(console);
function Wc(e = {}) {
  return typeof e.debug != "function" && (e.debug = Sn), typeof e.info != "function" && (e.info = Sn), typeof e.warn != "function" && (e.warn = Oc), typeof e.error != "function" && (e.error = _c), e;
}
const Un = `octokit-core.js/${Ii} ${st()}`;
class qc {
  static VERSION = Ii;
  static defaults(r) {
    return class extends this {
      constructor(...o) {
        const A = o[0] || {};
        if (typeof r == "function") {
          super(r(A));
          return;
        }
        super(
          Object.assign(
            {},
            r,
            A,
            A.userAgent && r.userAgent ? {
              userAgent: `${A.userAgent} ${r.userAgent}`
            } : null
          )
        );
      }
    };
  }
  static plugins = [];
  /**
   * Attach a plugin (or many) to your Octokit instance.
   *
   * @example
   * const API = Octokit.plugin(plugin1, plugin2, plugin3, ...)
   */
  static plugin(...r) {
    const t = this.plugins;
    return class extends this {
      static plugins = t.concat(
        r.filter((A) => !t.includes(A))
      );
    };
  }
  constructor(r = {}) {
    const t = new gc.Collection(), o = {
      baseUrl: As.endpoint.DEFAULTS.baseUrl,
      headers: {},
      request: Object.assign({}, r.request, {
        // @ts-ignore internal usage only, no need to type
        hook: t.bind(null, "request")
      }),
      mediaType: {
        previews: [],
        format: ""
      }
    };
    if (o.headers["user-agent"] = r.userAgent ? `${r.userAgent} ${Un}` : Un, r.baseUrl && (o.baseUrl = r.baseUrl), r.previews && (o.mediaType.previews = r.previews), r.timeZone && (o.headers["time-zone"] = r.timeZone), this.request = As.defaults(o), this.graphql = Yc(this.request).defaults(o), this.log = Wc(r.log), this.hook = t, r.authStrategy) {
      const { authStrategy: n, ...c } = r, g = n(
        Object.assign(
          {
            request: this.request,
            log: this.log,
            // we pass the current octokit instance as well as its constructor options
            // to allow for authentication strategies that return a new octokit instance
            // that shares the same internal state as the current one. The original
            // requirement for this was the "event-octokit" authentication strategy
            // of https://github.com/probot/octokit-auth-probot.
            octokit: this,
            octokitOptions: c
          },
          r.auth
        )
      );
      t.wrap("request", g.hook), this.auth = g;
    } else if (!r.auth)
      this.auth = async () => ({
        type: "unauthenticated"
      });
    else {
      const n = xc(r.auth);
      t.wrap("request", n.hook), this.auth = n;
    }
    const A = this.constructor;
    for (let n = 0; n < A.plugins.length; ++n)
      Object.assign(this, A.plugins[n](this, r));
  }
  // assigned during constructor
  request;
  graphql;
  log;
  hook;
  // TODO: type `octokit.auth` based on passed options.authStrategy
  auth;
}
const zc = "17.0.0", Zc = {
  actions: {
    addCustomLabelsToSelfHostedRunnerForOrg: [
      "POST /orgs/{org}/actions/runners/{runner_id}/labels"
    ],
    addCustomLabelsToSelfHostedRunnerForRepo: [
      "POST /repos/{owner}/{repo}/actions/runners/{runner_id}/labels"
    ],
    addRepoAccessToSelfHostedRunnerGroupInOrg: [
      "PUT /orgs/{org}/actions/runner-groups/{runner_group_id}/repositories/{repository_id}"
    ],
    addSelectedRepoToOrgSecret: [
      "PUT /orgs/{org}/actions/secrets/{secret_name}/repositories/{repository_id}"
    ],
    addSelectedRepoToOrgVariable: [
      "PUT /orgs/{org}/actions/variables/{name}/repositories/{repository_id}"
    ],
    approveWorkflowRun: [
      "POST /repos/{owner}/{repo}/actions/runs/{run_id}/approve"
    ],
    cancelWorkflowRun: [
      "POST /repos/{owner}/{repo}/actions/runs/{run_id}/cancel"
    ],
    createEnvironmentVariable: [
      "POST /repos/{owner}/{repo}/environments/{environment_name}/variables"
    ],
    createHostedRunnerForOrg: ["POST /orgs/{org}/actions/hosted-runners"],
    createOrUpdateEnvironmentSecret: [
      "PUT /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}"
    ],
    createOrUpdateOrgSecret: ["PUT /orgs/{org}/actions/secrets/{secret_name}"],
    createOrUpdateRepoSecret: [
      "PUT /repos/{owner}/{repo}/actions/secrets/{secret_name}"
    ],
    createOrgVariable: ["POST /orgs/{org}/actions/variables"],
    createRegistrationTokenForOrg: [
      "POST /orgs/{org}/actions/runners/registration-token"
    ],
    createRegistrationTokenForRepo: [
      "POST /repos/{owner}/{repo}/actions/runners/registration-token"
    ],
    createRemoveTokenForOrg: ["POST /orgs/{org}/actions/runners/remove-token"],
    createRemoveTokenForRepo: [
      "POST /repos/{owner}/{repo}/actions/runners/remove-token"
    ],
    createRepoVariable: ["POST /repos/{owner}/{repo}/actions/variables"],
    createWorkflowDispatch: [
      "POST /repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches"
    ],
    deleteActionsCacheById: [
      "DELETE /repos/{owner}/{repo}/actions/caches/{cache_id}"
    ],
    deleteActionsCacheByKey: [
      "DELETE /repos/{owner}/{repo}/actions/caches{?key,ref}"
    ],
    deleteArtifact: [
      "DELETE /repos/{owner}/{repo}/actions/artifacts/{artifact_id}"
    ],
    deleteCustomImageFromOrg: [
      "DELETE /orgs/{org}/actions/hosted-runners/images/custom/{image_definition_id}"
    ],
    deleteCustomImageVersionFromOrg: [
      "DELETE /orgs/{org}/actions/hosted-runners/images/custom/{image_definition_id}/versions/{version}"
    ],
    deleteEnvironmentSecret: [
      "DELETE /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}"
    ],
    deleteEnvironmentVariable: [
      "DELETE /repos/{owner}/{repo}/environments/{environment_name}/variables/{name}"
    ],
    deleteHostedRunnerForOrg: [
      "DELETE /orgs/{org}/actions/hosted-runners/{hosted_runner_id}"
    ],
    deleteOrgSecret: ["DELETE /orgs/{org}/actions/secrets/{secret_name}"],
    deleteOrgVariable: ["DELETE /orgs/{org}/actions/variables/{name}"],
    deleteRepoSecret: [
      "DELETE /repos/{owner}/{repo}/actions/secrets/{secret_name}"
    ],
    deleteRepoVariable: [
      "DELETE /repos/{owner}/{repo}/actions/variables/{name}"
    ],
    deleteSelfHostedRunnerFromOrg: [
      "DELETE /orgs/{org}/actions/runners/{runner_id}"
    ],
    deleteSelfHostedRunnerFromRepo: [
      "DELETE /repos/{owner}/{repo}/actions/runners/{runner_id}"
    ],
    deleteWorkflowRun: ["DELETE /repos/{owner}/{repo}/actions/runs/{run_id}"],
    deleteWorkflowRunLogs: [
      "DELETE /repos/{owner}/{repo}/actions/runs/{run_id}/logs"
    ],
    disableSelectedRepositoryGithubActionsOrganization: [
      "DELETE /orgs/{org}/actions/permissions/repositories/{repository_id}"
    ],
    disableWorkflow: [
      "PUT /repos/{owner}/{repo}/actions/workflows/{workflow_id}/disable"
    ],
    downloadArtifact: [
      "GET /repos/{owner}/{repo}/actions/artifacts/{artifact_id}/{archive_format}"
    ],
    downloadJobLogsForWorkflowRun: [
      "GET /repos/{owner}/{repo}/actions/jobs/{job_id}/logs"
    ],
    downloadWorkflowRunAttemptLogs: [
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}/logs"
    ],
    downloadWorkflowRunLogs: [
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/logs"
    ],
    enableSelectedRepositoryGithubActionsOrganization: [
      "PUT /orgs/{org}/actions/permissions/repositories/{repository_id}"
    ],
    enableWorkflow: [
      "PUT /repos/{owner}/{repo}/actions/workflows/{workflow_id}/enable"
    ],
    forceCancelWorkflowRun: [
      "POST /repos/{owner}/{repo}/actions/runs/{run_id}/force-cancel"
    ],
    generateRunnerJitconfigForOrg: [
      "POST /orgs/{org}/actions/runners/generate-jitconfig"
    ],
    generateRunnerJitconfigForRepo: [
      "POST /repos/{owner}/{repo}/actions/runners/generate-jitconfig"
    ],
    getActionsCacheList: ["GET /repos/{owner}/{repo}/actions/caches"],
    getActionsCacheUsage: ["GET /repos/{owner}/{repo}/actions/cache/usage"],
    getActionsCacheUsageByRepoForOrg: [
      "GET /orgs/{org}/actions/cache/usage-by-repository"
    ],
    getActionsCacheUsageForOrg: ["GET /orgs/{org}/actions/cache/usage"],
    getAllowedActionsOrganization: [
      "GET /orgs/{org}/actions/permissions/selected-actions"
    ],
    getAllowedActionsRepository: [
      "GET /repos/{owner}/{repo}/actions/permissions/selected-actions"
    ],
    getArtifact: ["GET /repos/{owner}/{repo}/actions/artifacts/{artifact_id}"],
    getCustomImageForOrg: [
      "GET /orgs/{org}/actions/hosted-runners/images/custom/{image_definition_id}"
    ],
    getCustomImageVersionForOrg: [
      "GET /orgs/{org}/actions/hosted-runners/images/custom/{image_definition_id}/versions/{version}"
    ],
    getCustomOidcSubClaimForRepo: [
      "GET /repos/{owner}/{repo}/actions/oidc/customization/sub"
    ],
    getEnvironmentPublicKey: [
      "GET /repos/{owner}/{repo}/environments/{environment_name}/secrets/public-key"
    ],
    getEnvironmentSecret: [
      "GET /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}"
    ],
    getEnvironmentVariable: [
      "GET /repos/{owner}/{repo}/environments/{environment_name}/variables/{name}"
    ],
    getGithubActionsDefaultWorkflowPermissionsOrganization: [
      "GET /orgs/{org}/actions/permissions/workflow"
    ],
    getGithubActionsDefaultWorkflowPermissionsRepository: [
      "GET /repos/{owner}/{repo}/actions/permissions/workflow"
    ],
    getGithubActionsPermissionsOrganization: [
      "GET /orgs/{org}/actions/permissions"
    ],
    getGithubActionsPermissionsRepository: [
      "GET /repos/{owner}/{repo}/actions/permissions"
    ],
    getHostedRunnerForOrg: [
      "GET /orgs/{org}/actions/hosted-runners/{hosted_runner_id}"
    ],
    getHostedRunnersGithubOwnedImagesForOrg: [
      "GET /orgs/{org}/actions/hosted-runners/images/github-owned"
    ],
    getHostedRunnersLimitsForOrg: [
      "GET /orgs/{org}/actions/hosted-runners/limits"
    ],
    getHostedRunnersMachineSpecsForOrg: [
      "GET /orgs/{org}/actions/hosted-runners/machine-sizes"
    ],
    getHostedRunnersPartnerImagesForOrg: [
      "GET /orgs/{org}/actions/hosted-runners/images/partner"
    ],
    getHostedRunnersPlatformsForOrg: [
      "GET /orgs/{org}/actions/hosted-runners/platforms"
    ],
    getJobForWorkflowRun: ["GET /repos/{owner}/{repo}/actions/jobs/{job_id}"],
    getOrgPublicKey: ["GET /orgs/{org}/actions/secrets/public-key"],
    getOrgSecret: ["GET /orgs/{org}/actions/secrets/{secret_name}"],
    getOrgVariable: ["GET /orgs/{org}/actions/variables/{name}"],
    getPendingDeploymentsForRun: [
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/pending_deployments"
    ],
    getRepoPermissions: [
      "GET /repos/{owner}/{repo}/actions/permissions",
      {},
      { renamed: ["actions", "getGithubActionsPermissionsRepository"] }
    ],
    getRepoPublicKey: ["GET /repos/{owner}/{repo}/actions/secrets/public-key"],
    getRepoSecret: ["GET /repos/{owner}/{repo}/actions/secrets/{secret_name}"],
    getRepoVariable: ["GET /repos/{owner}/{repo}/actions/variables/{name}"],
    getReviewsForRun: [
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/approvals"
    ],
    getSelfHostedRunnerForOrg: ["GET /orgs/{org}/actions/runners/{runner_id}"],
    getSelfHostedRunnerForRepo: [
      "GET /repos/{owner}/{repo}/actions/runners/{runner_id}"
    ],
    getWorkflow: ["GET /repos/{owner}/{repo}/actions/workflows/{workflow_id}"],
    getWorkflowAccessToRepository: [
      "GET /repos/{owner}/{repo}/actions/permissions/access"
    ],
    getWorkflowRun: ["GET /repos/{owner}/{repo}/actions/runs/{run_id}"],
    getWorkflowRunAttempt: [
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}"
    ],
    getWorkflowRunUsage: [
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/timing"
    ],
    getWorkflowUsage: [
      "GET /repos/{owner}/{repo}/actions/workflows/{workflow_id}/timing"
    ],
    listArtifactsForRepo: ["GET /repos/{owner}/{repo}/actions/artifacts"],
    listCustomImageVersionsForOrg: [
      "GET /orgs/{org}/actions/hosted-runners/images/custom/{image_definition_id}/versions"
    ],
    listCustomImagesForOrg: [
      "GET /orgs/{org}/actions/hosted-runners/images/custom"
    ],
    listEnvironmentSecrets: [
      "GET /repos/{owner}/{repo}/environments/{environment_name}/secrets"
    ],
    listEnvironmentVariables: [
      "GET /repos/{owner}/{repo}/environments/{environment_name}/variables"
    ],
    listGithubHostedRunnersInGroupForOrg: [
      "GET /orgs/{org}/actions/runner-groups/{runner_group_id}/hosted-runners"
    ],
    listHostedRunnersForOrg: ["GET /orgs/{org}/actions/hosted-runners"],
    listJobsForWorkflowRun: [
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs"
    ],
    listJobsForWorkflowRunAttempt: [
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}/jobs"
    ],
    listLabelsForSelfHostedRunnerForOrg: [
      "GET /orgs/{org}/actions/runners/{runner_id}/labels"
    ],
    listLabelsForSelfHostedRunnerForRepo: [
      "GET /repos/{owner}/{repo}/actions/runners/{runner_id}/labels"
    ],
    listOrgSecrets: ["GET /orgs/{org}/actions/secrets"],
    listOrgVariables: ["GET /orgs/{org}/actions/variables"],
    listRepoOrganizationSecrets: [
      "GET /repos/{owner}/{repo}/actions/organization-secrets"
    ],
    listRepoOrganizationVariables: [
      "GET /repos/{owner}/{repo}/actions/organization-variables"
    ],
    listRepoSecrets: ["GET /repos/{owner}/{repo}/actions/secrets"],
    listRepoVariables: ["GET /repos/{owner}/{repo}/actions/variables"],
    listRepoWorkflows: ["GET /repos/{owner}/{repo}/actions/workflows"],
    listRunnerApplicationsForOrg: ["GET /orgs/{org}/actions/runners/downloads"],
    listRunnerApplicationsForRepo: [
      "GET /repos/{owner}/{repo}/actions/runners/downloads"
    ],
    listSelectedReposForOrgSecret: [
      "GET /orgs/{org}/actions/secrets/{secret_name}/repositories"
    ],
    listSelectedReposForOrgVariable: [
      "GET /orgs/{org}/actions/variables/{name}/repositories"
    ],
    listSelectedRepositoriesEnabledGithubActionsOrganization: [
      "GET /orgs/{org}/actions/permissions/repositories"
    ],
    listSelfHostedRunnersForOrg: ["GET /orgs/{org}/actions/runners"],
    listSelfHostedRunnersForRepo: ["GET /repos/{owner}/{repo}/actions/runners"],
    listWorkflowRunArtifacts: [
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/artifacts"
    ],
    listWorkflowRuns: [
      "GET /repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs"
    ],
    listWorkflowRunsForRepo: ["GET /repos/{owner}/{repo}/actions/runs"],
    reRunJobForWorkflowRun: [
      "POST /repos/{owner}/{repo}/actions/jobs/{job_id}/rerun"
    ],
    reRunWorkflow: ["POST /repos/{owner}/{repo}/actions/runs/{run_id}/rerun"],
    reRunWorkflowFailedJobs: [
      "POST /repos/{owner}/{repo}/actions/runs/{run_id}/rerun-failed-jobs"
    ],
    removeAllCustomLabelsFromSelfHostedRunnerForOrg: [
      "DELETE /orgs/{org}/actions/runners/{runner_id}/labels"
    ],
    removeAllCustomLabelsFromSelfHostedRunnerForRepo: [
      "DELETE /repos/{owner}/{repo}/actions/runners/{runner_id}/labels"
    ],
    removeCustomLabelFromSelfHostedRunnerForOrg: [
      "DELETE /orgs/{org}/actions/runners/{runner_id}/labels/{name}"
    ],
    removeCustomLabelFromSelfHostedRunnerForRepo: [
      "DELETE /repos/{owner}/{repo}/actions/runners/{runner_id}/labels/{name}"
    ],
    removeSelectedRepoFromOrgSecret: [
      "DELETE /orgs/{org}/actions/secrets/{secret_name}/repositories/{repository_id}"
    ],
    removeSelectedRepoFromOrgVariable: [
      "DELETE /orgs/{org}/actions/variables/{name}/repositories/{repository_id}"
    ],
    reviewCustomGatesForRun: [
      "POST /repos/{owner}/{repo}/actions/runs/{run_id}/deployment_protection_rule"
    ],
    reviewPendingDeploymentsForRun: [
      "POST /repos/{owner}/{repo}/actions/runs/{run_id}/pending_deployments"
    ],
    setAllowedActionsOrganization: [
      "PUT /orgs/{org}/actions/permissions/selected-actions"
    ],
    setAllowedActionsRepository: [
      "PUT /repos/{owner}/{repo}/actions/permissions/selected-actions"
    ],
    setCustomLabelsForSelfHostedRunnerForOrg: [
      "PUT /orgs/{org}/actions/runners/{runner_id}/labels"
    ],
    setCustomLabelsForSelfHostedRunnerForRepo: [
      "PUT /repos/{owner}/{repo}/actions/runners/{runner_id}/labels"
    ],
    setCustomOidcSubClaimForRepo: [
      "PUT /repos/{owner}/{repo}/actions/oidc/customization/sub"
    ],
    setGithubActionsDefaultWorkflowPermissionsOrganization: [
      "PUT /orgs/{org}/actions/permissions/workflow"
    ],
    setGithubActionsDefaultWorkflowPermissionsRepository: [
      "PUT /repos/{owner}/{repo}/actions/permissions/workflow"
    ],
    setGithubActionsPermissionsOrganization: [
      "PUT /orgs/{org}/actions/permissions"
    ],
    setGithubActionsPermissionsRepository: [
      "PUT /repos/{owner}/{repo}/actions/permissions"
    ],
    setSelectedReposForOrgSecret: [
      "PUT /orgs/{org}/actions/secrets/{secret_name}/repositories"
    ],
    setSelectedReposForOrgVariable: [
      "PUT /orgs/{org}/actions/variables/{name}/repositories"
    ],
    setSelectedRepositoriesEnabledGithubActionsOrganization: [
      "PUT /orgs/{org}/actions/permissions/repositories"
    ],
    setWorkflowAccessToRepository: [
      "PUT /repos/{owner}/{repo}/actions/permissions/access"
    ],
    updateEnvironmentVariable: [
      "PATCH /repos/{owner}/{repo}/environments/{environment_name}/variables/{name}"
    ],
    updateHostedRunnerForOrg: [
      "PATCH /orgs/{org}/actions/hosted-runners/{hosted_runner_id}"
    ],
    updateOrgVariable: ["PATCH /orgs/{org}/actions/variables/{name}"],
    updateRepoVariable: [
      "PATCH /repos/{owner}/{repo}/actions/variables/{name}"
    ]
  },
  activity: {
    checkRepoIsStarredByAuthenticatedUser: ["GET /user/starred/{owner}/{repo}"],
    deleteRepoSubscription: ["DELETE /repos/{owner}/{repo}/subscription"],
    deleteThreadSubscription: [
      "DELETE /notifications/threads/{thread_id}/subscription"
    ],
    getFeeds: ["GET /feeds"],
    getRepoSubscription: ["GET /repos/{owner}/{repo}/subscription"],
    getThread: ["GET /notifications/threads/{thread_id}"],
    getThreadSubscriptionForAuthenticatedUser: [
      "GET /notifications/threads/{thread_id}/subscription"
    ],
    listEventsForAuthenticatedUser: ["GET /users/{username}/events"],
    listNotificationsForAuthenticatedUser: ["GET /notifications"],
    listOrgEventsForAuthenticatedUser: [
      "GET /users/{username}/events/orgs/{org}"
    ],
    listPublicEvents: ["GET /events"],
    listPublicEventsForRepoNetwork: ["GET /networks/{owner}/{repo}/events"],
    listPublicEventsForUser: ["GET /users/{username}/events/public"],
    listPublicOrgEvents: ["GET /orgs/{org}/events"],
    listReceivedEventsForUser: ["GET /users/{username}/received_events"],
    listReceivedPublicEventsForUser: [
      "GET /users/{username}/received_events/public"
    ],
    listRepoEvents: ["GET /repos/{owner}/{repo}/events"],
    listRepoNotificationsForAuthenticatedUser: [
      "GET /repos/{owner}/{repo}/notifications"
    ],
    listReposStarredByAuthenticatedUser: ["GET /user/starred"],
    listReposStarredByUser: ["GET /users/{username}/starred"],
    listReposWatchedByUser: ["GET /users/{username}/subscriptions"],
    listStargazersForRepo: ["GET /repos/{owner}/{repo}/stargazers"],
    listWatchedReposForAuthenticatedUser: ["GET /user/subscriptions"],
    listWatchersForRepo: ["GET /repos/{owner}/{repo}/subscribers"],
    markNotificationsAsRead: ["PUT /notifications"],
    markRepoNotificationsAsRead: ["PUT /repos/{owner}/{repo}/notifications"],
    markThreadAsDone: ["DELETE /notifications/threads/{thread_id}"],
    markThreadAsRead: ["PATCH /notifications/threads/{thread_id}"],
    setRepoSubscription: ["PUT /repos/{owner}/{repo}/subscription"],
    setThreadSubscription: [
      "PUT /notifications/threads/{thread_id}/subscription"
    ],
    starRepoForAuthenticatedUser: ["PUT /user/starred/{owner}/{repo}"],
    unstarRepoForAuthenticatedUser: ["DELETE /user/starred/{owner}/{repo}"]
  },
  apps: {
    addRepoToInstallation: [
      "PUT /user/installations/{installation_id}/repositories/{repository_id}",
      {},
      { renamed: ["apps", "addRepoToInstallationForAuthenticatedUser"] }
    ],
    addRepoToInstallationForAuthenticatedUser: [
      "PUT /user/installations/{installation_id}/repositories/{repository_id}"
    ],
    checkToken: ["POST /applications/{client_id}/token"],
    createFromManifest: ["POST /app-manifests/{code}/conversions"],
    createInstallationAccessToken: [
      "POST /app/installations/{installation_id}/access_tokens"
    ],
    deleteAuthorization: ["DELETE /applications/{client_id}/grant"],
    deleteInstallation: ["DELETE /app/installations/{installation_id}"],
    deleteToken: ["DELETE /applications/{client_id}/token"],
    getAuthenticated: ["GET /app"],
    getBySlug: ["GET /apps/{app_slug}"],
    getInstallation: ["GET /app/installations/{installation_id}"],
    getOrgInstallation: ["GET /orgs/{org}/installation"],
    getRepoInstallation: ["GET /repos/{owner}/{repo}/installation"],
    getSubscriptionPlanForAccount: [
      "GET /marketplace_listing/accounts/{account_id}"
    ],
    getSubscriptionPlanForAccountStubbed: [
      "GET /marketplace_listing/stubbed/accounts/{account_id}"
    ],
    getUserInstallation: ["GET /users/{username}/installation"],
    getWebhookConfigForApp: ["GET /app/hook/config"],
    getWebhookDelivery: ["GET /app/hook/deliveries/{delivery_id}"],
    listAccountsForPlan: ["GET /marketplace_listing/plans/{plan_id}/accounts"],
    listAccountsForPlanStubbed: [
      "GET /marketplace_listing/stubbed/plans/{plan_id}/accounts"
    ],
    listInstallationReposForAuthenticatedUser: [
      "GET /user/installations/{installation_id}/repositories"
    ],
    listInstallationRequestsForAuthenticatedApp: [
      "GET /app/installation-requests"
    ],
    listInstallations: ["GET /app/installations"],
    listInstallationsForAuthenticatedUser: ["GET /user/installations"],
    listPlans: ["GET /marketplace_listing/plans"],
    listPlansStubbed: ["GET /marketplace_listing/stubbed/plans"],
    listReposAccessibleToInstallation: ["GET /installation/repositories"],
    listSubscriptionsForAuthenticatedUser: ["GET /user/marketplace_purchases"],
    listSubscriptionsForAuthenticatedUserStubbed: [
      "GET /user/marketplace_purchases/stubbed"
    ],
    listWebhookDeliveries: ["GET /app/hook/deliveries"],
    redeliverWebhookDelivery: [
      "POST /app/hook/deliveries/{delivery_id}/attempts"
    ],
    removeRepoFromInstallation: [
      "DELETE /user/installations/{installation_id}/repositories/{repository_id}",
      {},
      { renamed: ["apps", "removeRepoFromInstallationForAuthenticatedUser"] }
    ],
    removeRepoFromInstallationForAuthenticatedUser: [
      "DELETE /user/installations/{installation_id}/repositories/{repository_id}"
    ],
    resetToken: ["PATCH /applications/{client_id}/token"],
    revokeInstallationAccessToken: ["DELETE /installation/token"],
    scopeToken: ["POST /applications/{client_id}/token/scoped"],
    suspendInstallation: ["PUT /app/installations/{installation_id}/suspended"],
    unsuspendInstallation: [
      "DELETE /app/installations/{installation_id}/suspended"
    ],
    updateWebhookConfigForApp: ["PATCH /app/hook/config"]
  },
  billing: {
    getGithubActionsBillingOrg: ["GET /orgs/{org}/settings/billing/actions"],
    getGithubActionsBillingUser: [
      "GET /users/{username}/settings/billing/actions"
    ],
    getGithubBillingPremiumRequestUsageReportOrg: [
      "GET /organizations/{org}/settings/billing/premium_request/usage"
    ],
    getGithubBillingPremiumRequestUsageReportUser: [
      "GET /users/{username}/settings/billing/premium_request/usage"
    ],
    getGithubBillingUsageReportOrg: [
      "GET /organizations/{org}/settings/billing/usage"
    ],
    getGithubBillingUsageReportUser: [
      "GET /users/{username}/settings/billing/usage"
    ],
    getGithubPackagesBillingOrg: ["GET /orgs/{org}/settings/billing/packages"],
    getGithubPackagesBillingUser: [
      "GET /users/{username}/settings/billing/packages"
    ],
    getSharedStorageBillingOrg: [
      "GET /orgs/{org}/settings/billing/shared-storage"
    ],
    getSharedStorageBillingUser: [
      "GET /users/{username}/settings/billing/shared-storage"
    ]
  },
  campaigns: {
    createCampaign: ["POST /orgs/{org}/campaigns"],
    deleteCampaign: ["DELETE /orgs/{org}/campaigns/{campaign_number}"],
    getCampaignSummary: ["GET /orgs/{org}/campaigns/{campaign_number}"],
    listOrgCampaigns: ["GET /orgs/{org}/campaigns"],
    updateCampaign: ["PATCH /orgs/{org}/campaigns/{campaign_number}"]
  },
  checks: {
    create: ["POST /repos/{owner}/{repo}/check-runs"],
    createSuite: ["POST /repos/{owner}/{repo}/check-suites"],
    get: ["GET /repos/{owner}/{repo}/check-runs/{check_run_id}"],
    getSuite: ["GET /repos/{owner}/{repo}/check-suites/{check_suite_id}"],
    listAnnotations: [
      "GET /repos/{owner}/{repo}/check-runs/{check_run_id}/annotations"
    ],
    listForRef: ["GET /repos/{owner}/{repo}/commits/{ref}/check-runs"],
    listForSuite: [
      "GET /repos/{owner}/{repo}/check-suites/{check_suite_id}/check-runs"
    ],
    listSuitesForRef: ["GET /repos/{owner}/{repo}/commits/{ref}/check-suites"],
    rerequestRun: [
      "POST /repos/{owner}/{repo}/check-runs/{check_run_id}/rerequest"
    ],
    rerequestSuite: [
      "POST /repos/{owner}/{repo}/check-suites/{check_suite_id}/rerequest"
    ],
    setSuitesPreferences: [
      "PATCH /repos/{owner}/{repo}/check-suites/preferences"
    ],
    update: ["PATCH /repos/{owner}/{repo}/check-runs/{check_run_id}"]
  },
  codeScanning: {
    commitAutofix: [
      "POST /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}/autofix/commits"
    ],
    createAutofix: [
      "POST /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}/autofix"
    ],
    createVariantAnalysis: [
      "POST /repos/{owner}/{repo}/code-scanning/codeql/variant-analyses"
    ],
    deleteAnalysis: [
      "DELETE /repos/{owner}/{repo}/code-scanning/analyses/{analysis_id}{?confirm_delete}"
    ],
    deleteCodeqlDatabase: [
      "DELETE /repos/{owner}/{repo}/code-scanning/codeql/databases/{language}"
    ],
    getAlert: [
      "GET /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}",
      {},
      { renamedParameters: { alert_id: "alert_number" } }
    ],
    getAnalysis: [
      "GET /repos/{owner}/{repo}/code-scanning/analyses/{analysis_id}"
    ],
    getAutofix: [
      "GET /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}/autofix"
    ],
    getCodeqlDatabase: [
      "GET /repos/{owner}/{repo}/code-scanning/codeql/databases/{language}"
    ],
    getDefaultSetup: ["GET /repos/{owner}/{repo}/code-scanning/default-setup"],
    getSarif: ["GET /repos/{owner}/{repo}/code-scanning/sarifs/{sarif_id}"],
    getVariantAnalysis: [
      "GET /repos/{owner}/{repo}/code-scanning/codeql/variant-analyses/{codeql_variant_analysis_id}"
    ],
    getVariantAnalysisRepoTask: [
      "GET /repos/{owner}/{repo}/code-scanning/codeql/variant-analyses/{codeql_variant_analysis_id}/repos/{repo_owner}/{repo_name}"
    ],
    listAlertInstances: [
      "GET /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}/instances"
    ],
    listAlertsForOrg: ["GET /orgs/{org}/code-scanning/alerts"],
    listAlertsForRepo: ["GET /repos/{owner}/{repo}/code-scanning/alerts"],
    listAlertsInstances: [
      "GET /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}/instances",
      {},
      { renamed: ["codeScanning", "listAlertInstances"] }
    ],
    listCodeqlDatabases: [
      "GET /repos/{owner}/{repo}/code-scanning/codeql/databases"
    ],
    listRecentAnalyses: ["GET /repos/{owner}/{repo}/code-scanning/analyses"],
    updateAlert: [
      "PATCH /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}"
    ],
    updateDefaultSetup: [
      "PATCH /repos/{owner}/{repo}/code-scanning/default-setup"
    ],
    uploadSarif: ["POST /repos/{owner}/{repo}/code-scanning/sarifs"]
  },
  codeSecurity: {
    attachConfiguration: [
      "POST /orgs/{org}/code-security/configurations/{configuration_id}/attach"
    ],
    attachEnterpriseConfiguration: [
      "POST /enterprises/{enterprise}/code-security/configurations/{configuration_id}/attach"
    ],
    createConfiguration: ["POST /orgs/{org}/code-security/configurations"],
    createConfigurationForEnterprise: [
      "POST /enterprises/{enterprise}/code-security/configurations"
    ],
    deleteConfiguration: [
      "DELETE /orgs/{org}/code-security/configurations/{configuration_id}"
    ],
    deleteConfigurationForEnterprise: [
      "DELETE /enterprises/{enterprise}/code-security/configurations/{configuration_id}"
    ],
    detachConfiguration: [
      "DELETE /orgs/{org}/code-security/configurations/detach"
    ],
    getConfiguration: [
      "GET /orgs/{org}/code-security/configurations/{configuration_id}"
    ],
    getConfigurationForRepository: [
      "GET /repos/{owner}/{repo}/code-security-configuration"
    ],
    getConfigurationsForEnterprise: [
      "GET /enterprises/{enterprise}/code-security/configurations"
    ],
    getConfigurationsForOrg: ["GET /orgs/{org}/code-security/configurations"],
    getDefaultConfigurations: [
      "GET /orgs/{org}/code-security/configurations/defaults"
    ],
    getDefaultConfigurationsForEnterprise: [
      "GET /enterprises/{enterprise}/code-security/configurations/defaults"
    ],
    getRepositoriesForConfiguration: [
      "GET /orgs/{org}/code-security/configurations/{configuration_id}/repositories"
    ],
    getRepositoriesForEnterpriseConfiguration: [
      "GET /enterprises/{enterprise}/code-security/configurations/{configuration_id}/repositories"
    ],
    getSingleConfigurationForEnterprise: [
      "GET /enterprises/{enterprise}/code-security/configurations/{configuration_id}"
    ],
    setConfigurationAsDefault: [
      "PUT /orgs/{org}/code-security/configurations/{configuration_id}/defaults"
    ],
    setConfigurationAsDefaultForEnterprise: [
      "PUT /enterprises/{enterprise}/code-security/configurations/{configuration_id}/defaults"
    ],
    updateConfiguration: [
      "PATCH /orgs/{org}/code-security/configurations/{configuration_id}"
    ],
    updateEnterpriseConfiguration: [
      "PATCH /enterprises/{enterprise}/code-security/configurations/{configuration_id}"
    ]
  },
  codesOfConduct: {
    getAllCodesOfConduct: ["GET /codes_of_conduct"],
    getConductCode: ["GET /codes_of_conduct/{key}"]
  },
  codespaces: {
    addRepositoryForSecretForAuthenticatedUser: [
      "PUT /user/codespaces/secrets/{secret_name}/repositories/{repository_id}"
    ],
    addSelectedRepoToOrgSecret: [
      "PUT /orgs/{org}/codespaces/secrets/{secret_name}/repositories/{repository_id}"
    ],
    checkPermissionsForDevcontainer: [
      "GET /repos/{owner}/{repo}/codespaces/permissions_check"
    ],
    codespaceMachinesForAuthenticatedUser: [
      "GET /user/codespaces/{codespace_name}/machines"
    ],
    createForAuthenticatedUser: ["POST /user/codespaces"],
    createOrUpdateOrgSecret: [
      "PUT /orgs/{org}/codespaces/secrets/{secret_name}"
    ],
    createOrUpdateRepoSecret: [
      "PUT /repos/{owner}/{repo}/codespaces/secrets/{secret_name}"
    ],
    createOrUpdateSecretForAuthenticatedUser: [
      "PUT /user/codespaces/secrets/{secret_name}"
    ],
    createWithPrForAuthenticatedUser: [
      "POST /repos/{owner}/{repo}/pulls/{pull_number}/codespaces"
    ],
    createWithRepoForAuthenticatedUser: [
      "POST /repos/{owner}/{repo}/codespaces"
    ],
    deleteForAuthenticatedUser: ["DELETE /user/codespaces/{codespace_name}"],
    deleteFromOrganization: [
      "DELETE /orgs/{org}/members/{username}/codespaces/{codespace_name}"
    ],
    deleteOrgSecret: ["DELETE /orgs/{org}/codespaces/secrets/{secret_name}"],
    deleteRepoSecret: [
      "DELETE /repos/{owner}/{repo}/codespaces/secrets/{secret_name}"
    ],
    deleteSecretForAuthenticatedUser: [
      "DELETE /user/codespaces/secrets/{secret_name}"
    ],
    exportForAuthenticatedUser: [
      "POST /user/codespaces/{codespace_name}/exports"
    ],
    getCodespacesForUserInOrg: [
      "GET /orgs/{org}/members/{username}/codespaces"
    ],
    getExportDetailsForAuthenticatedUser: [
      "GET /user/codespaces/{codespace_name}/exports/{export_id}"
    ],
    getForAuthenticatedUser: ["GET /user/codespaces/{codespace_name}"],
    getOrgPublicKey: ["GET /orgs/{org}/codespaces/secrets/public-key"],
    getOrgSecret: ["GET /orgs/{org}/codespaces/secrets/{secret_name}"],
    getPublicKeyForAuthenticatedUser: [
      "GET /user/codespaces/secrets/public-key"
    ],
    getRepoPublicKey: [
      "GET /repos/{owner}/{repo}/codespaces/secrets/public-key"
    ],
    getRepoSecret: [
      "GET /repos/{owner}/{repo}/codespaces/secrets/{secret_name}"
    ],
    getSecretForAuthenticatedUser: [
      "GET /user/codespaces/secrets/{secret_name}"
    ],
    listDevcontainersInRepositoryForAuthenticatedUser: [
      "GET /repos/{owner}/{repo}/codespaces/devcontainers"
    ],
    listForAuthenticatedUser: ["GET /user/codespaces"],
    listInOrganization: [
      "GET /orgs/{org}/codespaces",
      {},
      { renamedParameters: { org_id: "org" } }
    ],
    listInRepositoryForAuthenticatedUser: [
      "GET /repos/{owner}/{repo}/codespaces"
    ],
    listOrgSecrets: ["GET /orgs/{org}/codespaces/secrets"],
    listRepoSecrets: ["GET /repos/{owner}/{repo}/codespaces/secrets"],
    listRepositoriesForSecretForAuthenticatedUser: [
      "GET /user/codespaces/secrets/{secret_name}/repositories"
    ],
    listSecretsForAuthenticatedUser: ["GET /user/codespaces/secrets"],
    listSelectedReposForOrgSecret: [
      "GET /orgs/{org}/codespaces/secrets/{secret_name}/repositories"
    ],
    preFlightWithRepoForAuthenticatedUser: [
      "GET /repos/{owner}/{repo}/codespaces/new"
    ],
    publishForAuthenticatedUser: [
      "POST /user/codespaces/{codespace_name}/publish"
    ],
    removeRepositoryForSecretForAuthenticatedUser: [
      "DELETE /user/codespaces/secrets/{secret_name}/repositories/{repository_id}"
    ],
    removeSelectedRepoFromOrgSecret: [
      "DELETE /orgs/{org}/codespaces/secrets/{secret_name}/repositories/{repository_id}"
    ],
    repoMachinesForAuthenticatedUser: [
      "GET /repos/{owner}/{repo}/codespaces/machines"
    ],
    setRepositoriesForSecretForAuthenticatedUser: [
      "PUT /user/codespaces/secrets/{secret_name}/repositories"
    ],
    setSelectedReposForOrgSecret: [
      "PUT /orgs/{org}/codespaces/secrets/{secret_name}/repositories"
    ],
    startForAuthenticatedUser: ["POST /user/codespaces/{codespace_name}/start"],
    stopForAuthenticatedUser: ["POST /user/codespaces/{codespace_name}/stop"],
    stopInOrganization: [
      "POST /orgs/{org}/members/{username}/codespaces/{codespace_name}/stop"
    ],
    updateForAuthenticatedUser: ["PATCH /user/codespaces/{codespace_name}"]
  },
  copilot: {
    addCopilotSeatsForTeams: [
      "POST /orgs/{org}/copilot/billing/selected_teams"
    ],
    addCopilotSeatsForUsers: [
      "POST /orgs/{org}/copilot/billing/selected_users"
    ],
    cancelCopilotSeatAssignmentForTeams: [
      "DELETE /orgs/{org}/copilot/billing/selected_teams"
    ],
    cancelCopilotSeatAssignmentForUsers: [
      "DELETE /orgs/{org}/copilot/billing/selected_users"
    ],
    copilotMetricsForOrganization: ["GET /orgs/{org}/copilot/metrics"],
    copilotMetricsForTeam: ["GET /orgs/{org}/team/{team_slug}/copilot/metrics"],
    getCopilotOrganizationDetails: ["GET /orgs/{org}/copilot/billing"],
    getCopilotSeatDetailsForUser: [
      "GET /orgs/{org}/members/{username}/copilot"
    ],
    listCopilotSeats: ["GET /orgs/{org}/copilot/billing/seats"]
  },
  credentials: { revoke: ["POST /credentials/revoke"] },
  dependabot: {
    addSelectedRepoToOrgSecret: [
      "PUT /orgs/{org}/dependabot/secrets/{secret_name}/repositories/{repository_id}"
    ],
    createOrUpdateOrgSecret: [
      "PUT /orgs/{org}/dependabot/secrets/{secret_name}"
    ],
    createOrUpdateRepoSecret: [
      "PUT /repos/{owner}/{repo}/dependabot/secrets/{secret_name}"
    ],
    deleteOrgSecret: ["DELETE /orgs/{org}/dependabot/secrets/{secret_name}"],
    deleteRepoSecret: [
      "DELETE /repos/{owner}/{repo}/dependabot/secrets/{secret_name}"
    ],
    getAlert: ["GET /repos/{owner}/{repo}/dependabot/alerts/{alert_number}"],
    getOrgPublicKey: ["GET /orgs/{org}/dependabot/secrets/public-key"],
    getOrgSecret: ["GET /orgs/{org}/dependabot/secrets/{secret_name}"],
    getRepoPublicKey: [
      "GET /repos/{owner}/{repo}/dependabot/secrets/public-key"
    ],
    getRepoSecret: [
      "GET /repos/{owner}/{repo}/dependabot/secrets/{secret_name}"
    ],
    listAlertsForEnterprise: [
      "GET /enterprises/{enterprise}/dependabot/alerts"
    ],
    listAlertsForOrg: ["GET /orgs/{org}/dependabot/alerts"],
    listAlertsForRepo: ["GET /repos/{owner}/{repo}/dependabot/alerts"],
    listOrgSecrets: ["GET /orgs/{org}/dependabot/secrets"],
    listRepoSecrets: ["GET /repos/{owner}/{repo}/dependabot/secrets"],
    listSelectedReposForOrgSecret: [
      "GET /orgs/{org}/dependabot/secrets/{secret_name}/repositories"
    ],
    removeSelectedRepoFromOrgSecret: [
      "DELETE /orgs/{org}/dependabot/secrets/{secret_name}/repositories/{repository_id}"
    ],
    repositoryAccessForOrg: [
      "GET /organizations/{org}/dependabot/repository-access"
    ],
    setRepositoryAccessDefaultLevel: [
      "PUT /organizations/{org}/dependabot/repository-access/default-level"
    ],
    setSelectedReposForOrgSecret: [
      "PUT /orgs/{org}/dependabot/secrets/{secret_name}/repositories"
    ],
    updateAlert: [
      "PATCH /repos/{owner}/{repo}/dependabot/alerts/{alert_number}"
    ],
    updateRepositoryAccessForOrg: [
      "PATCH /organizations/{org}/dependabot/repository-access"
    ]
  },
  dependencyGraph: {
    createRepositorySnapshot: [
      "POST /repos/{owner}/{repo}/dependency-graph/snapshots"
    ],
    diffRange: [
      "GET /repos/{owner}/{repo}/dependency-graph/compare/{basehead}"
    ],
    exportSbom: ["GET /repos/{owner}/{repo}/dependency-graph/sbom"]
  },
  emojis: { get: ["GET /emojis"] },
  enterpriseTeamMemberships: {
    add: [
      "PUT /enterprises/{enterprise}/teams/{enterprise-team}/memberships/{username}"
    ],
    bulkAdd: [
      "POST /enterprises/{enterprise}/teams/{enterprise-team}/memberships/add"
    ],
    bulkRemove: [
      "POST /enterprises/{enterprise}/teams/{enterprise-team}/memberships/remove"
    ],
    get: [
      "GET /enterprises/{enterprise}/teams/{enterprise-team}/memberships/{username}"
    ],
    list: ["GET /enterprises/{enterprise}/teams/{enterprise-team}/memberships"],
    remove: [
      "DELETE /enterprises/{enterprise}/teams/{enterprise-team}/memberships/{username}"
    ]
  },
  enterpriseTeamOrganizations: {
    add: [
      "PUT /enterprises/{enterprise}/teams/{enterprise-team}/organizations/{org}"
    ],
    bulkAdd: [
      "POST /enterprises/{enterprise}/teams/{enterprise-team}/organizations/add"
    ],
    bulkRemove: [
      "POST /enterprises/{enterprise}/teams/{enterprise-team}/organizations/remove"
    ],
    delete: [
      "DELETE /enterprises/{enterprise}/teams/{enterprise-team}/organizations/{org}"
    ],
    getAssignment: [
      "GET /enterprises/{enterprise}/teams/{enterprise-team}/organizations/{org}"
    ],
    getAssignments: [
      "GET /enterprises/{enterprise}/teams/{enterprise-team}/organizations"
    ]
  },
  enterpriseTeams: {
    create: ["POST /enterprises/{enterprise}/teams"],
    delete: ["DELETE /enterprises/{enterprise}/teams/{team_slug}"],
    get: ["GET /enterprises/{enterprise}/teams/{team_slug}"],
    list: ["GET /enterprises/{enterprise}/teams"],
    update: ["PATCH /enterprises/{enterprise}/teams/{team_slug}"]
  },
  gists: {
    checkIsStarred: ["GET /gists/{gist_id}/star"],
    create: ["POST /gists"],
    createComment: ["POST /gists/{gist_id}/comments"],
    delete: ["DELETE /gists/{gist_id}"],
    deleteComment: ["DELETE /gists/{gist_id}/comments/{comment_id}"],
    fork: ["POST /gists/{gist_id}/forks"],
    get: ["GET /gists/{gist_id}"],
    getComment: ["GET /gists/{gist_id}/comments/{comment_id}"],
    getRevision: ["GET /gists/{gist_id}/{sha}"],
    list: ["GET /gists"],
    listComments: ["GET /gists/{gist_id}/comments"],
    listCommits: ["GET /gists/{gist_id}/commits"],
    listForUser: ["GET /users/{username}/gists"],
    listForks: ["GET /gists/{gist_id}/forks"],
    listPublic: ["GET /gists/public"],
    listStarred: ["GET /gists/starred"],
    star: ["PUT /gists/{gist_id}/star"],
    unstar: ["DELETE /gists/{gist_id}/star"],
    update: ["PATCH /gists/{gist_id}"],
    updateComment: ["PATCH /gists/{gist_id}/comments/{comment_id}"]
  },
  git: {
    createBlob: ["POST /repos/{owner}/{repo}/git/blobs"],
    createCommit: ["POST /repos/{owner}/{repo}/git/commits"],
    createRef: ["POST /repos/{owner}/{repo}/git/refs"],
    createTag: ["POST /repos/{owner}/{repo}/git/tags"],
    createTree: ["POST /repos/{owner}/{repo}/git/trees"],
    deleteRef: ["DELETE /repos/{owner}/{repo}/git/refs/{ref}"],
    getBlob: ["GET /repos/{owner}/{repo}/git/blobs/{file_sha}"],
    getCommit: ["GET /repos/{owner}/{repo}/git/commits/{commit_sha}"],
    getRef: ["GET /repos/{owner}/{repo}/git/ref/{ref}"],
    getTag: ["GET /repos/{owner}/{repo}/git/tags/{tag_sha}"],
    getTree: ["GET /repos/{owner}/{repo}/git/trees/{tree_sha}"],
    listMatchingRefs: ["GET /repos/{owner}/{repo}/git/matching-refs/{ref}"],
    updateRef: ["PATCH /repos/{owner}/{repo}/git/refs/{ref}"]
  },
  gitignore: {
    getAllTemplates: ["GET /gitignore/templates"],
    getTemplate: ["GET /gitignore/templates/{name}"]
  },
  hostedCompute: {
    createNetworkConfigurationForOrg: [
      "POST /orgs/{org}/settings/network-configurations"
    ],
    deleteNetworkConfigurationFromOrg: [
      "DELETE /orgs/{org}/settings/network-configurations/{network_configuration_id}"
    ],
    getNetworkConfigurationForOrg: [
      "GET /orgs/{org}/settings/network-configurations/{network_configuration_id}"
    ],
    getNetworkSettingsForOrg: [
      "GET /orgs/{org}/settings/network-settings/{network_settings_id}"
    ],
    listNetworkConfigurationsForOrg: [
      "GET /orgs/{org}/settings/network-configurations"
    ],
    updateNetworkConfigurationForOrg: [
      "PATCH /orgs/{org}/settings/network-configurations/{network_configuration_id}"
    ]
  },
  interactions: {
    getRestrictionsForAuthenticatedUser: ["GET /user/interaction-limits"],
    getRestrictionsForOrg: ["GET /orgs/{org}/interaction-limits"],
    getRestrictionsForRepo: ["GET /repos/{owner}/{repo}/interaction-limits"],
    getRestrictionsForYourPublicRepos: [
      "GET /user/interaction-limits",
      {},
      { renamed: ["interactions", "getRestrictionsForAuthenticatedUser"] }
    ],
    removeRestrictionsForAuthenticatedUser: ["DELETE /user/interaction-limits"],
    removeRestrictionsForOrg: ["DELETE /orgs/{org}/interaction-limits"],
    removeRestrictionsForRepo: [
      "DELETE /repos/{owner}/{repo}/interaction-limits"
    ],
    removeRestrictionsForYourPublicRepos: [
      "DELETE /user/interaction-limits",
      {},
      { renamed: ["interactions", "removeRestrictionsForAuthenticatedUser"] }
    ],
    setRestrictionsForAuthenticatedUser: ["PUT /user/interaction-limits"],
    setRestrictionsForOrg: ["PUT /orgs/{org}/interaction-limits"],
    setRestrictionsForRepo: ["PUT /repos/{owner}/{repo}/interaction-limits"],
    setRestrictionsForYourPublicRepos: [
      "PUT /user/interaction-limits",
      {},
      { renamed: ["interactions", "setRestrictionsForAuthenticatedUser"] }
    ]
  },
  issues: {
    addAssignees: [
      "POST /repos/{owner}/{repo}/issues/{issue_number}/assignees"
    ],
    addBlockedByDependency: [
      "POST /repos/{owner}/{repo}/issues/{issue_number}/dependencies/blocked_by"
    ],
    addLabels: ["POST /repos/{owner}/{repo}/issues/{issue_number}/labels"],
    addSubIssue: [
      "POST /repos/{owner}/{repo}/issues/{issue_number}/sub_issues"
    ],
    checkUserCanBeAssigned: ["GET /repos/{owner}/{repo}/assignees/{assignee}"],
    checkUserCanBeAssignedToIssue: [
      "GET /repos/{owner}/{repo}/issues/{issue_number}/assignees/{assignee}"
    ],
    create: ["POST /repos/{owner}/{repo}/issues"],
    createComment: [
      "POST /repos/{owner}/{repo}/issues/{issue_number}/comments"
    ],
    createLabel: ["POST /repos/{owner}/{repo}/labels"],
    createMilestone: ["POST /repos/{owner}/{repo}/milestones"],
    deleteComment: [
      "DELETE /repos/{owner}/{repo}/issues/comments/{comment_id}"
    ],
    deleteLabel: ["DELETE /repos/{owner}/{repo}/labels/{name}"],
    deleteMilestone: [
      "DELETE /repos/{owner}/{repo}/milestones/{milestone_number}"
    ],
    get: ["GET /repos/{owner}/{repo}/issues/{issue_number}"],
    getComment: ["GET /repos/{owner}/{repo}/issues/comments/{comment_id}"],
    getEvent: ["GET /repos/{owner}/{repo}/issues/events/{event_id}"],
    getLabel: ["GET /repos/{owner}/{repo}/labels/{name}"],
    getMilestone: ["GET /repos/{owner}/{repo}/milestones/{milestone_number}"],
    getParent: ["GET /repos/{owner}/{repo}/issues/{issue_number}/parent"],
    list: ["GET /issues"],
    listAssignees: ["GET /repos/{owner}/{repo}/assignees"],
    listComments: ["GET /repos/{owner}/{repo}/issues/{issue_number}/comments"],
    listCommentsForRepo: ["GET /repos/{owner}/{repo}/issues/comments"],
    listDependenciesBlockedBy: [
      "GET /repos/{owner}/{repo}/issues/{issue_number}/dependencies/blocked_by"
    ],
    listDependenciesBlocking: [
      "GET /repos/{owner}/{repo}/issues/{issue_number}/dependencies/blocking"
    ],
    listEvents: ["GET /repos/{owner}/{repo}/issues/{issue_number}/events"],
    listEventsForRepo: ["GET /repos/{owner}/{repo}/issues/events"],
    listEventsForTimeline: [
      "GET /repos/{owner}/{repo}/issues/{issue_number}/timeline"
    ],
    listForAuthenticatedUser: ["GET /user/issues"],
    listForOrg: ["GET /orgs/{org}/issues"],
    listForRepo: ["GET /repos/{owner}/{repo}/issues"],
    listLabelsForMilestone: [
      "GET /repos/{owner}/{repo}/milestones/{milestone_number}/labels"
    ],
    listLabelsForRepo: ["GET /repos/{owner}/{repo}/labels"],
    listLabelsOnIssue: [
      "GET /repos/{owner}/{repo}/issues/{issue_number}/labels"
    ],
    listMilestones: ["GET /repos/{owner}/{repo}/milestones"],
    listSubIssues: [
      "GET /repos/{owner}/{repo}/issues/{issue_number}/sub_issues"
    ],
    lock: ["PUT /repos/{owner}/{repo}/issues/{issue_number}/lock"],
    removeAllLabels: [
      "DELETE /repos/{owner}/{repo}/issues/{issue_number}/labels"
    ],
    removeAssignees: [
      "DELETE /repos/{owner}/{repo}/issues/{issue_number}/assignees"
    ],
    removeDependencyBlockedBy: [
      "DELETE /repos/{owner}/{repo}/issues/{issue_number}/dependencies/blocked_by/{issue_id}"
    ],
    removeLabel: [
      "DELETE /repos/{owner}/{repo}/issues/{issue_number}/labels/{name}"
    ],
    removeSubIssue: [
      "DELETE /repos/{owner}/{repo}/issues/{issue_number}/sub_issue"
    ],
    reprioritizeSubIssue: [
      "PATCH /repos/{owner}/{repo}/issues/{issue_number}/sub_issues/priority"
    ],
    setLabels: ["PUT /repos/{owner}/{repo}/issues/{issue_number}/labels"],
    unlock: ["DELETE /repos/{owner}/{repo}/issues/{issue_number}/lock"],
    update: ["PATCH /repos/{owner}/{repo}/issues/{issue_number}"],
    updateComment: ["PATCH /repos/{owner}/{repo}/issues/comments/{comment_id}"],
    updateLabel: ["PATCH /repos/{owner}/{repo}/labels/{name}"],
    updateMilestone: [
      "PATCH /repos/{owner}/{repo}/milestones/{milestone_number}"
    ]
  },
  licenses: {
    get: ["GET /licenses/{license}"],
    getAllCommonlyUsed: ["GET /licenses"],
    getForRepo: ["GET /repos/{owner}/{repo}/license"]
  },
  markdown: {
    render: ["POST /markdown"],
    renderRaw: [
      "POST /markdown/raw",
      { headers: { "content-type": "text/plain; charset=utf-8" } }
    ]
  },
  meta: {
    get: ["GET /meta"],
    getAllVersions: ["GET /versions"],
    getOctocat: ["GET /octocat"],
    getZen: ["GET /zen"],
    root: ["GET /"]
  },
  migrations: {
    deleteArchiveForAuthenticatedUser: [
      "DELETE /user/migrations/{migration_id}/archive"
    ],
    deleteArchiveForOrg: [
      "DELETE /orgs/{org}/migrations/{migration_id}/archive"
    ],
    downloadArchiveForOrg: [
      "GET /orgs/{org}/migrations/{migration_id}/archive"
    ],
    getArchiveForAuthenticatedUser: [
      "GET /user/migrations/{migration_id}/archive"
    ],
    getStatusForAuthenticatedUser: ["GET /user/migrations/{migration_id}"],
    getStatusForOrg: ["GET /orgs/{org}/migrations/{migration_id}"],
    listForAuthenticatedUser: ["GET /user/migrations"],
    listForOrg: ["GET /orgs/{org}/migrations"],
    listReposForAuthenticatedUser: [
      "GET /user/migrations/{migration_id}/repositories"
    ],
    listReposForOrg: ["GET /orgs/{org}/migrations/{migration_id}/repositories"],
    listReposForUser: [
      "GET /user/migrations/{migration_id}/repositories",
      {},
      { renamed: ["migrations", "listReposForAuthenticatedUser"] }
    ],
    startForAuthenticatedUser: ["POST /user/migrations"],
    startForOrg: ["POST /orgs/{org}/migrations"],
    unlockRepoForAuthenticatedUser: [
      "DELETE /user/migrations/{migration_id}/repos/{repo_name}/lock"
    ],
    unlockRepoForOrg: [
      "DELETE /orgs/{org}/migrations/{migration_id}/repos/{repo_name}/lock"
    ]
  },
  oidc: {
    getOidcCustomSubTemplateForOrg: [
      "GET /orgs/{org}/actions/oidc/customization/sub"
    ],
    updateOidcCustomSubTemplateForOrg: [
      "PUT /orgs/{org}/actions/oidc/customization/sub"
    ]
  },
  orgs: {
    addSecurityManagerTeam: [
      "PUT /orgs/{org}/security-managers/teams/{team_slug}",
      {},
      {
        deprecated: "octokit.rest.orgs.addSecurityManagerTeam() is deprecated, see https://docs.github.com/rest/orgs/security-managers#add-a-security-manager-team"
      }
    ],
    assignTeamToOrgRole: [
      "PUT /orgs/{org}/organization-roles/teams/{team_slug}/{role_id}"
    ],
    assignUserToOrgRole: [
      "PUT /orgs/{org}/organization-roles/users/{username}/{role_id}"
    ],
    blockUser: ["PUT /orgs/{org}/blocks/{username}"],
    cancelInvitation: ["DELETE /orgs/{org}/invitations/{invitation_id}"],
    checkBlockedUser: ["GET /orgs/{org}/blocks/{username}"],
    checkMembershipForUser: ["GET /orgs/{org}/members/{username}"],
    checkPublicMembershipForUser: ["GET /orgs/{org}/public_members/{username}"],
    convertMemberToOutsideCollaborator: [
      "PUT /orgs/{org}/outside_collaborators/{username}"
    ],
    createArtifactStorageRecord: [
      "POST /orgs/{org}/artifacts/metadata/storage-record"
    ],
    createInvitation: ["POST /orgs/{org}/invitations"],
    createIssueType: ["POST /orgs/{org}/issue-types"],
    createWebhook: ["POST /orgs/{org}/hooks"],
    customPropertiesForOrgsCreateOrUpdateOrganizationValues: [
      "PATCH /organizations/{org}/org-properties/values"
    ],
    customPropertiesForOrgsGetOrganizationValues: [
      "GET /organizations/{org}/org-properties/values"
    ],
    customPropertiesForReposCreateOrUpdateOrganizationDefinition: [
      "PUT /orgs/{org}/properties/schema/{custom_property_name}"
    ],
    customPropertiesForReposCreateOrUpdateOrganizationDefinitions: [
      "PATCH /orgs/{org}/properties/schema"
    ],
    customPropertiesForReposCreateOrUpdateOrganizationValues: [
      "PATCH /orgs/{org}/properties/values"
    ],
    customPropertiesForReposDeleteOrganizationDefinition: [
      "DELETE /orgs/{org}/properties/schema/{custom_property_name}"
    ],
    customPropertiesForReposGetOrganizationDefinition: [
      "GET /orgs/{org}/properties/schema/{custom_property_name}"
    ],
    customPropertiesForReposGetOrganizationDefinitions: [
      "GET /orgs/{org}/properties/schema"
    ],
    customPropertiesForReposGetOrganizationValues: [
      "GET /orgs/{org}/properties/values"
    ],
    delete: ["DELETE /orgs/{org}"],
    deleteAttestationsBulk: ["POST /orgs/{org}/attestations/delete-request"],
    deleteAttestationsById: [
      "DELETE /orgs/{org}/attestations/{attestation_id}"
    ],
    deleteAttestationsBySubjectDigest: [
      "DELETE /orgs/{org}/attestations/digest/{subject_digest}"
    ],
    deleteIssueType: ["DELETE /orgs/{org}/issue-types/{issue_type_id}"],
    deleteWebhook: ["DELETE /orgs/{org}/hooks/{hook_id}"],
    disableSelectedRepositoryImmutableReleasesOrganization: [
      "DELETE /orgs/{org}/settings/immutable-releases/repositories/{repository_id}"
    ],
    enableSelectedRepositoryImmutableReleasesOrganization: [
      "PUT /orgs/{org}/settings/immutable-releases/repositories/{repository_id}"
    ],
    get: ["GET /orgs/{org}"],
    getImmutableReleasesSettings: [
      "GET /orgs/{org}/settings/immutable-releases"
    ],
    getImmutableReleasesSettingsRepositories: [
      "GET /orgs/{org}/settings/immutable-releases/repositories"
    ],
    getMembershipForAuthenticatedUser: ["GET /user/memberships/orgs/{org}"],
    getMembershipForUser: ["GET /orgs/{org}/memberships/{username}"],
    getOrgRole: ["GET /orgs/{org}/organization-roles/{role_id}"],
    getOrgRulesetHistory: ["GET /orgs/{org}/rulesets/{ruleset_id}/history"],
    getOrgRulesetVersion: [
      "GET /orgs/{org}/rulesets/{ruleset_id}/history/{version_id}"
    ],
    getWebhook: ["GET /orgs/{org}/hooks/{hook_id}"],
    getWebhookConfigForOrg: ["GET /orgs/{org}/hooks/{hook_id}/config"],
    getWebhookDelivery: [
      "GET /orgs/{org}/hooks/{hook_id}/deliveries/{delivery_id}"
    ],
    list: ["GET /organizations"],
    listAppInstallations: ["GET /orgs/{org}/installations"],
    listArtifactStorageRecords: [
      "GET /orgs/{org}/artifacts/{subject_digest}/metadata/storage-records"
    ],
    listAttestationRepositories: ["GET /orgs/{org}/attestations/repositories"],
    listAttestations: ["GET /orgs/{org}/attestations/{subject_digest}"],
    listAttestationsBulk: [
      "POST /orgs/{org}/attestations/bulk-list{?per_page,before,after}"
    ],
    listBlockedUsers: ["GET /orgs/{org}/blocks"],
    listFailedInvitations: ["GET /orgs/{org}/failed_invitations"],
    listForAuthenticatedUser: ["GET /user/orgs"],
    listForUser: ["GET /users/{username}/orgs"],
    listInvitationTeams: ["GET /orgs/{org}/invitations/{invitation_id}/teams"],
    listIssueTypes: ["GET /orgs/{org}/issue-types"],
    listMembers: ["GET /orgs/{org}/members"],
    listMembershipsForAuthenticatedUser: ["GET /user/memberships/orgs"],
    listOrgRoleTeams: ["GET /orgs/{org}/organization-roles/{role_id}/teams"],
    listOrgRoleUsers: ["GET /orgs/{org}/organization-roles/{role_id}/users"],
    listOrgRoles: ["GET /orgs/{org}/organization-roles"],
    listOrganizationFineGrainedPermissions: [
      "GET /orgs/{org}/organization-fine-grained-permissions"
    ],
    listOutsideCollaborators: ["GET /orgs/{org}/outside_collaborators"],
    listPatGrantRepositories: [
      "GET /orgs/{org}/personal-access-tokens/{pat_id}/repositories"
    ],
    listPatGrantRequestRepositories: [
      "GET /orgs/{org}/personal-access-token-requests/{pat_request_id}/repositories"
    ],
    listPatGrantRequests: ["GET /orgs/{org}/personal-access-token-requests"],
    listPatGrants: ["GET /orgs/{org}/personal-access-tokens"],
    listPendingInvitations: ["GET /orgs/{org}/invitations"],
    listPublicMembers: ["GET /orgs/{org}/public_members"],
    listSecurityManagerTeams: [
      "GET /orgs/{org}/security-managers",
      {},
      {
        deprecated: "octokit.rest.orgs.listSecurityManagerTeams() is deprecated, see https://docs.github.com/rest/orgs/security-managers#list-security-manager-teams"
      }
    ],
    listWebhookDeliveries: ["GET /orgs/{org}/hooks/{hook_id}/deliveries"],
    listWebhooks: ["GET /orgs/{org}/hooks"],
    pingWebhook: ["POST /orgs/{org}/hooks/{hook_id}/pings"],
    redeliverWebhookDelivery: [
      "POST /orgs/{org}/hooks/{hook_id}/deliveries/{delivery_id}/attempts"
    ],
    removeMember: ["DELETE /orgs/{org}/members/{username}"],
    removeMembershipForUser: ["DELETE /orgs/{org}/memberships/{username}"],
    removeOutsideCollaborator: [
      "DELETE /orgs/{org}/outside_collaborators/{username}"
    ],
    removePublicMembershipForAuthenticatedUser: [
      "DELETE /orgs/{org}/public_members/{username}"
    ],
    removeSecurityManagerTeam: [
      "DELETE /orgs/{org}/security-managers/teams/{team_slug}",
      {},
      {
        deprecated: "octokit.rest.orgs.removeSecurityManagerTeam() is deprecated, see https://docs.github.com/rest/orgs/security-managers#remove-a-security-manager-team"
      }
    ],
    reviewPatGrantRequest: [
      "POST /orgs/{org}/personal-access-token-requests/{pat_request_id}"
    ],
    reviewPatGrantRequestsInBulk: [
      "POST /orgs/{org}/personal-access-token-requests"
    ],
    revokeAllOrgRolesTeam: [
      "DELETE /orgs/{org}/organization-roles/teams/{team_slug}"
    ],
    revokeAllOrgRolesUser: [
      "DELETE /orgs/{org}/organization-roles/users/{username}"
    ],
    revokeOrgRoleTeam: [
      "DELETE /orgs/{org}/organization-roles/teams/{team_slug}/{role_id}"
    ],
    revokeOrgRoleUser: [
      "DELETE /orgs/{org}/organization-roles/users/{username}/{role_id}"
    ],
    setImmutableReleasesSettings: [
      "PUT /orgs/{org}/settings/immutable-releases"
    ],
    setImmutableReleasesSettingsRepositories: [
      "PUT /orgs/{org}/settings/immutable-releases/repositories"
    ],
    setMembershipForUser: ["PUT /orgs/{org}/memberships/{username}"],
    setPublicMembershipForAuthenticatedUser: [
      "PUT /orgs/{org}/public_members/{username}"
    ],
    unblockUser: ["DELETE /orgs/{org}/blocks/{username}"],
    update: ["PATCH /orgs/{org}"],
    updateIssueType: ["PUT /orgs/{org}/issue-types/{issue_type_id}"],
    updateMembershipForAuthenticatedUser: [
      "PATCH /user/memberships/orgs/{org}"
    ],
    updatePatAccess: ["POST /orgs/{org}/personal-access-tokens/{pat_id}"],
    updatePatAccesses: ["POST /orgs/{org}/personal-access-tokens"],
    updateWebhook: ["PATCH /orgs/{org}/hooks/{hook_id}"],
    updateWebhookConfigForOrg: ["PATCH /orgs/{org}/hooks/{hook_id}/config"]
  },
  packages: {
    deletePackageForAuthenticatedUser: [
      "DELETE /user/packages/{package_type}/{package_name}"
    ],
    deletePackageForOrg: [
      "DELETE /orgs/{org}/packages/{package_type}/{package_name}"
    ],
    deletePackageForUser: [
      "DELETE /users/{username}/packages/{package_type}/{package_name}"
    ],
    deletePackageVersionForAuthenticatedUser: [
      "DELETE /user/packages/{package_type}/{package_name}/versions/{package_version_id}"
    ],
    deletePackageVersionForOrg: [
      "DELETE /orgs/{org}/packages/{package_type}/{package_name}/versions/{package_version_id}"
    ],
    deletePackageVersionForUser: [
      "DELETE /users/{username}/packages/{package_type}/{package_name}/versions/{package_version_id}"
    ],
    getAllPackageVersionsForAPackageOwnedByAnOrg: [
      "GET /orgs/{org}/packages/{package_type}/{package_name}/versions",
      {},
      { renamed: ["packages", "getAllPackageVersionsForPackageOwnedByOrg"] }
    ],
    getAllPackageVersionsForAPackageOwnedByTheAuthenticatedUser: [
      "GET /user/packages/{package_type}/{package_name}/versions",
      {},
      {
        renamed: [
          "packages",
          "getAllPackageVersionsForPackageOwnedByAuthenticatedUser"
        ]
      }
    ],
    getAllPackageVersionsForPackageOwnedByAuthenticatedUser: [
      "GET /user/packages/{package_type}/{package_name}/versions"
    ],
    getAllPackageVersionsForPackageOwnedByOrg: [
      "GET /orgs/{org}/packages/{package_type}/{package_name}/versions"
    ],
    getAllPackageVersionsForPackageOwnedByUser: [
      "GET /users/{username}/packages/{package_type}/{package_name}/versions"
    ],
    getPackageForAuthenticatedUser: [
      "GET /user/packages/{package_type}/{package_name}"
    ],
    getPackageForOrganization: [
      "GET /orgs/{org}/packages/{package_type}/{package_name}"
    ],
    getPackageForUser: [
      "GET /users/{username}/packages/{package_type}/{package_name}"
    ],
    getPackageVersionForAuthenticatedUser: [
      "GET /user/packages/{package_type}/{package_name}/versions/{package_version_id}"
    ],
    getPackageVersionForOrganization: [
      "GET /orgs/{org}/packages/{package_type}/{package_name}/versions/{package_version_id}"
    ],
    getPackageVersionForUser: [
      "GET /users/{username}/packages/{package_type}/{package_name}/versions/{package_version_id}"
    ],
    listDockerMigrationConflictingPackagesForAuthenticatedUser: [
      "GET /user/docker/conflicts"
    ],
    listDockerMigrationConflictingPackagesForOrganization: [
      "GET /orgs/{org}/docker/conflicts"
    ],
    listDockerMigrationConflictingPackagesForUser: [
      "GET /users/{username}/docker/conflicts"
    ],
    listPackagesForAuthenticatedUser: ["GET /user/packages"],
    listPackagesForOrganization: ["GET /orgs/{org}/packages"],
    listPackagesForUser: ["GET /users/{username}/packages"],
    restorePackageForAuthenticatedUser: [
      "POST /user/packages/{package_type}/{package_name}/restore{?token}"
    ],
    restorePackageForOrg: [
      "POST /orgs/{org}/packages/{package_type}/{package_name}/restore{?token}"
    ],
    restorePackageForUser: [
      "POST /users/{username}/packages/{package_type}/{package_name}/restore{?token}"
    ],
    restorePackageVersionForAuthenticatedUser: [
      "POST /user/packages/{package_type}/{package_name}/versions/{package_version_id}/restore"
    ],
    restorePackageVersionForOrg: [
      "POST /orgs/{org}/packages/{package_type}/{package_name}/versions/{package_version_id}/restore"
    ],
    restorePackageVersionForUser: [
      "POST /users/{username}/packages/{package_type}/{package_name}/versions/{package_version_id}/restore"
    ]
  },
  privateRegistries: {
    createOrgPrivateRegistry: ["POST /orgs/{org}/private-registries"],
    deleteOrgPrivateRegistry: [
      "DELETE /orgs/{org}/private-registries/{secret_name}"
    ],
    getOrgPrivateRegistry: ["GET /orgs/{org}/private-registries/{secret_name}"],
    getOrgPublicKey: ["GET /orgs/{org}/private-registries/public-key"],
    listOrgPrivateRegistries: ["GET /orgs/{org}/private-registries"],
    updateOrgPrivateRegistry: [
      "PATCH /orgs/{org}/private-registries/{secret_name}"
    ]
  },
  projects: {
    addItemForOrg: ["POST /orgs/{org}/projectsV2/{project_number}/items"],
    addItemForUser: [
      "POST /users/{username}/projectsV2/{project_number}/items"
    ],
    deleteItemForOrg: [
      "DELETE /orgs/{org}/projectsV2/{project_number}/items/{item_id}"
    ],
    deleteItemForUser: [
      "DELETE /users/{username}/projectsV2/{project_number}/items/{item_id}"
    ],
    getFieldForOrg: [
      "GET /orgs/{org}/projectsV2/{project_number}/fields/{field_id}"
    ],
    getFieldForUser: [
      "GET /users/{username}/projectsV2/{project_number}/fields/{field_id}"
    ],
    getForOrg: ["GET /orgs/{org}/projectsV2/{project_number}"],
    getForUser: ["GET /users/{username}/projectsV2/{project_number}"],
    getOrgItem: ["GET /orgs/{org}/projectsV2/{project_number}/items/{item_id}"],
    getUserItem: [
      "GET /users/{username}/projectsV2/{project_number}/items/{item_id}"
    ],
    listFieldsForOrg: ["GET /orgs/{org}/projectsV2/{project_number}/fields"],
    listFieldsForUser: [
      "GET /users/{username}/projectsV2/{project_number}/fields"
    ],
    listForOrg: ["GET /orgs/{org}/projectsV2"],
    listForUser: ["GET /users/{username}/projectsV2"],
    listItemsForOrg: ["GET /orgs/{org}/projectsV2/{project_number}/items"],
    listItemsForUser: [
      "GET /users/{username}/projectsV2/{project_number}/items"
    ],
    updateItemForOrg: [
      "PATCH /orgs/{org}/projectsV2/{project_number}/items/{item_id}"
    ],
    updateItemForUser: [
      "PATCH /users/{username}/projectsV2/{project_number}/items/{item_id}"
    ]
  },
  pulls: {
    checkIfMerged: ["GET /repos/{owner}/{repo}/pulls/{pull_number}/merge"],
    create: ["POST /repos/{owner}/{repo}/pulls"],
    createReplyForReviewComment: [
      "POST /repos/{owner}/{repo}/pulls/{pull_number}/comments/{comment_id}/replies"
    ],
    createReview: ["POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews"],
    createReviewComment: [
      "POST /repos/{owner}/{repo}/pulls/{pull_number}/comments"
    ],
    deletePendingReview: [
      "DELETE /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}"
    ],
    deleteReviewComment: [
      "DELETE /repos/{owner}/{repo}/pulls/comments/{comment_id}"
    ],
    dismissReview: [
      "PUT /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}/dismissals"
    ],
    get: ["GET /repos/{owner}/{repo}/pulls/{pull_number}"],
    getReview: [
      "GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}"
    ],
    getReviewComment: ["GET /repos/{owner}/{repo}/pulls/comments/{comment_id}"],
    list: ["GET /repos/{owner}/{repo}/pulls"],
    listCommentsForReview: [
      "GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}/comments"
    ],
    listCommits: ["GET /repos/{owner}/{repo}/pulls/{pull_number}/commits"],
    listFiles: ["GET /repos/{owner}/{repo}/pulls/{pull_number}/files"],
    listRequestedReviewers: [
      "GET /repos/{owner}/{repo}/pulls/{pull_number}/requested_reviewers"
    ],
    listReviewComments: [
      "GET /repos/{owner}/{repo}/pulls/{pull_number}/comments"
    ],
    listReviewCommentsForRepo: ["GET /repos/{owner}/{repo}/pulls/comments"],
    listReviews: ["GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews"],
    merge: ["PUT /repos/{owner}/{repo}/pulls/{pull_number}/merge"],
    removeRequestedReviewers: [
      "DELETE /repos/{owner}/{repo}/pulls/{pull_number}/requested_reviewers"
    ],
    requestReviewers: [
      "POST /repos/{owner}/{repo}/pulls/{pull_number}/requested_reviewers"
    ],
    submitReview: [
      "POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}/events"
    ],
    update: ["PATCH /repos/{owner}/{repo}/pulls/{pull_number}"],
    updateBranch: [
      "PUT /repos/{owner}/{repo}/pulls/{pull_number}/update-branch"
    ],
    updateReview: [
      "PUT /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}"
    ],
    updateReviewComment: [
      "PATCH /repos/{owner}/{repo}/pulls/comments/{comment_id}"
    ]
  },
  rateLimit: { get: ["GET /rate_limit"] },
  reactions: {
    createForCommitComment: [
      "POST /repos/{owner}/{repo}/comments/{comment_id}/reactions"
    ],
    createForIssue: [
      "POST /repos/{owner}/{repo}/issues/{issue_number}/reactions"
    ],
    createForIssueComment: [
      "POST /repos/{owner}/{repo}/issues/comments/{comment_id}/reactions"
    ],
    createForPullRequestReviewComment: [
      "POST /repos/{owner}/{repo}/pulls/comments/{comment_id}/reactions"
    ],
    createForRelease: [
      "POST /repos/{owner}/{repo}/releases/{release_id}/reactions"
    ],
    createForTeamDiscussionCommentInOrg: [
      "POST /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}/reactions"
    ],
    createForTeamDiscussionInOrg: [
      "POST /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/reactions"
    ],
    deleteForCommitComment: [
      "DELETE /repos/{owner}/{repo}/comments/{comment_id}/reactions/{reaction_id}"
    ],
    deleteForIssue: [
      "DELETE /repos/{owner}/{repo}/issues/{issue_number}/reactions/{reaction_id}"
    ],
    deleteForIssueComment: [
      "DELETE /repos/{owner}/{repo}/issues/comments/{comment_id}/reactions/{reaction_id}"
    ],
    deleteForPullRequestComment: [
      "DELETE /repos/{owner}/{repo}/pulls/comments/{comment_id}/reactions/{reaction_id}"
    ],
    deleteForRelease: [
      "DELETE /repos/{owner}/{repo}/releases/{release_id}/reactions/{reaction_id}"
    ],
    deleteForTeamDiscussion: [
      "DELETE /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/reactions/{reaction_id}"
    ],
    deleteForTeamDiscussionComment: [
      "DELETE /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}/reactions/{reaction_id}"
    ],
    listForCommitComment: [
      "GET /repos/{owner}/{repo}/comments/{comment_id}/reactions"
    ],
    listForIssue: ["GET /repos/{owner}/{repo}/issues/{issue_number}/reactions"],
    listForIssueComment: [
      "GET /repos/{owner}/{repo}/issues/comments/{comment_id}/reactions"
    ],
    listForPullRequestReviewComment: [
      "GET /repos/{owner}/{repo}/pulls/comments/{comment_id}/reactions"
    ],
    listForRelease: [
      "GET /repos/{owner}/{repo}/releases/{release_id}/reactions"
    ],
    listForTeamDiscussionCommentInOrg: [
      "GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}/reactions"
    ],
    listForTeamDiscussionInOrg: [
      "GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/reactions"
    ]
  },
  repos: {
    acceptInvitation: [
      "PATCH /user/repository_invitations/{invitation_id}",
      {},
      { renamed: ["repos", "acceptInvitationForAuthenticatedUser"] }
    ],
    acceptInvitationForAuthenticatedUser: [
      "PATCH /user/repository_invitations/{invitation_id}"
    ],
    addAppAccessRestrictions: [
      "POST /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/apps",
      {},
      { mapToData: "apps" }
    ],
    addCollaborator: ["PUT /repos/{owner}/{repo}/collaborators/{username}"],
    addStatusCheckContexts: [
      "POST /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks/contexts",
      {},
      { mapToData: "contexts" }
    ],
    addTeamAccessRestrictions: [
      "POST /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/teams",
      {},
      { mapToData: "teams" }
    ],
    addUserAccessRestrictions: [
      "POST /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/users",
      {},
      { mapToData: "users" }
    ],
    cancelPagesDeployment: [
      "POST /repos/{owner}/{repo}/pages/deployments/{pages_deployment_id}/cancel"
    ],
    checkAutomatedSecurityFixes: [
      "GET /repos/{owner}/{repo}/automated-security-fixes"
    ],
    checkCollaborator: ["GET /repos/{owner}/{repo}/collaborators/{username}"],
    checkImmutableReleases: ["GET /repos/{owner}/{repo}/immutable-releases"],
    checkPrivateVulnerabilityReporting: [
      "GET /repos/{owner}/{repo}/private-vulnerability-reporting"
    ],
    checkVulnerabilityAlerts: [
      "GET /repos/{owner}/{repo}/vulnerability-alerts"
    ],
    codeownersErrors: ["GET /repos/{owner}/{repo}/codeowners/errors"],
    compareCommits: ["GET /repos/{owner}/{repo}/compare/{base}...{head}"],
    compareCommitsWithBasehead: [
      "GET /repos/{owner}/{repo}/compare/{basehead}"
    ],
    createAttestation: ["POST /repos/{owner}/{repo}/attestations"],
    createAutolink: ["POST /repos/{owner}/{repo}/autolinks"],
    createCommitComment: [
      "POST /repos/{owner}/{repo}/commits/{commit_sha}/comments"
    ],
    createCommitSignatureProtection: [
      "POST /repos/{owner}/{repo}/branches/{branch}/protection/required_signatures"
    ],
    createCommitStatus: ["POST /repos/{owner}/{repo}/statuses/{sha}"],
    createDeployKey: ["POST /repos/{owner}/{repo}/keys"],
    createDeployment: ["POST /repos/{owner}/{repo}/deployments"],
    createDeploymentBranchPolicy: [
      "POST /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies"
    ],
    createDeploymentProtectionRule: [
      "POST /repos/{owner}/{repo}/environments/{environment_name}/deployment_protection_rules"
    ],
    createDeploymentStatus: [
      "POST /repos/{owner}/{repo}/deployments/{deployment_id}/statuses"
    ],
    createDispatchEvent: ["POST /repos/{owner}/{repo}/dispatches"],
    createForAuthenticatedUser: ["POST /user/repos"],
    createFork: ["POST /repos/{owner}/{repo}/forks"],
    createInOrg: ["POST /orgs/{org}/repos"],
    createOrUpdateEnvironment: [
      "PUT /repos/{owner}/{repo}/environments/{environment_name}"
    ],
    createOrUpdateFileContents: ["PUT /repos/{owner}/{repo}/contents/{path}"],
    createOrgRuleset: ["POST /orgs/{org}/rulesets"],
    createPagesDeployment: ["POST /repos/{owner}/{repo}/pages/deployments"],
    createPagesSite: ["POST /repos/{owner}/{repo}/pages"],
    createRelease: ["POST /repos/{owner}/{repo}/releases"],
    createRepoRuleset: ["POST /repos/{owner}/{repo}/rulesets"],
    createUsingTemplate: [
      "POST /repos/{template_owner}/{template_repo}/generate"
    ],
    createWebhook: ["POST /repos/{owner}/{repo}/hooks"],
    customPropertiesForReposCreateOrUpdateRepositoryValues: [
      "PATCH /repos/{owner}/{repo}/properties/values"
    ],
    customPropertiesForReposGetRepositoryValues: [
      "GET /repos/{owner}/{repo}/properties/values"
    ],
    declineInvitation: [
      "DELETE /user/repository_invitations/{invitation_id}",
      {},
      { renamed: ["repos", "declineInvitationForAuthenticatedUser"] }
    ],
    declineInvitationForAuthenticatedUser: [
      "DELETE /user/repository_invitations/{invitation_id}"
    ],
    delete: ["DELETE /repos/{owner}/{repo}"],
    deleteAccessRestrictions: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/restrictions"
    ],
    deleteAdminBranchProtection: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/enforce_admins"
    ],
    deleteAnEnvironment: [
      "DELETE /repos/{owner}/{repo}/environments/{environment_name}"
    ],
    deleteAutolink: ["DELETE /repos/{owner}/{repo}/autolinks/{autolink_id}"],
    deleteBranchProtection: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection"
    ],
    deleteCommitComment: ["DELETE /repos/{owner}/{repo}/comments/{comment_id}"],
    deleteCommitSignatureProtection: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/required_signatures"
    ],
    deleteDeployKey: ["DELETE /repos/{owner}/{repo}/keys/{key_id}"],
    deleteDeployment: [
      "DELETE /repos/{owner}/{repo}/deployments/{deployment_id}"
    ],
    deleteDeploymentBranchPolicy: [
      "DELETE /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies/{branch_policy_id}"
    ],
    deleteFile: ["DELETE /repos/{owner}/{repo}/contents/{path}"],
    deleteInvitation: [
      "DELETE /repos/{owner}/{repo}/invitations/{invitation_id}"
    ],
    deleteOrgRuleset: ["DELETE /orgs/{org}/rulesets/{ruleset_id}"],
    deletePagesSite: ["DELETE /repos/{owner}/{repo}/pages"],
    deletePullRequestReviewProtection: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/required_pull_request_reviews"
    ],
    deleteRelease: ["DELETE /repos/{owner}/{repo}/releases/{release_id}"],
    deleteReleaseAsset: [
      "DELETE /repos/{owner}/{repo}/releases/assets/{asset_id}"
    ],
    deleteRepoRuleset: ["DELETE /repos/{owner}/{repo}/rulesets/{ruleset_id}"],
    deleteWebhook: ["DELETE /repos/{owner}/{repo}/hooks/{hook_id}"],
    disableAutomatedSecurityFixes: [
      "DELETE /repos/{owner}/{repo}/automated-security-fixes"
    ],
    disableDeploymentProtectionRule: [
      "DELETE /repos/{owner}/{repo}/environments/{environment_name}/deployment_protection_rules/{protection_rule_id}"
    ],
    disableImmutableReleases: [
      "DELETE /repos/{owner}/{repo}/immutable-releases"
    ],
    disablePrivateVulnerabilityReporting: [
      "DELETE /repos/{owner}/{repo}/private-vulnerability-reporting"
    ],
    disableVulnerabilityAlerts: [
      "DELETE /repos/{owner}/{repo}/vulnerability-alerts"
    ],
    downloadArchive: [
      "GET /repos/{owner}/{repo}/zipball/{ref}",
      {},
      { renamed: ["repos", "downloadZipballArchive"] }
    ],
    downloadTarballArchive: ["GET /repos/{owner}/{repo}/tarball/{ref}"],
    downloadZipballArchive: ["GET /repos/{owner}/{repo}/zipball/{ref}"],
    enableAutomatedSecurityFixes: [
      "PUT /repos/{owner}/{repo}/automated-security-fixes"
    ],
    enableImmutableReleases: ["PUT /repos/{owner}/{repo}/immutable-releases"],
    enablePrivateVulnerabilityReporting: [
      "PUT /repos/{owner}/{repo}/private-vulnerability-reporting"
    ],
    enableVulnerabilityAlerts: [
      "PUT /repos/{owner}/{repo}/vulnerability-alerts"
    ],
    generateReleaseNotes: [
      "POST /repos/{owner}/{repo}/releases/generate-notes"
    ],
    get: ["GET /repos/{owner}/{repo}"],
    getAccessRestrictions: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection/restrictions"
    ],
    getAdminBranchProtection: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection/enforce_admins"
    ],
    getAllDeploymentProtectionRules: [
      "GET /repos/{owner}/{repo}/environments/{environment_name}/deployment_protection_rules"
    ],
    getAllEnvironments: ["GET /repos/{owner}/{repo}/environments"],
    getAllStatusCheckContexts: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks/contexts"
    ],
    getAllTopics: ["GET /repos/{owner}/{repo}/topics"],
    getAppsWithAccessToProtectedBranch: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/apps"
    ],
    getAutolink: ["GET /repos/{owner}/{repo}/autolinks/{autolink_id}"],
    getBranch: ["GET /repos/{owner}/{repo}/branches/{branch}"],
    getBranchProtection: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection"
    ],
    getBranchRules: ["GET /repos/{owner}/{repo}/rules/branches/{branch}"],
    getClones: ["GET /repos/{owner}/{repo}/traffic/clones"],
    getCodeFrequencyStats: ["GET /repos/{owner}/{repo}/stats/code_frequency"],
    getCollaboratorPermissionLevel: [
      "GET /repos/{owner}/{repo}/collaborators/{username}/permission"
    ],
    getCombinedStatusForRef: ["GET /repos/{owner}/{repo}/commits/{ref}/status"],
    getCommit: ["GET /repos/{owner}/{repo}/commits/{ref}"],
    getCommitActivityStats: ["GET /repos/{owner}/{repo}/stats/commit_activity"],
    getCommitComment: ["GET /repos/{owner}/{repo}/comments/{comment_id}"],
    getCommitSignatureProtection: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection/required_signatures"
    ],
    getCommunityProfileMetrics: ["GET /repos/{owner}/{repo}/community/profile"],
    getContent: ["GET /repos/{owner}/{repo}/contents/{path}"],
    getContributorsStats: ["GET /repos/{owner}/{repo}/stats/contributors"],
    getCustomDeploymentProtectionRule: [
      "GET /repos/{owner}/{repo}/environments/{environment_name}/deployment_protection_rules/{protection_rule_id}"
    ],
    getDeployKey: ["GET /repos/{owner}/{repo}/keys/{key_id}"],
    getDeployment: ["GET /repos/{owner}/{repo}/deployments/{deployment_id}"],
    getDeploymentBranchPolicy: [
      "GET /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies/{branch_policy_id}"
    ],
    getDeploymentStatus: [
      "GET /repos/{owner}/{repo}/deployments/{deployment_id}/statuses/{status_id}"
    ],
    getEnvironment: [
      "GET /repos/{owner}/{repo}/environments/{environment_name}"
    ],
    getLatestPagesBuild: ["GET /repos/{owner}/{repo}/pages/builds/latest"],
    getLatestRelease: ["GET /repos/{owner}/{repo}/releases/latest"],
    getOrgRuleSuite: ["GET /orgs/{org}/rulesets/rule-suites/{rule_suite_id}"],
    getOrgRuleSuites: ["GET /orgs/{org}/rulesets/rule-suites"],
    getOrgRuleset: ["GET /orgs/{org}/rulesets/{ruleset_id}"],
    getOrgRulesets: ["GET /orgs/{org}/rulesets"],
    getPages: ["GET /repos/{owner}/{repo}/pages"],
    getPagesBuild: ["GET /repos/{owner}/{repo}/pages/builds/{build_id}"],
    getPagesDeployment: [
      "GET /repos/{owner}/{repo}/pages/deployments/{pages_deployment_id}"
    ],
    getPagesHealthCheck: ["GET /repos/{owner}/{repo}/pages/health"],
    getParticipationStats: ["GET /repos/{owner}/{repo}/stats/participation"],
    getPullRequestReviewProtection: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection/required_pull_request_reviews"
    ],
    getPunchCardStats: ["GET /repos/{owner}/{repo}/stats/punch_card"],
    getReadme: ["GET /repos/{owner}/{repo}/readme"],
    getReadmeInDirectory: ["GET /repos/{owner}/{repo}/readme/{dir}"],
    getRelease: ["GET /repos/{owner}/{repo}/releases/{release_id}"],
    getReleaseAsset: ["GET /repos/{owner}/{repo}/releases/assets/{asset_id}"],
    getReleaseByTag: ["GET /repos/{owner}/{repo}/releases/tags/{tag}"],
    getRepoRuleSuite: [
      "GET /repos/{owner}/{repo}/rulesets/rule-suites/{rule_suite_id}"
    ],
    getRepoRuleSuites: ["GET /repos/{owner}/{repo}/rulesets/rule-suites"],
    getRepoRuleset: ["GET /repos/{owner}/{repo}/rulesets/{ruleset_id}"],
    getRepoRulesetHistory: [
      "GET /repos/{owner}/{repo}/rulesets/{ruleset_id}/history"
    ],
    getRepoRulesetVersion: [
      "GET /repos/{owner}/{repo}/rulesets/{ruleset_id}/history/{version_id}"
    ],
    getRepoRulesets: ["GET /repos/{owner}/{repo}/rulesets"],
    getStatusChecksProtection: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks"
    ],
    getTeamsWithAccessToProtectedBranch: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/teams"
    ],
    getTopPaths: ["GET /repos/{owner}/{repo}/traffic/popular/paths"],
    getTopReferrers: ["GET /repos/{owner}/{repo}/traffic/popular/referrers"],
    getUsersWithAccessToProtectedBranch: [
      "GET /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/users"
    ],
    getViews: ["GET /repos/{owner}/{repo}/traffic/views"],
    getWebhook: ["GET /repos/{owner}/{repo}/hooks/{hook_id}"],
    getWebhookConfigForRepo: [
      "GET /repos/{owner}/{repo}/hooks/{hook_id}/config"
    ],
    getWebhookDelivery: [
      "GET /repos/{owner}/{repo}/hooks/{hook_id}/deliveries/{delivery_id}"
    ],
    listActivities: ["GET /repos/{owner}/{repo}/activity"],
    listAttestations: [
      "GET /repos/{owner}/{repo}/attestations/{subject_digest}"
    ],
    listAutolinks: ["GET /repos/{owner}/{repo}/autolinks"],
    listBranches: ["GET /repos/{owner}/{repo}/branches"],
    listBranchesForHeadCommit: [
      "GET /repos/{owner}/{repo}/commits/{commit_sha}/branches-where-head"
    ],
    listCollaborators: ["GET /repos/{owner}/{repo}/collaborators"],
    listCommentsForCommit: [
      "GET /repos/{owner}/{repo}/commits/{commit_sha}/comments"
    ],
    listCommitCommentsForRepo: ["GET /repos/{owner}/{repo}/comments"],
    listCommitStatusesForRef: [
      "GET /repos/{owner}/{repo}/commits/{ref}/statuses"
    ],
    listCommits: ["GET /repos/{owner}/{repo}/commits"],
    listContributors: ["GET /repos/{owner}/{repo}/contributors"],
    listCustomDeploymentRuleIntegrations: [
      "GET /repos/{owner}/{repo}/environments/{environment_name}/deployment_protection_rules/apps"
    ],
    listDeployKeys: ["GET /repos/{owner}/{repo}/keys"],
    listDeploymentBranchPolicies: [
      "GET /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies"
    ],
    listDeploymentStatuses: [
      "GET /repos/{owner}/{repo}/deployments/{deployment_id}/statuses"
    ],
    listDeployments: ["GET /repos/{owner}/{repo}/deployments"],
    listForAuthenticatedUser: ["GET /user/repos"],
    listForOrg: ["GET /orgs/{org}/repos"],
    listForUser: ["GET /users/{username}/repos"],
    listForks: ["GET /repos/{owner}/{repo}/forks"],
    listInvitations: ["GET /repos/{owner}/{repo}/invitations"],
    listInvitationsForAuthenticatedUser: ["GET /user/repository_invitations"],
    listLanguages: ["GET /repos/{owner}/{repo}/languages"],
    listPagesBuilds: ["GET /repos/{owner}/{repo}/pages/builds"],
    listPublic: ["GET /repositories"],
    listPullRequestsAssociatedWithCommit: [
      "GET /repos/{owner}/{repo}/commits/{commit_sha}/pulls"
    ],
    listReleaseAssets: [
      "GET /repos/{owner}/{repo}/releases/{release_id}/assets"
    ],
    listReleases: ["GET /repos/{owner}/{repo}/releases"],
    listTags: ["GET /repos/{owner}/{repo}/tags"],
    listTeams: ["GET /repos/{owner}/{repo}/teams"],
    listWebhookDeliveries: [
      "GET /repos/{owner}/{repo}/hooks/{hook_id}/deliveries"
    ],
    listWebhooks: ["GET /repos/{owner}/{repo}/hooks"],
    merge: ["POST /repos/{owner}/{repo}/merges"],
    mergeUpstream: ["POST /repos/{owner}/{repo}/merge-upstream"],
    pingWebhook: ["POST /repos/{owner}/{repo}/hooks/{hook_id}/pings"],
    redeliverWebhookDelivery: [
      "POST /repos/{owner}/{repo}/hooks/{hook_id}/deliveries/{delivery_id}/attempts"
    ],
    removeAppAccessRestrictions: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/apps",
      {},
      { mapToData: "apps" }
    ],
    removeCollaborator: [
      "DELETE /repos/{owner}/{repo}/collaborators/{username}"
    ],
    removeStatusCheckContexts: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks/contexts",
      {},
      { mapToData: "contexts" }
    ],
    removeStatusCheckProtection: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks"
    ],
    removeTeamAccessRestrictions: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/teams",
      {},
      { mapToData: "teams" }
    ],
    removeUserAccessRestrictions: [
      "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/users",
      {},
      { mapToData: "users" }
    ],
    renameBranch: ["POST /repos/{owner}/{repo}/branches/{branch}/rename"],
    replaceAllTopics: ["PUT /repos/{owner}/{repo}/topics"],
    requestPagesBuild: ["POST /repos/{owner}/{repo}/pages/builds"],
    setAdminBranchProtection: [
      "POST /repos/{owner}/{repo}/branches/{branch}/protection/enforce_admins"
    ],
    setAppAccessRestrictions: [
      "PUT /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/apps",
      {},
      { mapToData: "apps" }
    ],
    setStatusCheckContexts: [
      "PUT /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks/contexts",
      {},
      { mapToData: "contexts" }
    ],
    setTeamAccessRestrictions: [
      "PUT /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/teams",
      {},
      { mapToData: "teams" }
    ],
    setUserAccessRestrictions: [
      "PUT /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/users",
      {},
      { mapToData: "users" }
    ],
    testPushWebhook: ["POST /repos/{owner}/{repo}/hooks/{hook_id}/tests"],
    transfer: ["POST /repos/{owner}/{repo}/transfer"],
    update: ["PATCH /repos/{owner}/{repo}"],
    updateBranchProtection: [
      "PUT /repos/{owner}/{repo}/branches/{branch}/protection"
    ],
    updateCommitComment: ["PATCH /repos/{owner}/{repo}/comments/{comment_id}"],
    updateDeploymentBranchPolicy: [
      "PUT /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies/{branch_policy_id}"
    ],
    updateInformationAboutPagesSite: ["PUT /repos/{owner}/{repo}/pages"],
    updateInvitation: [
      "PATCH /repos/{owner}/{repo}/invitations/{invitation_id}"
    ],
    updateOrgRuleset: ["PUT /orgs/{org}/rulesets/{ruleset_id}"],
    updatePullRequestReviewProtection: [
      "PATCH /repos/{owner}/{repo}/branches/{branch}/protection/required_pull_request_reviews"
    ],
    updateRelease: ["PATCH /repos/{owner}/{repo}/releases/{release_id}"],
    updateReleaseAsset: [
      "PATCH /repos/{owner}/{repo}/releases/assets/{asset_id}"
    ],
    updateRepoRuleset: ["PUT /repos/{owner}/{repo}/rulesets/{ruleset_id}"],
    updateStatusCheckPotection: [
      "PATCH /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks",
      {},
      { renamed: ["repos", "updateStatusCheckProtection"] }
    ],
    updateStatusCheckProtection: [
      "PATCH /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks"
    ],
    updateWebhook: ["PATCH /repos/{owner}/{repo}/hooks/{hook_id}"],
    updateWebhookConfigForRepo: [
      "PATCH /repos/{owner}/{repo}/hooks/{hook_id}/config"
    ],
    uploadReleaseAsset: [
      "POST /repos/{owner}/{repo}/releases/{release_id}/assets{?name,label}",
      { baseUrl: "https://uploads.github.com" }
    ]
  },
  search: {
    code: ["GET /search/code"],
    commits: ["GET /search/commits"],
    issuesAndPullRequests: ["GET /search/issues"],
    labels: ["GET /search/labels"],
    repos: ["GET /search/repositories"],
    topics: ["GET /search/topics"],
    users: ["GET /search/users"]
  },
  secretScanning: {
    createPushProtectionBypass: [
      "POST /repos/{owner}/{repo}/secret-scanning/push-protection-bypasses"
    ],
    getAlert: [
      "GET /repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}"
    ],
    getScanHistory: ["GET /repos/{owner}/{repo}/secret-scanning/scan-history"],
    listAlertsForOrg: ["GET /orgs/{org}/secret-scanning/alerts"],
    listAlertsForRepo: ["GET /repos/{owner}/{repo}/secret-scanning/alerts"],
    listLocationsForAlert: [
      "GET /repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}/locations"
    ],
    listOrgPatternConfigs: [
      "GET /orgs/{org}/secret-scanning/pattern-configurations"
    ],
    updateAlert: [
      "PATCH /repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}"
    ],
    updateOrgPatternConfigs: [
      "PATCH /orgs/{org}/secret-scanning/pattern-configurations"
    ]
  },
  securityAdvisories: {
    createFork: [
      "POST /repos/{owner}/{repo}/security-advisories/{ghsa_id}/forks"
    ],
    createPrivateVulnerabilityReport: [
      "POST /repos/{owner}/{repo}/security-advisories/reports"
    ],
    createRepositoryAdvisory: [
      "POST /repos/{owner}/{repo}/security-advisories"
    ],
    createRepositoryAdvisoryCveRequest: [
      "POST /repos/{owner}/{repo}/security-advisories/{ghsa_id}/cve"
    ],
    getGlobalAdvisory: ["GET /advisories/{ghsa_id}"],
    getRepositoryAdvisory: [
      "GET /repos/{owner}/{repo}/security-advisories/{ghsa_id}"
    ],
    listGlobalAdvisories: ["GET /advisories"],
    listOrgRepositoryAdvisories: ["GET /orgs/{org}/security-advisories"],
    listRepositoryAdvisories: ["GET /repos/{owner}/{repo}/security-advisories"],
    updateRepositoryAdvisory: [
      "PATCH /repos/{owner}/{repo}/security-advisories/{ghsa_id}"
    ]
  },
  teams: {
    addOrUpdateMembershipForUserInOrg: [
      "PUT /orgs/{org}/teams/{team_slug}/memberships/{username}"
    ],
    addOrUpdateRepoPermissionsInOrg: [
      "PUT /orgs/{org}/teams/{team_slug}/repos/{owner}/{repo}"
    ],
    checkPermissionsForRepoInOrg: [
      "GET /orgs/{org}/teams/{team_slug}/repos/{owner}/{repo}"
    ],
    create: ["POST /orgs/{org}/teams"],
    createDiscussionCommentInOrg: [
      "POST /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments"
    ],
    createDiscussionInOrg: ["POST /orgs/{org}/teams/{team_slug}/discussions"],
    deleteDiscussionCommentInOrg: [
      "DELETE /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}"
    ],
    deleteDiscussionInOrg: [
      "DELETE /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}"
    ],
    deleteInOrg: ["DELETE /orgs/{org}/teams/{team_slug}"],
    getByName: ["GET /orgs/{org}/teams/{team_slug}"],
    getDiscussionCommentInOrg: [
      "GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}"
    ],
    getDiscussionInOrg: [
      "GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}"
    ],
    getMembershipForUserInOrg: [
      "GET /orgs/{org}/teams/{team_slug}/memberships/{username}"
    ],
    list: ["GET /orgs/{org}/teams"],
    listChildInOrg: ["GET /orgs/{org}/teams/{team_slug}/teams"],
    listDiscussionCommentsInOrg: [
      "GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments"
    ],
    listDiscussionsInOrg: ["GET /orgs/{org}/teams/{team_slug}/discussions"],
    listForAuthenticatedUser: ["GET /user/teams"],
    listMembersInOrg: ["GET /orgs/{org}/teams/{team_slug}/members"],
    listPendingInvitationsInOrg: [
      "GET /orgs/{org}/teams/{team_slug}/invitations"
    ],
    listReposInOrg: ["GET /orgs/{org}/teams/{team_slug}/repos"],
    removeMembershipForUserInOrg: [
      "DELETE /orgs/{org}/teams/{team_slug}/memberships/{username}"
    ],
    removeRepoInOrg: [
      "DELETE /orgs/{org}/teams/{team_slug}/repos/{owner}/{repo}"
    ],
    updateDiscussionCommentInOrg: [
      "PATCH /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}"
    ],
    updateDiscussionInOrg: [
      "PATCH /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}"
    ],
    updateInOrg: ["PATCH /orgs/{org}/teams/{team_slug}"]
  },
  users: {
    addEmailForAuthenticated: [
      "POST /user/emails",
      {},
      { renamed: ["users", "addEmailForAuthenticatedUser"] }
    ],
    addEmailForAuthenticatedUser: ["POST /user/emails"],
    addSocialAccountForAuthenticatedUser: ["POST /user/social_accounts"],
    block: ["PUT /user/blocks/{username}"],
    checkBlocked: ["GET /user/blocks/{username}"],
    checkFollowingForUser: ["GET /users/{username}/following/{target_user}"],
    checkPersonIsFollowedByAuthenticated: ["GET /user/following/{username}"],
    createGpgKeyForAuthenticated: [
      "POST /user/gpg_keys",
      {},
      { renamed: ["users", "createGpgKeyForAuthenticatedUser"] }
    ],
    createGpgKeyForAuthenticatedUser: ["POST /user/gpg_keys"],
    createPublicSshKeyForAuthenticated: [
      "POST /user/keys",
      {},
      { renamed: ["users", "createPublicSshKeyForAuthenticatedUser"] }
    ],
    createPublicSshKeyForAuthenticatedUser: ["POST /user/keys"],
    createSshSigningKeyForAuthenticatedUser: ["POST /user/ssh_signing_keys"],
    deleteAttestationsBulk: [
      "POST /users/{username}/attestations/delete-request"
    ],
    deleteAttestationsById: [
      "DELETE /users/{username}/attestations/{attestation_id}"
    ],
    deleteAttestationsBySubjectDigest: [
      "DELETE /users/{username}/attestations/digest/{subject_digest}"
    ],
    deleteEmailForAuthenticated: [
      "DELETE /user/emails",
      {},
      { renamed: ["users", "deleteEmailForAuthenticatedUser"] }
    ],
    deleteEmailForAuthenticatedUser: ["DELETE /user/emails"],
    deleteGpgKeyForAuthenticated: [
      "DELETE /user/gpg_keys/{gpg_key_id}",
      {},
      { renamed: ["users", "deleteGpgKeyForAuthenticatedUser"] }
    ],
    deleteGpgKeyForAuthenticatedUser: ["DELETE /user/gpg_keys/{gpg_key_id}"],
    deletePublicSshKeyForAuthenticated: [
      "DELETE /user/keys/{key_id}",
      {},
      { renamed: ["users", "deletePublicSshKeyForAuthenticatedUser"] }
    ],
    deletePublicSshKeyForAuthenticatedUser: ["DELETE /user/keys/{key_id}"],
    deleteSocialAccountForAuthenticatedUser: ["DELETE /user/social_accounts"],
    deleteSshSigningKeyForAuthenticatedUser: [
      "DELETE /user/ssh_signing_keys/{ssh_signing_key_id}"
    ],
    follow: ["PUT /user/following/{username}"],
    getAuthenticated: ["GET /user"],
    getById: ["GET /user/{account_id}"],
    getByUsername: ["GET /users/{username}"],
    getContextForUser: ["GET /users/{username}/hovercard"],
    getGpgKeyForAuthenticated: [
      "GET /user/gpg_keys/{gpg_key_id}",
      {},
      { renamed: ["users", "getGpgKeyForAuthenticatedUser"] }
    ],
    getGpgKeyForAuthenticatedUser: ["GET /user/gpg_keys/{gpg_key_id}"],
    getPublicSshKeyForAuthenticated: [
      "GET /user/keys/{key_id}",
      {},
      { renamed: ["users", "getPublicSshKeyForAuthenticatedUser"] }
    ],
    getPublicSshKeyForAuthenticatedUser: ["GET /user/keys/{key_id}"],
    getSshSigningKeyForAuthenticatedUser: [
      "GET /user/ssh_signing_keys/{ssh_signing_key_id}"
    ],
    list: ["GET /users"],
    listAttestations: ["GET /users/{username}/attestations/{subject_digest}"],
    listAttestationsBulk: [
      "POST /users/{username}/attestations/bulk-list{?per_page,before,after}"
    ],
    listBlockedByAuthenticated: [
      "GET /user/blocks",
      {},
      { renamed: ["users", "listBlockedByAuthenticatedUser"] }
    ],
    listBlockedByAuthenticatedUser: ["GET /user/blocks"],
    listEmailsForAuthenticated: [
      "GET /user/emails",
      {},
      { renamed: ["users", "listEmailsForAuthenticatedUser"] }
    ],
    listEmailsForAuthenticatedUser: ["GET /user/emails"],
    listFollowedByAuthenticated: [
      "GET /user/following",
      {},
      { renamed: ["users", "listFollowedByAuthenticatedUser"] }
    ],
    listFollowedByAuthenticatedUser: ["GET /user/following"],
    listFollowersForAuthenticatedUser: ["GET /user/followers"],
    listFollowersForUser: ["GET /users/{username}/followers"],
    listFollowingForUser: ["GET /users/{username}/following"],
    listGpgKeysForAuthenticated: [
      "GET /user/gpg_keys",
      {},
      { renamed: ["users", "listGpgKeysForAuthenticatedUser"] }
    ],
    listGpgKeysForAuthenticatedUser: ["GET /user/gpg_keys"],
    listGpgKeysForUser: ["GET /users/{username}/gpg_keys"],
    listPublicEmailsForAuthenticated: [
      "GET /user/public_emails",
      {},
      { renamed: ["users", "listPublicEmailsForAuthenticatedUser"] }
    ],
    listPublicEmailsForAuthenticatedUser: ["GET /user/public_emails"],
    listPublicKeysForUser: ["GET /users/{username}/keys"],
    listPublicSshKeysForAuthenticated: [
      "GET /user/keys",
      {},
      { renamed: ["users", "listPublicSshKeysForAuthenticatedUser"] }
    ],
    listPublicSshKeysForAuthenticatedUser: ["GET /user/keys"],
    listSocialAccountsForAuthenticatedUser: ["GET /user/social_accounts"],
    listSocialAccountsForUser: ["GET /users/{username}/social_accounts"],
    listSshSigningKeysForAuthenticatedUser: ["GET /user/ssh_signing_keys"],
    listSshSigningKeysForUser: ["GET /users/{username}/ssh_signing_keys"],
    setPrimaryEmailVisibilityForAuthenticated: [
      "PATCH /user/email/visibility",
      {},
      { renamed: ["users", "setPrimaryEmailVisibilityForAuthenticatedUser"] }
    ],
    setPrimaryEmailVisibilityForAuthenticatedUser: [
      "PATCH /user/email/visibility"
    ],
    unblock: ["DELETE /user/blocks/{username}"],
    unfollow: ["DELETE /user/following/{username}"],
    updateAuthenticated: ["PATCH /user"]
  }
};
var Kc = Zc;
const hA = /* @__PURE__ */ new Map();
for (const [e, r] of Object.entries(Kc))
  for (const [t, o] of Object.entries(r)) {
    const [A, n, c] = o, [g, Q] = A.split(/ /), B = Object.assign(
      {
        method: g,
        url: Q
      },
      n
    );
    hA.has(e) || hA.set(e, /* @__PURE__ */ new Map()), hA.get(e).set(t, {
      scope: e,
      methodName: t,
      endpointDefaults: B,
      decorations: c
    });
  }
const Xc = {
  has({ scope: e }, r) {
    return hA.get(e).has(r);
  },
  getOwnPropertyDescriptor(e, r) {
    return {
      value: this.get(e, r),
      // ensures method is in the cache
      configurable: !0,
      writable: !0,
      enumerable: !0
    };
  },
  defineProperty(e, r, t) {
    return Object.defineProperty(e.cache, r, t), !0;
  },
  deleteProperty(e, r) {
    return delete e.cache[r], !0;
  },
  ownKeys({ scope: e }) {
    return [...hA.get(e).keys()];
  },
  set(e, r, t) {
    return e.cache[r] = t;
  },
  get({ octokit: e, scope: r, cache: t }, o) {
    if (t[o])
      return t[o];
    const A = hA.get(r).get(o);
    if (!A)
      return;
    const { endpointDefaults: n, decorations: c } = A;
    return c ? t[o] = $c(
      e,
      r,
      o,
      n,
      c
    ) : t[o] = e.request.defaults(n), t[o];
  }
};
function jc(e) {
  const r = {};
  for (const t of hA.keys())
    r[t] = new Proxy({ octokit: e, scope: t, cache: {} }, Xc);
  return r;
}
function $c(e, r, t, o, A) {
  const n = e.request.defaults(o);
  function c(...g) {
    let Q = n.endpoint.merge(...g);
    if (A.mapToData)
      return Q = Object.assign({}, Q, {
        data: Q[A.mapToData],
        [A.mapToData]: void 0
      }), n(Q);
    if (A.renamed) {
      const [B, i] = A.renamed;
      e.log.warn(
        `octokit.${r}.${t}() has been renamed to octokit.${B}.${i}()`
      );
    }
    if (A.deprecated && e.log.warn(A.deprecated), A.renamedParameters) {
      const B = n.endpoint.merge(...g);
      for (const [i, a] of Object.entries(
        A.renamedParameters
      ))
        i in B && (e.log.warn(
          `"${i}" parameter is deprecated for "octokit.${r}.${t}()". Use "${a}" instead`
        ), a in B || (B[a] = B[i]), delete B[i]);
      return n(B);
    }
    return n(...g);
  }
  return Object.assign(c, n);
}
function Ci(e) {
  return {
    rest: jc(e)
  };
}
Ci.VERSION = zc;
var eg = "0.0.0-development";
function Ag(e) {
  if (!e.data)
    return {
      ...e,
      data: []
    };
  if (!(("total_count" in e.data || "total_commits" in e.data) && !("url" in e.data))) return e;
  const t = e.data.incomplete_results, o = e.data.repository_selection, A = e.data.total_count, n = e.data.total_commits;
  delete e.data.incomplete_results, delete e.data.repository_selection, delete e.data.total_count, delete e.data.total_commits;
  const c = Object.keys(e.data)[0], g = e.data[c];
  return e.data = g, typeof t < "u" && (e.data.incomplete_results = t), typeof o < "u" && (e.data.repository_selection = o), e.data.total_count = A, e.data.total_commits = n, e;
}
function Es(e, r, t) {
  const o = typeof r == "function" ? r.endpoint(t) : e.request.endpoint(r, t), A = typeof r == "function" ? r : e.request, n = o.method, c = o.headers;
  let g = o.url;
  return {
    [Symbol.asyncIterator]: () => ({
      async next() {
        if (!g) return { done: !0 };
        try {
          const Q = await A({ method: n, url: g, headers: c }), B = Ag(Q);
          if (g = ((B.headers.link || "").match(
            /<([^<>]+)>;\s*rel="next"/
          ) || [])[1], !g && "total_commits" in B.data) {
            const i = new URL(B.url), a = i.searchParams, h = parseInt(a.get("page") || "1", 10), u = parseInt(a.get("per_page") || "250", 10);
            h * u < B.data.total_commits && (a.set("page", String(h + 1)), g = i.toString());
          }
          return { value: B };
        } catch (Q) {
          if (Q.status !== 409) throw Q;
          return g = "", {
            value: {
              status: 200,
              headers: {},
              data: []
            }
          };
        }
      }
    })
  };
}
function di(e, r, t, o) {
  return typeof t == "function" && (o = t, t = void 0), fi(
    e,
    [],
    Es(e, r, t)[Symbol.asyncIterator](),
    o
  );
}
function fi(e, r, t, o) {
  return t.next().then((A) => {
    if (A.done)
      return r;
    let n = !1;
    function c() {
      n = !0;
    }
    return r = r.concat(
      o ? o(A.value, c) : A.value.data
    ), n ? r : fi(e, r, t, o);
  });
}
Object.assign(di, {
  iterator: Es
});
function pi(e) {
  return {
    paginate: Object.assign(di.bind(null, e), {
      iterator: Es.bind(null, e)
    })
  };
}
pi.VERSION = eg;
new gi();
const Kr = oc(), tg = {
  baseUrl: Kr,
  request: {
    agent: tc(Kr),
    fetch: sc(Kr)
  }
}, rg = qc.plugin(Ci, pi).defaults(tg);
function sg(e, r) {
  const t = Object.assign({}, {}), o = Ac(e, t);
  return o && (t.auth = o), t;
}
const og = new gi();
function ng(e, r, ...t) {
  const o = rg.plugin(...t);
  return new o(sg(e));
}
let Nn;
function cA() {
  return Nn ??= ng(Ga("repo-token")), Nn;
}
let Mn;
function gA() {
  return Mn ??= og.repo, Mn;
}
async function ig(e) {
  await cA().rest.issues.update({
    ...gA(),
    issue_number: e,
    state: "closed"
  }).catch((r) => {
    throw new ci(e, String(r));
  });
}
async function ag(e, r) {
  await cA().rest.issues.createComment({
    ...gA(),
    body: r,
    issue_number: e
  }).catch((t) => {
    throw new Za(e, String(t));
  });
}
async function us(e, r, t) {
  await cA().rest.issues.create({
    ...gA(),
    assignees: t,
    body: r,
    labels: ["wpvc"],
    title: e
  }).catch((o) => {
    throw new Ka(String(o));
  });
}
async function ot() {
  const e = await cA().rest.issues.listForRepo({
    ...gA(),
    creator: "github-actions[bot]",
    labels: "wpvc"
  }).catch((r) => {
    throw new Xa(String(r));
  });
  return e.data.length > 0 ? e.data[0].number : null;
}
async function Qs(e, r, t) {
  const o = await cA().rest.issues.get({ ...gA(), issue_number: e }).catch((A) => {
    throw new za(e, String(A));
  });
  o.data.title === r && o.data.body === t || await cA().rest.issues.update({
    ...gA(),
    body: t,
    issue_number: e,
    title: r
  }).catch((A) => {
    throw new ci(e, String(A));
  });
}
async function cg(e, r, t) {
  const o = await ot(), A = "The plugin hasn't been tested with a beta version of WordPress", n = gg(r, t);
  o !== null ? await Qs(o, A, n) : await us(A, n, e.assignees);
}
function gg(e, r) {
  return `There is an upcoming WordPress version in the **beta** stage that the plugin hasn't been tested with.

**Tested up to:** ${e}
**Beta version:** ${r}

This issue will be closed automatically when the versions match.`;
}
async function lg(e, r, t) {
  const o = await ot(), A = "The plugin hasn't been tested with an upcoming version of WordPress", n = Eg(r, t);
  o !== null ? await Qs(o, A, n) : await us(A, n, e.assignees);
}
function Eg(e, r) {
  return `There is an upcoming WordPress version in the **release candidate** stage that the plugin hasn't been tested with. Please test it and then change the "Tested up to" field in the plugin readme.

**Tested up to:** ${e}
**Upcoming version:** ${r}

This issue will be closed automatically when the versions match.`;
}
async function ug(e, r, t) {
  const o = await ot(), A = "The plugin hasn't been tested with the latest version of WordPress", n = Qg(r, t);
  o !== null ? await Qs(o, A, n) : await us(A, n, e.assignees);
}
function Qg(e, r) {
  return `There is a new WordPress version that the plugin hasn't been tested with. Please test it and then change the "Tested up to" field in the plugin readme.

**Tested up to:** ${e}
**Latest version:** ${r}

This issue will be closed automatically when the versions match.`;
}
class wi extends lA {
  constructor(r) {
    super(`Couldn't get the repository readme. Error message: ${r}`);
  }
}
async function Bg(e) {
  const r = await hg(e);
  for (const t of r.split(/\r?\n/u)) {
    const o = [
      ...t.matchAll(/^[\s]*Tested up to:[\s]*([.\d]+)[\s]*$/gu)
    ];
    if (o.length === 1)
      return o[0][1];
  }
  throw new wi('No "Tested up to:" line found');
}
async function hg(e) {
  const r = e.readme.map(
    async (t) => cA().rest.repos.getContent({ ...gA(), path: t }).then((o) => {
      const A = o.data.content;
      if (A === void 0)
        throw new Error();
      return Buffer.from(A, "base64").toString();
    })
  );
  for (const t of await Promise.allSettled(r))
    if (t.status === "fulfilled")
      return t.value;
  throw new wi(
    "No readme file was found in repo and all usual locations were exhausted."
  );
}
async function Ig() {
  const e = await ot();
  e !== null && (await ag(
    e,
    'The "Tested up to" version in the readme matches the latest version now, closing this issue.'
  ), await ig(e));
}
class _A extends lA {
  constructor(r) {
    r === void 0 ? super("Failed to fetch the latest WordPress version.") : super(
      `Failed to fetch the latest WordPress version. Error message: ${r}`
    );
  }
}
async function Cg() {
  const e = await dg({
    host: "api.wordpress.org",
    path: "/core/version-check/1.7/?channel=beta"
  }).catch((A) => {
    throw new _A(typeof A == "string" ? A : void 0);
  });
  let r = {};
  try {
    r = JSON.parse(e);
  } catch (A) {
    throw new _A(A.message);
  }
  if (r.offers === void 0)
    throw new _A("Couldn't find the latest version");
  const t = r.offers.find(
    (A) => A.response === "upgrade"
  );
  if (t?.current === void 0)
    throw new _A("Couldn't find the latest version");
  const o = r.offers.find(
    (A) => A.response === "development"
  );
  return {
    beta: o?.current !== void 0 && (fg(o.current) || Ln(o.current)) ? Xr(o.current) : null,
    rc: o?.current !== void 0 && Ln(o.current) ? Xr(o.current) : null,
    stable: Xr(t.current)
  };
}
async function dg(e) {
  return new Promise((r, t) => {
    Fi.get(e, (o) => {
      let A = "";
      o.setEncoding("utf8"), o.on("data", (n) => {
        A += n;
      }), o.on("end", () => {
        o.statusCode === 200 ? r(A) : t(
          new Error(
            `A request returned error ${(o.statusCode ?? 0).toString()}.`
          )
        );
      });
    }).on("error", (o) => {
      t(o);
    });
  });
}
function fg(e) {
  const r = e.split("-");
  return r.length >= 2 && r[1].startsWith("beta");
}
function Ln(e) {
  const r = e.split("-");
  return r.length >= 2 && r[1].startsWith("RC");
}
function Xr(e) {
  return e.split("-")[0].split(".").slice(0, 2).join(".");
}
class BA extends lA {
  constructor(r) {
    super(
      `Couldn't get the wordpress-version-checker config file. Error message: ${r}`
    );
  }
}
async function pg() {
  const e = await cA().rest.repos.getContent({
    ...gA(),
    path: ".wordpress-version-checker.json"
  }).catch((o) => {
    if (wg(o) && o.status === 404)
      return null;
    throw new BA(String(o));
  });
  if (e === null)
    return Gn({});
  const r = e.data.content;
  if (r === void 0)
    throw new BA("Failed to decode the file.");
  let t;
  try {
    t = JSON.parse(Buffer.from(r, "base64").toString());
  } catch (o) {
    throw new BA(o.message);
  }
  return Gn(t);
}
function wg(e) {
  return Object.prototype.hasOwnProperty.call(e, "status");
}
function Gn(e) {
  if (typeof e != "object" || e === null)
    throw new BA("Invalid config file.");
  const r = {
    assignees: [],
    channel: "rc",
    readme: [
      "readme.txt",
      "src/readme.txt",
      "plugin/readme.txt",
      "readme.md",
      "src/readme.md",
      "plugin/readme.md"
    ]
  };
  if ("readme" in e)
    if (typeof e.readme == "string")
      r.readme = [e.readme];
    else if (Array.isArray(e.readme) && e.readme.every((t) => typeof t == "string"))
      r.readme = e.readme;
    else
      throw new BA(
        'Invalid config file, the "readme" field should be a string or an array of strings.'
      );
  if ("assignees" in e) {
    if (!Array.isArray(e.assignees) || !e.assignees.every((t) => typeof t == "string"))
      throw new BA(
        'Invalid config file, the "assignees" field should be an array of strings.'
      );
    r.assignees = e.assignees;
  }
  if ("channel" in e) {
    if (typeof e.channel != "string" || !["beta", "rc", "stable"].includes(e.channel))
      throw new BA(
        'Invalid config file, the "channel" field should be one of "beta", "rc" or "stable".'
      );
    r.channel = e.channel;
  }
  return r;
}
async function mg() {
  try {
    const e = await pg(), r = await Bg(e), t = await Cg(), o = e.channel === "beta" ? t.beta : null, A = ["beta", "rc"].includes(e.channel) ? t.rc : null;
    Wr(r, t.stable, "<") ? await ug(e, r, t.stable) : A !== null && Wr(r, A, "<") ? await lg(e, r, A) : o !== null && Wr(r, o, "<") ? await cg(e, r, o) : await Ig();
  } catch (e) {
    va(e.message);
  }
}
mg();
