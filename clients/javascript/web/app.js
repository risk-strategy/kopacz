/**
 * Kopacz Web UI Controller — uses window.Kopacz (../kopacz.js)
 */
(function() {
  "use strict";

  var K = window.Kopacz;
  var concatBytes = K.concatBytes;
  var hexToBytes = K.hexToBytes;
  var textEncode = K.textEncode;
  var textDecode = K.textDecode;
  var Base32 = K.Base32;
  var Header = K.Header;
  var HEADER_SIZE = K.HEADER_SIZE;
  var Carrier = K.Carrier;
  var AEAD = K.AEAD;
  var SHA256 = K.SHA256;
  var CryptoState = K.CryptoState;
  var LZ4 = K.LZ4;
  var fragmentData = K.fragmentData;
  var ReassemblyBuffer = K.ReassemblyBuffer;
  var SendWindow = K.SendWindow;
  var RecvWindow = K.RecvWindow;
  var DoHResolver = K.DoHResolver;
  var TunnelClient = K.TunnelClient;

  function bytesToBase64(bytes) {
    var binary = "";
    for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }

  // Response types (match Python kopacz/apps/web.py)
  var WEB_HEADER = 0x01;
  var WEB_CHUNK = 0x02;
  var WEB_END = 0x03;
  var WEB_FETCH = 0x01;
  var WEB_POST = 0x02;
  var WEB_FETCH_READER = 0x03;
  var WEB_POST_READER = 0x04;
  var APP_WEB = 0x04;

  var _navGen = 0;
  var readerMode = true;
  var imagesEnabled = false;

  function isFontUrl(u) {
    return /\.(?:woff2?|ttf|otf|eot)(?:[?#]|$)/i.test(u);
  }

  function isImageUrl(u) {
    return /\.(?:png|jpe?g|gif|webp|avif|svg|ico|bmp)(?:[?#]|$)/i.test(u);
  }

  function extractResources(html, baseUrl) {
    var stylesheets = [];
    var images = [];
    var seenCss = {};
    var seenImg = {};
    var m;

    var linkRe = /<link[^>]+(?:rel\s*=\s*["']stylesheet["']|as\s*=\s*["']style["'])[^>]*>/gi;
    while ((m = linkRe.exec(html)) !== null && stylesheets.length < 8) {
      var hrefM = m[0].match(/href\s*=\s*["']([^"']+)["']/i);
      if (hrefM) {
        try {
          var resolved = new URL(hrefM[1], baseUrl).href;
          if (!seenCss[resolved]) {
            seenCss[resolved] = true;
            stylesheets.push({ tag: m[0], url: resolved });
          } else {
            stylesheets.push({ tag: m[0], url: resolved, duplicate: true });
          }
        } catch (e) {}
      }
    }

    var styleRe = /<style[^>]*>([\s\S]*?)<\/style>/gi;
    while ((m = styleRe.exec(html)) !== null) {
      var importRe = /@import\s+(?:url\(\s*)?["']([^"']+)["']\s*\)?\s*;?/gi;
      var im;
      while ((im = importRe.exec(m[1])) !== null && stylesheets.length < 12) {
        try {
          var resolvedImp = new URL(im[1], baseUrl).href;
          if (!seenCss[resolvedImp]) {
            seenCss[resolvedImp] = true;
            stylesheets.push({ tag: im[0], url: resolvedImp, isImport: true });
          }
        } catch (e) {}
      }
    }

    var imgRe = /<img[^>]+(?:src|data-src)\s*=\s*["']([^"']+)["'][^>]*>/gi;
    while ((m = imgRe.exec(html)) !== null && images.length < 8) {
      var srcM = m[0].match(/(?:^|[\s"'])src\s*=\s*["']([^"']+)["']/i);
      var dataSrcM = m[0].match(/data-src\s*=\s*["']([^"']+)["']/i);
      var src = (srcM && srcM[1]) || (dataSrcM && dataSrcM[1]);
      if (!src || src.indexOf("data:") === 0 || src.indexOf("blob:") === 0) continue;
      try {
        var resolvedImg = new URL(src, baseUrl).href;
        var origAttr = srcM ? srcM[0].replace(/^[\s"']+/, "") : 'data-src="' + dataSrcM[1] + '"';
        if (!seenImg[origAttr]) {
          seenImg[origAttr] = true;
          images.push({ tag: m[0], attr: origAttr, url: resolvedImg });
        }
      } catch (e) {}
    }

    return { stylesheets: stylesheets, images: images };
  }

  async function fetchResource(url, timeoutMs, navGen) {
    timeoutMs = timeoutMs || 15000;
    var gen = navGen !== undefined ? navGen : _navGen;
    if (gen !== _navGen) throw new Error("navigation cancelled");

    await webProxy.ensureConnected();

    var deadline = Date.now() + timeoutMs;
    var urlBytes = textEncode(url);
    var payload = new Uint8Array(2 + urlBytes.length);
    payload[0] = APP_WEB;
    payload[1] = WEB_FETCH;
    payload.set(urlBytes, 2);

    var status = 0;
    var contentType = "";
    var bodyParts = [];
    var done = false;

    function processChunk(data) {
      if (!data || data.length === 0) return;
      var type = data[0];
      if (type === WEB_HEADER && data.length >= 3) {
        status = (data[1] << 8) | data[2];
        contentType = data.length > 3 ? textDecode(data.subarray(3)) : "";
      } else if (type === WEB_CHUNK && data.length > 1) {
        bodyParts.push(data.subarray(1));
      } else if (type === WEB_END) {
        done = true;
      }
    }

    var immediate = await webProxy.tunnel.send(payload);
    for (var i = 0; i < immediate.length; i++) processChunk(immediate[i]);

    var pollRounds = 0;
    while (!done && pollRounds < 5 && Date.now() < deadline && gen === _navGen) {
      pollRounds++;
      var results = await webProxy.tunnel.pollAll(200, 400, deadline, function() { return gen !== _navGen; });
      for (var j = 0; j < results.length; j++) {
        processChunk(results[j]);
        if (done) break;
      }
      updateQueryCount();
      if (results.length === 0 && !done) break;
    }

    if (!done) {
      webProxy._dirtySession = true;
      if (gen !== _navGen) throw new Error("navigation cancelled");
      if (bodyParts.length === 0) throw new Error("fetch timeout");
    }

    return {
      status: status,
      contentType: contentType,
      body: bodyParts.length > 0 ? concatBytes(bodyParts) : new Uint8Array(0)
    };
  }

  async function inlineCssUrls(css, cssBaseUrl, budget, navGen) {
    if (imagesEnabled) {
      var urlRe = /url\(\s*["']?([^"')]+)["']?\s*\)/gi;
      var matches = [], seen = {}, m;
      while ((m = urlRe.exec(css)) !== null && matches.length < 6) {
        var ref = m[1].trim();
        if (!ref || ref.indexOf("data:") === 0 || ref.indexOf("#") === 0 || isFontUrl(ref)) continue;
        try {
          var resolved = new URL(ref, cssBaseUrl).href;
          if (!seen[ref]) { seen[ref] = true; matches.push({ ref: ref, url: resolved }); }
        } catch (e) {}
      }
      for (var i = 0; i < matches.length && budget.remaining > 0; i++) {
        if (navGen !== undefined && navGen !== _navGen) break;
        try {
          var res = await fetchResource(matches[i].url, 8000, navGen);
          if (res.status < 400 && res.body.length > 0 && res.body.length < 150000 && res.body.length <= budget.remaining) {
            var dataUri = "data:" + (res.contentType || "image/png") + ";base64," + bytesToBase64(res.body);
            css = css.split(matches[i].ref).join(dataUri);
            budget.remaining -= res.body.length;
          }
        } catch (e) {}
      }
    }
    css = css.replace(/url\(\s*["']?(?!data:|blob:|#)([^"')]+)["']?\s*\)/gi, 'url("data:,")');
    return css;
  }

  function buildWombatShim(baseUrl, imgOn) {
    var B = baseUrl.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
    var imgFlag = imgOn ? "true" : "false";
    return "<scr" + "ipt>(function(){" +
      "var B='" + B + "',IMG=" + imgFlag + ";" +
      "var _rid=0,_pending={};" +
      'window.addEventListener("message",function(e){' +
        'if(e.data&&e.data.type==="fetchResp"&&_pending[e.data.id]){' +
          "_pending[e.data.id](e.data);delete _pending[e.data.id];" +
        "}" +
      "});" +
      "function tFetch(url,kind){" +
        "return new Promise(function(ok){" +
          "var id=++_rid;_pending[id]=ok;" +
          "try{url=new URL(url,B).href}catch(x){}" +
          'window.parent.postMessage({type:"shimFetch",id:id,url:url,kind:kind||""},"*");' +
        "});" +
      "}" +
      'document.addEventListener("click",function(e){' +
        "var el=e.target;" +
        'while(el&&el.tagName!=="A"&&el.tagName!=="BUTTON"&&el.tagName!=="INPUT")el=el.parentElement;' +
        "if(!el)return;" +
        'if(el.tagName==="A"&&el.href){' +
          'var url=el.getAttribute("href")||el.href;' +
          'if(url.indexOf("#")===0||url.indexOf("javascript:")===0)return;' +
          "try{url=new URL(url,B).href}catch(x){return}" +
          'if(url.indexOf("http")!==0)return;' +
          "e.preventDefault();e.stopPropagation();" +
          'window.parent.postMessage({type:"navigate",url:url},"*");' +
        "}" +
      "},true);" +
      "function submitForm(form,sub){" +
        "if(!form)return;" +
        'var act=(sub&&sub.getAttribute&&sub.getAttribute("formaction"))||form.getAttribute("action")||B;' +
        "var url;try{url=new URL(act,B).href}catch(x){return}" +
        'if(url.indexOf("http")!==0)return;' +
        'var meth=((sub&&sub.getAttribute&&sub.getAttribute("formmethod"))||form.getAttribute("method")||"GET").toUpperCase();' +
        "var pairs=[],els=form.elements||[];" +
        "for(var i=0;i<els.length;i++){" +
          "var c=els[i];if(!c.name||c.disabled)continue;" +
          'var ct=(c.type||"").toLowerCase();' +
          'if(ct==="file"||ct==="reset"||ct==="button"||ct==="submit"||ct==="image")continue;' +
          'if((ct==="checkbox"||ct==="radio")&&!c.checked)continue;' +
          'pairs.push(encodeURIComponent(c.name)+"="+encodeURIComponent(c.value||""));' +
        "}" +
        'var qs=pairs.join("&");' +
        'if(meth==="POST"){' +
          'window.parent.postMessage({type:"navigate",url:url,method:"POST",body:qs},"*");' +
        "}else{" +
          'try{var u=new URL(url);u.search=qs;url=u.href;}catch(x){url=url+(url.indexOf("?")===-1?"?":"&")+qs;}' +
          'window.parent.postMessage({type:"navigate",url:url,method:"GET"},"*");' +
        "}" +
      "}" +
      'document.addEventListener("submit",function(e){' +
        "e.preventDefault();e.stopPropagation();submitForm(e.target,e.submitter||null);" +
      "},true);" +
    "})()</scr" + "ipt>";
  }

  function stripTagBlocks(html, tagName) {
    var result = "", lower = html.toLowerCase();
    var openTag = "<" + tagName, closeTag = "</" + tagName, pos = 0;
    while (pos < html.length) {
      var start = lower.indexOf(openTag, pos);
      if (start === -1) { result += html.substring(pos); break; }
      var charAfter = lower.charCodeAt(start + openTag.length);
      if (charAfter !== 62 && charAfter !== 32 && charAfter !== 9 && charAfter !== 10 && charAfter !== 13 && charAfter !== 47) {
        result += html.substring(pos, start + 1);
        pos = start + 1;
        continue;
      }
      result += html.substring(pos, start);
      var end = lower.indexOf(closeTag, start + openTag.length);
      if (end === -1) break;
      var gt = html.indexOf(">", end);
      pos = gt !== -1 ? gt + 1 : html.length;
    }
    return result;
  }

  function injectWombatShim(html, baseUrl, extraHeadHtml) {
    var cspMeta = '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; script-src \'unsafe-inline\'; style-src \'unsafe-inline\'; img-src data:; font-src data:; media-src data:; connect-src \'none\'; frame-src \'none\'; form-action \'none\';">';
    var shim = cspMeta + buildWombatShim(baseUrl, imagesEnabled) + (extraHeadHtml || "");
    if (/<head>/i.test(html)) return html.replace(/<head>/i, function(m) { return m + shim; });
    if (/<head\s[^>]*>/i.test(html)) return html.replace(/<head\s[^>]*>/i, function(m) { return m + shim; });
    if (/<html[^>]*>/i.test(html)) return html.replace(/<html[^>]*>/i, function(m) { return m + "<head>" + shim + "</head>"; });
    return shim + html;
  }

  async function fetchAndInlineResources(html, baseUrl, navGen) {
    var gen = navGen !== undefined ? navGen : _navGen;
    var resources = extractResources(html, baseUrl);
    var budget = { remaining: 2 * 1024 * 1024 };

    var cssList = resources.stylesheets;
    var cssTotal = 0;
    for (var i = 0; i < cssList.length; i++) if (!cssList[i].duplicate) cssTotal++;
    var cssIdx = 0;
    for (var c = 0; c < cssList.length && budget.remaining > 0; c++) {
      if (gen !== _navGen) throw new Error("navigation cancelled");
      var item = cssList[c];
      if (item.duplicate) { html = html.replace(item.tag, ""); continue; }
      cssIdx++;
      updateStatus("Loading CSS " + cssIdx + "/" + cssTotal + "...");
      try {
        var res = await fetchResource(item.url, 15000, gen);
        if (res.status < 400 && res.body.length > 0 && res.body.length < 400000 && res.body.length <= budget.remaining) {
          var css = textDecode(res.body);
          budget.remaining -= res.body.length;
          try { css = await inlineCssUrls(css, item.url, budget, gen); } catch (e) {}
          var styleTag = "<st" + "yle>/* " + item.url + " */\n" + css + "</st" + "yle>";
      html = html.replace(item.tag, item.isImport ? ("/* " + item.url + " */\n" + css) : styleTag);
        } else {
          html = html.replace(item.tag, "");
        }
      } catch (e) {
        if (gen !== _navGen) throw e;
        html = html.replace(item.tag, "");
      }
    }

    html = html.replace(/<link[^>]+(?:rel\s*=\s*["']stylesheet["']|as\s*=\s*["']style["'])[^>]*>/gi, "");

    if (imagesEnabled) {
      var imgCount = resources.images.length;
      for (var k = 0; k < imgCount && budget.remaining > 0; k++) {
        if (gen !== _navGen) throw new Error("navigation cancelled");
        updateStatus("Loading image " + (k + 1) + "/" + imgCount + "...");
        try {
          var imgRes = await fetchResource(resources.images[k].url, 12000, gen);
          if (imgRes.status < 400 && imgRes.body.length > 0 && imgRes.body.length < 300000 && imgRes.body.length <= budget.remaining) {
            var dataUri = "data:" + (imgRes.contentType || "image/png") + ";base64," + bytesToBase64(imgRes.body);
            html = html.replace(resources.images[k].attr, 'src="' + dataUri + '"');
            budget.remaining -= imgRes.body.length;
          }
        } catch (e) {
          if (gen !== _navGen) throw e;
        }
      }
    }

    html = stripTagBlocks(html, "script");
    html = stripTagBlocks(html, "noscript");
    html = html.replace(/<meta[^>]*http-equiv\s*=\s*["']refresh["'][^>]*>/gi, "");
    html = html.replace(/<base[^>]*>/gi, "");
    html = html.replace(/\ssrcset\s*=\s*["'][^"']*["']/gi, "");
    html = html.replace(/\sdata-src\s*=\s*["'][^"']*["']/gi, "");

    var extraHead = "";
    if (!imagesEnabled) {
      html = html.replace(/(<img[^>]*?\s)src\s*=\s*["'](?!data:)[^"']*["']/gi, '$1src="data:,"');
      html = html.replace(/background(?:-image)?\s*:\s*url\(\s*["']?(?!data:)[^"')]+["']?\s*\)/gi, "background-image:none");
      extraHead = '<st' + 'yle id="kopacz-noimg-style">img, picture, source, input[type="image"] { display: none !important; }</st' + 'yle>';
    } else {
      html = html.replace(/(<img[^>]*?\s)src\s*=\s*["']https?:\/\/[^"']*["']/gi, '$1src="data:,"');
    }

    return injectWombatShim(html, baseUrl, extraHead);
  }

  var webProxy = {
    tunnel: null,
    resolver: null,
    _cfgKey: "",
    _dirtySession: false,
    _lastRawHtml: null,
    _lastUrl: null,

    init: function(domain, pubHex, providers, customUrl) {
      var pub = hexToBytes(pubHex);
      this.resolver = new DoHResolver(providers, customUrl, function(msg) { logLine(msg, "error"); });
      this.tunnel = new TunnelClient(domain, pub, this.resolver);
      this._cfgKey = [domain, pubHex, (providers || []).join(","), customUrl || ""].join("|");
      this._dirtySession = false;
    },

    ensureConnected: async function() {
      var cfg = getConfig();
      var key = [cfg.domain, cfg.psk, (cfg.providers || []).join(","), cfg.customUrl || ""].join("|");
      if (!this.tunnel || !this.tunnel.connected() || this._dirtySession || this._cfgKey !== key) {
        var prevCount = this.resolver ? this.resolver._queryCount : 0;
        this.init(cfg.domain, cfg.psk, cfg.providers, cfg.customUrl);
        this.resolver._queryCount = prevCount;
        updateStatus("Connecting...");
        await this.tunnel.connect();
        updateStatus("Connected", "connected");
      }
    },

    navigate: async function(url, navGen, opts) {
      var gen = navGen !== undefined ? navGen : _navGen;
      opts = opts || {};
      var isPost = opts.method === "POST";
      await this.ensureConnected();
      if (gen !== _navGen) return;

      updateStatus(isPost ? "Submitting..." : "Fetching...");
      showLoading(true);

      var deadline = Date.now() + 35000;
      var urlBytes = textEncode(url);
      var payload;
      if (isPost) {
        var bodyBytes = textEncode(opts.body || "");
        payload = new Uint8Array(4 + urlBytes.length + bodyBytes.length);
        payload[0] = APP_WEB;
        payload[1] = readerMode ? WEB_POST_READER : WEB_POST;
        payload[2] = (urlBytes.length >> 8) & 0xff;
        payload[3] = urlBytes.length & 0xff;
        payload.set(urlBytes, 4);
        payload.set(bodyBytes, 4 + urlBytes.length);
      } else {
        payload = new Uint8Array(2 + urlBytes.length);
        payload[0] = APP_WEB;
        payload[1] = readerMode ? WEB_FETCH_READER : WEB_FETCH;
        payload.set(urlBytes, 2);
      }

      var immediate = await this.tunnel.send(payload);
      var status = 0, contentType = "", bodyParts = [], done = false;

      for (var i = 0; i < immediate.length; i++) {
        this._processChunk(immediate[i], function(s, ct, bp, d) {
          if (s) status = s;
          if (ct) contentType = ct;
          if (bp) bodyParts.push(bp);
          if (d) done = true;
        });
      }

      var pollRounds = 0;
      while (!done && pollRounds < 6 && Date.now() < deadline && gen === _navGen) {
        pollRounds++;
        var results = await this.tunnel.pollAll(200, 500, deadline, function() { return gen !== _navGen; });
        for (var j = 0; j < results.length; j++) {
          this._processChunk(results[j], function(s, ct, bp, d) {
            if (s) status = s;
            if (ct) contentType = ct;
            if (bp) bodyParts.push(bp);
            if (d) done = true;
          });
          if (done) break;
        }
        updateQueryCount();
        if (results.length === 0 && !done) break;
      }

      if (!done) this._dirtySession = true;
      if (gen !== _navGen) return;
      updateQueryCount();

      if (bodyParts.length === 0) {
        showLoading(false);
        renderError("No response received");
        return;
      }

      var body = concatBytes(bodyParts);
      if (status >= 400) {
        showLoading(false);
        renderError("HTTP " + status + ": " + textDecode(body));
        return;
      }

      if (contentType.indexOf("text/html") !== -1 || contentType === "") {
        var rawHtml = textDecode(body);
        this._lastRawHtml = rawHtml;
        this._lastUrl = url;
        var html = readerMode ? injectWombatShim(rawHtml, url, "") : await fetchAndInlineResources(rawHtml, url, gen);
        if (gen !== _navGen) return;
        showLoading(false);
        renderHtml(html);
      } else {
        this._lastRawHtml = null;
        this._lastUrl = url;
        showLoading(false);
        renderHtml("<pre>" + escapeHtml(textDecode(body)) + "</pre>");
      }

      updateStatus("Done (HTTP " + status + ")", status < 400 ? "connected" : "error");
      logLine("Fetched " + url + " → HTTP " + status + ", " + body.length + " bytes", "info");
    },

    _processChunk: function(data, cb) {
      if (!data || data.length === 0) return;
      var type = data[0];
      if (type === WEB_HEADER && data.length >= 3) {
        var s = (data[1] << 8) | data[2];
        var ct = data.length > 3 ? textDecode(data.subarray(3)) : "";
        cb(s, ct, null, false);
      } else if (type === WEB_CHUNK && data.length > 1) {
        cb(null, null, data.subarray(1), false);
      } else if (type === WEB_END) {
        cb(null, null, null, true);
      }
    }
  };

  function escapeHtml(s) {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  window.toggleConfig = function() {
    var panel = document.getElementById("config-panel");
    panel.classList.toggle("collapsed");
    document.getElementById("config-arrow").innerHTML = panel.classList.contains("collapsed") ? "&#9654;" : "&#9660;";
  };

  window.toggleLog = function() {
    document.getElementById("log-panel").classList.toggle("visible");
  };

  function updateModeButton() {
    var btn = document.getElementById("mode-toggle-btn");
    if (!btn) return;
    btn.textContent = readerMode ? "Mode: Reader" : "Mode: Full";
    btn.classList.toggle("active", readerMode);
  }

  window.toggleReaderMode = async function() {
    readerMode = !readerMode;
    updateModeButton();
    saveConfig();
    logLine("Render mode: " + (readerMode ? "Reader (relay-distilled)" : "Full HTML"), "info");
    if (webProxy._lastUrl) {
      document.getElementById("url-input").value = webProxy._lastUrl;
      _skipHistory = true;
      await window.navigate();
    }
  };

  function updateImgButton() {
    var btn = document.getElementById("img-toggle-btn");
    if (!btn) return;
    btn.textContent = imagesEnabled ? "Images: ON" : "Images: OFF";
    btn.classList.toggle("active", imagesEnabled);
  }

  window.toggleImages = async function() {
    imagesEnabled = !imagesEnabled;
    if (imagesEnabled && readerMode) {
      readerMode = false;
      updateModeButton();
    }
    updateImgButton();
    saveConfig();
    logLine("Images mode: " + (imagesEnabled ? "ON" : "OFF"), "info");
    if (webProxy._lastRawHtml && webProxy._lastUrl) {
      var myGen = ++_navGen;
      showLoading(true);
      try {
        var html = await fetchAndInlineResources(webProxy._lastRawHtml, webProxy._lastUrl, myGen);
        if (myGen === _navGen) {
          renderHtml(html);
          updateStatus("Done (Images " + (imagesEnabled ? "ON" : "OFF") + ")", "connected");
        }
      } finally {
        if (myGen === _navGen) { showLoading(false); updateQueryCount(); }
      }
    }
  };

  function showLoading(show) {
    document.getElementById("loading").style.display = show ? "block" : "none";
  }

  function updateStatus(text, cls) {
    var el = document.getElementById("st-conn");
    el.textContent = text;
    el.className = "status-value" + (cls ? " " + cls : "");
  }

  function updateQueryCount() {
    if (webProxy.resolver) {
      document.getElementById("st-queries").textContent = webProxy.resolver._queryCount;
    }
  }

  function logLine(msg, cls) {
    var panel = document.getElementById("log-panel");
    var line = document.createElement("div");
    line.className = "log-line" + (cls ? " " + cls : "");
    line.textContent = "[" + new Date().toLocaleTimeString() + "] " + msg;
    panel.appendChild(line);
    panel.scrollTop = panel.scrollHeight;
  }

  function renderHtml(html) {
    document.getElementById("page-frame").srcdoc = html;
  }

  function renderError(msg) {
    renderHtml('<div style="padding:20px;font-family:sans-serif;color:#c00"><h2>Error</h2><p>' + escapeHtml(msg) + "</p></" + "div>");
  }

  function getConfig() {
    var domain = document.getElementById("cfg-domain").value.trim();
    var psk = document.getElementById("cfg-psk").value.trim();
    var providers = [];
    document.querySelectorAll(".doh-btn.active").forEach(function(btn) {
      providers.push(btn.dataset.provider);
    });
    var customUrl = document.getElementById("cfg-doh-custom").value.trim();
    return { domain: domain, psk: psk, providers: providers, customUrl: customUrl, readerMode: readerMode, imagesEnabled: imagesEnabled };
  }

  function saveConfig() {
    try { localStorage.setItem("kopacz-config", JSON.stringify(getConfig())); } catch (e) {}
  }

  function loadConfig() {
    try {
      var saved = localStorage.getItem("kopacz-config");
      if (!saved) { updateModeButton(); updateImgButton(); return; }
      var cfg = JSON.parse(saved);
      if (cfg.domain) document.getElementById("cfg-domain").value = cfg.domain;
      if (cfg.psk) document.getElementById("cfg-psk").value = cfg.psk;
      if (cfg.customUrl) document.getElementById("cfg-doh-custom").value = cfg.customUrl;
      if (typeof cfg.readerMode === "boolean") readerMode = cfg.readerMode;
      if (typeof cfg.imagesEnabled === "boolean") imagesEnabled = cfg.imagesEnabled;
      updateModeButton();
      updateImgButton();
      if (cfg.providers && cfg.providers.length) {
        document.querySelectorAll(".doh-btn").forEach(function(btn) {
          btn.classList.toggle("active", cfg.providers.indexOf(btn.dataset.provider) !== -1);
        });
        if (cfg.providers.indexOf("custom") !== -1) {
          document.getElementById("cfg-doh-custom").style.display = "";
        }
      }
    } catch (e) {
      updateModeButton();
      updateImgButton();
    }
  }

  var navHistory = [];
  var navHistoryIdx = -1;
  var _skipHistory = false;

  function updateNavButtons() {
    document.getElementById("back-btn").disabled = navHistoryIdx <= 0;
    document.getElementById("fwd-btn").disabled = navHistoryIdx >= navHistory.length - 1;
  }

  window.goBack = function() {
    if (navHistoryIdx <= 0) return;
    navHistoryIdx--;
    document.getElementById("url-input").value = navHistory[navHistoryIdx];
    _skipHistory = true;
    window.navigate();
  };

  window.goForward = function() {
    if (navHistoryIdx >= navHistory.length - 1) return;
    navHistoryIdx++;
    document.getElementById("url-input").value = navHistory[navHistoryIdx];
    _skipHistory = true;
    window.navigate();
  };

  window.navigate = async function(opts) {
    var url = document.getElementById("url-input").value.trim();
    if (!url) return;
    if (!url.match(/^https?:\/\//)) url = "http://" + url;
    document.getElementById("url-input").value = url;

    var myGen = ++_navGen;

    if (!_skipHistory) {
      if (navHistoryIdx < navHistory.length - 1) navHistory = navHistory.slice(0, navHistoryIdx + 1);
      navHistory.push(url);
      navHistoryIdx = navHistory.length - 1;
    }
    _skipHistory = false;
    updateNavButtons();

    var cfg = getConfig();
    if (!cfg.domain || !cfg.psk) {
      renderError("Configure domain and Server Public Key first");
      return;
    }
    if (cfg.psk.length !== 64) {
      renderError("Server Public Key must be 64 hex characters (32 bytes)");
      return;
    }

    saveConfig();
    var goBtn = document.getElementById("go-btn");
    goBtn.disabled = true;

    try {
      document.getElementById("st-provider").textContent = cfg.providers.length ? cfg.providers[0] : "None";
      await webProxy.navigate(url, myGen, opts);
    } catch (e) {
      if (myGen === _navGen) {
        showLoading(false);
        updateStatus("Error", "error");
        renderError(e.message);
        logLine("Error: " + e.message, "error");
        webProxy._dirtySession = true;
      }
    } finally {
      if (myGen === _navGen) {
        goBtn.disabled = false;
        updateQueryCount();
      }
    }
  };

  window.addEventListener("message", function(e) {
    var frame = document.getElementById("page-frame");
    if (!e.data || !frame || e.source !== frame.contentWindow) return;
    if (e.data.type === "navigate" && e.data.url) {
      document.getElementById("url-input").value = e.data.url;
      window.navigate({ method: e.data.method || "GET", body: e.data.body || "" });
    }
  });

  document.querySelectorAll(".doh-btn").forEach(function(btn) {
    btn.addEventListener("click", function() {
      btn.classList.toggle("active");
      var customInput = document.getElementById("cfg-doh-custom");
      if (btn.dataset.provider === "custom") {
        customInput.style.display = btn.classList.contains("active") ? "" : "none";
      }
      saveConfig();
    });
  });

  document.querySelectorAll("#config-panel input").forEach(function(input) {
    input.addEventListener("change", saveConfig);
  });

  document.getElementById("url-input").addEventListener("keydown", function(e) {
    if (e.key === "Enter") window.navigate();
  });

  loadConfig();

  document.getElementById("url-input").addEventListener("input", function() {
    var url = this.value.trim();
    document.getElementById("lock-icon").innerHTML = url.startsWith("https") ? "&#128274;" : "&#128275;";
  });

  // Self-test suite (?test=1)
  if (new URLSearchParams(window.location.search).get("test") === "1") {
    (async function runTests() {
      var pass = 0, fail = 0;
      function assert(cond, msg) {
        if (!cond) { console.error("FAIL: " + msg); fail++; } else { console.log("PASS: " + msg); pass++; }
      }
      var enc = Base32.encode(new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]));
      assert(enc === "jbswy3dp", "Base32 encode Hello");
      var kp = K.nacl.generateKeyPair();
      var cs = new CryptoState(kp.publicKey);
      var syn = cs.clientHello();
      assert(syn.length === K.SYN_SIZE, "Noise_NK SYN is 56 bytes");
      logLine("Tests: " + pass + " passed, " + fail + " failed", fail > 0 ? "error" : "info");
      document.getElementById("log-panel").classList.add("visible");
    })();
  }
})();
