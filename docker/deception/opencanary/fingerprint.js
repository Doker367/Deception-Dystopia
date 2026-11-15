(function () {
  "use strict";

  function post(data) {
    try {
      fetch("/__fp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
        keepalive: true,
      });
    } catch (_) { /* the decoy page must keep working */ }
  }

  function osFromUserAgent(ua) {
    var match;
    if (!ua) return "";
    if ((match = ua.match(/Windows NT ([\d.]+)/i))) {
      var names = { "10.0": "Windows 10/11", "6.3": "Windows 8.1", "6.2": "Windows 8", "6.1": "Windows 7" };
      return names[match[1]] || ("Windows NT " + match[1]);
    }
    if (/Android/i.test(ua)) {
      match = ua.match(/Android\s+([\d.]+)/i);
      return match ? "Android " + match[1] : "Android";
    }
    if (/(iPhone|iPad|iPod)/i.test(ua)) {
      match = ua.match(/OS\s+([\d_]+)/i);
      return match ? "iOS " + match[1].replace(/_/g, ".") : "iOS";
    }
    if (/Mac OS X/i.test(ua)) {
      match = ua.match(/Mac OS X\s+([\d_]+)/i);
      return match ? "macOS " + match[1].replace(/_/g, ".") : "macOS";
    }
    if (/CrOS/i.test(ua)) return "ChromeOS";
    if (/Linux/i.test(ua)) return "Linux";
    return "";
  }

  function webglInfo() {
    try {
      var canvas = document.createElement("canvas");
      var gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
      if (!gl) return { vendor: "", renderer: "" };
      var ext = gl.getExtension("WEBGL_debug_renderer_info");
      return {
        vendor: ext ? String(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL)) : String(gl.getParameter(gl.VENDOR) || ""),
        renderer: ext ? String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)) : String(gl.getParameter(gl.RENDERER) || ""),
      };
    } catch (_) {
      return { vendor: "", renderer: "" };
    }
  }

  function collect() {
    var nav = navigator;
    var ua = nav.userAgent || "";
    var gpu = webglInfo();
    var data = nav.userAgentData;
    var fp = {
      ua: ua,
      platform: nav.platform || "",
      os: osFromUserAgent(ua),
      osVersion: "",
      arch: "",
      bitness: "",
      model: "",
      mobile: data ? Boolean(data.mobile) : /Mobi|Android/i.test(ua),
      lang: nav.language || "",
      languages: (nav.languages || []).join(","),
      tz: (function () { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ""; } catch (_) { return ""; } })(),
      screen: [screen.width, screen.height, screen.colorDepth].join("x"),
      viewport: [window.innerWidth, window.innerHeight].join("x"),
      dpr: window.devicePixelRatio || 1,
      cores: nav.hardwareConcurrency || null,
      memory: nav.deviceMemory || null,
      ram_gb: nav.deviceMemory || null,
      touch: nav.maxTouchPoints || 0,
      touchscreen: (nav.maxTouchPoints || 0) > 0,
      webdriver: Boolean(nav.webdriver),
      cookie: Boolean(nav.cookieEnabled),
      pdf: Boolean(nav.pdfViewerEnabled),
      plugins: nav.plugins ? nav.plugins.length : null,
      connection: nav.connection ? {
        type: nav.connection.effectiveType || "",
        down: nav.connection.downlink || null,
        rtt: nav.connection.rtt || null,
        saveData: Boolean(nav.connection.saveData),
      } : null,
      webgl: gpu.renderer,
      gpuVendor: gpu.vendor,
      battery: null,
      storage: null,
    };

    if (data && data.platform) {
      fp.os = data.platform;
    }

    var pending = [];

    if (data && data.getHighEntropyValues) {
      pending.push(data.getHighEntropyValues([
        "architecture", "bitness", "model", "platform", "platformVersion",
        "uaFullVersion", "fullVersionList",
      ]).then(function (high) {
        fp.arch = high.architecture || "";
        fp.bitness = high.bitness || "";
        fp.model = high.model || "";
        fp.osVersion = high.platformVersion || "";
        if (high.platform) {
          fp.os = high.platform + (high.platformVersion ? " " + high.platformVersion : "");
        }
        fp.uaFullVersion = high.uaFullVersion || "";
        fp.brands = (high.fullVersionList || []).map(function (item) {
          return item.brand + " " + item.version;
        }).join(", ");
      }).catch(function () { /* client hints are optional */ }));
    }

    if (nav.getBattery) {
      pending.push(nav.getBattery().then(function (battery) {
        fp.battery = {
          level: Math.round(battery.level * 100),
          charging: Boolean(battery.charging),
          chargingTime: battery.chargingTime,
          dischargingTime: battery.dischargingTime,
        };
      }).catch(function () { /* Firefox/Safari do not expose it */ }));
    }

    if (nav.storage && nav.storage.estimate) {
      pending.push(nav.storage.estimate().then(function (estimate) {
        fp.storage = {
          quota_mb: estimate.quota ? Math.round(estimate.quota / 1048576) : null,
          usage_mb: estimate.usage ? Math.round(estimate.usage / 1048576) : null,
        };
      }).catch(function () { /* quota is optional */ }));
    }

    var done = function () { post(fp); };
    if (pending.length && typeof Promise !== "undefined") {
      Promise.all(pending).then(done, done);
    } else {
      done();
    }
  }

  function schedule() {
    if (document.readyState === "complete") setTimeout(collect, 350);
    else window.addEventListener("load", function () { setTimeout(collect, 350); });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", schedule);
  } else {
    schedule();
  }
})();
