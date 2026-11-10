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
  function collect() {
    var fp = {
      ua: navigator.userAgent,
      platform: navigator.platform,
      lang: navigator.language,
      languages: (navigator.languages || []).join(","),
      tz: (function () { try { return Intl.DateTimeFormat().resolvedOptions().timeZone; } catch (_) { return ""; } })(),
      screen: [screen.width, screen.height, screen.colorDepth].join("x"),
      viewport: [window.innerWidth, window.innerHeight].join("x"),
      dpr: window.devicePixelRatio || 1,
      cores: navigator.hardwareConcurrency || null,
      memory: navigator.deviceMemory || null,
      touch: navigator.maxTouchPoints || 0,
      webdriver: Boolean(navigator.webdriver),
      cookie: Boolean(navigator.cookieEnabled),
      pdf: Boolean(navigator.pdfViewerEnabled),
      connection: navigator.connection ? {
        type: navigator.connection.effectiveType || "",
        down: navigator.connection.downlink || null,
        rtt: navigator.connection.rtt || null,
      } : null,
      webgl: (function () {
        try {
          var canvas = document.createElement("canvas");
          var gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
          if (!gl) return "";
          var ext = gl.getExtension("WEBGL_debug_renderer_info");
          return ext ? String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)) : "";
        } catch (_) { return ""; }
      })(),
    };
    if (navigator.getBattery) {
      navigator.getBattery().then(function (battery) {
        fp.battery = { level: Math.round(battery.level * 100), charging: battery.charging };
        post(fp);
      }).catch(function () { post(fp); });
    } else {
      post(fp);
    }
  }
  if (document.readyState === "complete") setTimeout(collect, 350);
  else window.addEventListener("load", function () { setTimeout(collect, 350); });
})();
