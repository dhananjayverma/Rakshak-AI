/**
 * Browser-side Hardware, Canvas, and WebGL fingerprint collector script generator
 */
function getFingerprintScript() {
  return `
(function() {
  // 1. Render text in a hidden HTML Canvas to capture precise graphics rendering hashes
  function getCanvasHash() {
    try {
      const canvas = document.createElement('canvas');
      canvas.width = 200;
      canvas.height = 40;
      const ctx = canvas.getContext('2d');
      if (!ctx) return 'no-canvas-context';
      ctx.textBaseline = "top";
      ctx.font = "14px 'Arial'";
      ctx.fillStyle = "#f60";
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = "#069";
      ctx.fillText("WebShield Fingerprint 🛡️", 2, 15);
      ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
      ctx.fillText("WebShield Fingerprint 🛡️", 4, 17);
      return canvas.toDataURL();
    } catch(e) {
      return 'canvas-blocked';
    }
  }

  // 2. Fetch GPU Model and Vendor strings from experimental WebGL contexts
  function getWebGLHash() {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return 'webgl-disabled';
      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      if (!debugInfo) return 'webgl-no-debug';
      const vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
      const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
      return vendor + '|' + renderer;
    } catch(e) {
      return 'webgl-blocked';
    }
  }

  // 3. Collect core hardware thread, screen size, and localization variables
  function getHardwareTelemetry() {
    return [
      navigator.hardwareConcurrency || 0,
      navigator.deviceMemory || 0,
      screen.width + 'x' + screen.height,
      screen.colorDepth,
      Intl.DateTimeFormat().resolvedOptions().timeZone,
      navigator.languages ? navigator.languages.join(',') : ''
    ].join('|');
  }

  function compileHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16);
  }

  const payload = [getCanvasHash(), getWebGLHash(), getHardwareTelemetry()].join('||');
  const deviceId = compileHash(payload);

  sessionStorage.setItem('__webshield_device_id', deviceId);

  // Hook into Fetch calls dynamically to automatically append the verification header
  const originalFetch = window.fetch;
  window.fetch = function(input, init = {}) {
    init.headers = init.headers || {};
    if (init.headers instanceof Headers) {
      init.headers.set('x-webshield-device-id', deviceId);
    } else {
      init.headers['x-webshield-device-id'] = deviceId;
    }
    return originalFetch(input, init);
  };

  // Hook into XMLHttpRequests dynamically to automatically append the verification header
  const originalOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function() {
    const originalSend = this.send;
    this.send = function() {
      try {
        this.setRequestHeader('x-webshield-device-id', deviceId);
      } catch(e) {}
      return originalSend.apply(this, arguments);
    };
    return originalOpen.apply(this, arguments);
  };

  console.log('🛡️ WebShield Client Fingerprinting Tag Active. Device ID: ' + deviceId);
})();
`;
}

module.exports = {
  getFingerprintScript
};
