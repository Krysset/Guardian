// Adds a show button to every password field, and centres the sign-in bar's content vertically.
// The pages work without this script.
(function () {
  var eye = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" ' +
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"></path>' +
    '<circle cx="12" cy="12" r="3"></circle></svg>';
  document.querySelectorAll('.password input').forEach(function (input) {
    var button = document.createElement('button');
    button.type = 'button';
    button.className = 'reveal';
    button.innerHTML = eye;
    button.setAttribute('aria-label', 'Show password');
    button.setAttribute('aria-pressed', 'false');
    button.addEventListener('click', function () {
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      button.setAttribute('aria-pressed', show ? 'true' : 'false');
      button.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
      input.focus();
    });
    input.parentNode.appendChild(button);
  });
})();

// Centre the logo and the content in the bar, and keep the logo cut out of the glass at the logo's place.
// The consent page is left alone: its list scrolls between a fixed top and fixed buttons.
(function () {
  var bar = document.querySelector('.bar');
  var logo = bar && bar.querySelector('.logo');
  if (!logo || bar.classList.contains('fixed')) {
    return;
  }
  bar.classList.add('centered');
  function place() {
    bar.style.setProperty('--logo-y', logo.offsetTop + 'px');
  }
  place();
  if (window.ResizeObserver) {
    new ResizeObserver(place).observe(bar);
  } else {
    window.addEventListener('resize', place);
  }
  if (document.fonts && document.fonts.ready) {
    document.fonts.ready.then(place);
  }
})();

// Copy, download and print for the two-factor secret and the recovery codes. Without JavaScript the
// buttons stay hidden and the codes can still be written down.
(function () {
  function text(id) {
    var el = document.getElementById(id);
    if (!el) return '';
    var codes = el.querySelectorAll('code');
    if (codes.length) return Array.prototype.map.call(codes, function (c) { return c.textContent; }).join('\n') + '\n';
    return el.textContent.replace(/\s+/g, '');
  }
  document.querySelectorAll('[data-copy]').forEach(function (b) {
    if (!navigator.clipboard) return;
    b.hidden = false;
    b.addEventListener('click', function () {
      navigator.clipboard.writeText(text(b.getAttribute('data-copy'))).then(function () {
        var label = b.textContent;
        b.textContent = 'Copied';
        setTimeout(function () { b.textContent = label; }, 1500);
      });
    });
  });
  document.querySelectorAll('[data-download]').forEach(function (b) {
    b.addEventListener('click', function () {
      var blob = new Blob(['Guardian recovery codes. Each works once.\n\n' + text(b.getAttribute('data-download'))], { type: 'text/plain' });
      var a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'guardian-recovery-codes.txt';
      document.body.appendChild(a);
      a.click();
      setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 0);
    });
  });
  document.querySelectorAll('[data-print]').forEach(function (b) {
    b.addEventListener('click', function () { window.print(); });
  });
  document.querySelectorAll('.code-actions').forEach(function (row) { row.hidden = false; });
})();

// Security keys and passkeys: a form with data-webauthn runs the browser's key dialog, puts the answer in
// its "credential" field and submits. The options come from the server in data-options; the challenge in
// them is checked when the form comes back. "create" adds a key (S15), "get" asks for one (S14), and
// "passkey" signs in without a password (S1), also from the browser's suggestions in the username field.
(function () {
  var forms = document.querySelectorAll('form[data-webauthn]');
  if (!forms.length) return;

  function toBytes(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    var bin = atob(s + '==='.slice((s.length + 3) % 4));
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }
  function toText(buf) {
    var bytes = new Uint8Array(buf), bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function withIds(list) {
    return (list || []).map(function (c) { return Object.assign({}, c, { id: toBytes(c.id) }); });
  }
  function creation(o) {
    var pk = Object.assign({}, o.publicKey);
    pk.challenge = toBytes(pk.challenge);
    pk.user = Object.assign({}, pk.user, { id: toBytes(pk.user.id) });
    pk.excludeCredentials = withIds(pk.excludeCredentials);
    return { publicKey: pk };
  }
  function request(o) {
    var pk = Object.assign({}, o.publicKey);
    pk.challenge = toBytes(pk.challenge);
    pk.allowCredentials = withIds(pk.allowCredentials);
    return { publicKey: pk };
  }
  function answer(c) {
    var r = c.response, out = {
      id: c.id, rawId: toText(c.rawId), type: c.type,
      authenticatorAttachment: c.authenticatorAttachment || undefined,
      clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {},
      response: { clientDataJSON: toText(r.clientDataJSON) }
    };
    if (r.attestationObject) {
      out.response.attestationObject = toText(r.attestationObject);
      if (r.getTransports) out.response.transports = r.getTransports();
    } else {
      out.response.authenticatorData = toText(r.authenticatorData);
      out.response.signature = toText(r.signature);
      if (r.userHandle) out.response.userHandle = toText(r.userHandle);
    }
    return JSON.stringify(out);
  }
  function why(e, kind) {
    if (e && e.name === 'NotAllowedError') return 'The request was cancelled or timed out. Try again.';
    if (e && e.name === 'InvalidStateError' && kind === 'create') return 'That key is already registered. Use another one.';
    return 'This browser could not use the key. Try again, or use another way.';
  }

  forms.forEach(function (form) {
    var kind = form.getAttribute('data-webauthn');
    var error = form.querySelector('[data-webauthn-error]');
    var button = form.querySelector('button[type=submit]');
    function say(text) {
      if (!error) return;
      error.textContent = text;
      error.hidden = !text;
    }
    if (!window.PublicKeyCredential || !navigator.credentials) {
      if (kind === 'passkey') return; // the form stays hidden
      say('This browser can\'t use security keys. Use another way.');
      if (button) button.disabled = true;
      return;
    }
    var options = JSON.parse(form.getAttribute('data-options'));
    var busy = false;
    function finish(c) {
      form.querySelector('input[name=credential]').value = answer(c);
      HTMLFormElement.prototype.submit.call(form);
    }

    // The browser's own passkey suggestions in the username field (conditional mediation).
    var waiting = null;
    function suggest() {
      if (kind !== 'passkey' || !PublicKeyCredential.isConditionalMediationAvailable) return;
      PublicKeyCredential.isConditionalMediationAvailable().then(function (ok) {
        if (!ok) return;
        waiting = new AbortController();
        var o = request(options);
        o.mediation = 'conditional';
        o.signal = waiting.signal;
        navigator.credentials.get(o).then(function (c) { if (c) finish(c); }, function () {});
      });
    }
    if (kind === 'passkey') {
      form.hidden = false;
      suggest();
    }

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      if (busy) return;
      busy = true;
      say('');
      if (waiting) waiting.abort();
      var run = kind === 'create' ? navigator.credentials.create(creation(options)) : navigator.credentials.get(request(options));
      run.then(function (c) {
        if (!c) throw new Error('no credential');
        finish(c);
      }).catch(function (err) {
        busy = false;
        say(why(err, kind));
        suggest();
      });
    });
  });
})();

// Proof of work: a form with a puzzle (input[name=pow]) gets its answer before it is sent. The browser tries
// numbers until the SHA-256 of the salt followed by the number is the challenge; that takes about half a
// second, and starts as soon as the page opens, so it is usually done before the form is filled in.
(function () {
  var subtle = window.crypto && window.crypto.subtle;
  document.querySelectorAll('input[name="pow"]').forEach(function (input) {
    var form = input.form;
    var answer = form.querySelector('input[name="pow_number"]');
    var status = form.querySelector('[data-pow-status]');
    var salt = input.getAttribute('data-pow-salt');
    var challenge = input.getAttribute('data-pow-challenge');
    var max = parseInt(input.getAttribute('data-pow-max'), 10);
    var done = false;
    var submitting = false;
    if (!subtle) {
      // Only on plain http away from localhost: the server then says the check failed.
      return;
    }
    function hex(buffer) {
      var bytes = new Uint8Array(buffer);
      var out = '';
      for (var i = 0; i < bytes.length; i++) {
        out += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
      }
      return out;
    }
    var encoder = new TextEncoder();
    function attempt(n) {
      return subtle.digest('SHA-256', encoder.encode(salt + n)).then(function (sum) {
        return hex(sum) === challenge;
      });
    }
    // Batches of digests in parallel, then the next batch.
    function search(from) {
      if (from > max) {
        return Promise.resolve(-1);
      }
      var batch = [];
      for (var n = from; n <= max && n < from + 500; n++) {
        batch.push(attempt(n));
      }
      return Promise.all(batch).then(function (hits) {
        var i = hits.indexOf(true);
        return i >= 0 ? from + i : search(from + 500);
      });
    }
    var solved = search(0).then(function (n) {
      if (n >= 0) {
        answer.value = String(n);
      }
      done = true;
      if (status) {
        status.hidden = true;
      }
    });
    form.addEventListener('submit', function (event) {
      if (done || submitting) {
        return;
      }
      event.preventDefault();
      submitting = true;
      if (status) {
        status.hidden = false;
      }
      var button = form.querySelector('button[type="submit"]');
      if (button) {
        button.disabled = true;
      }
      solved.then(function () {
        if (button) {
          button.disabled = false;
        }
        if (form.requestSubmit) {
          form.requestSubmit(button || undefined);
        } else {
          form.submit();
        }
      });
    });
  });
})();
