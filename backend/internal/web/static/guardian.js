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
