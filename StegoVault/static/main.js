(function () {
  'use strict';

  var segments = document.querySelectorAll('[data-segment]');
  segments.forEach(function (seg) {
    var buttons = seg.querySelectorAll('.seg-btn');
    var typeInput = document.getElementById('payload_type');
    buttons.forEach(function (button) {
      button.addEventListener('click', function () {
        buttons.forEach(function (other) { other.classList.remove('active'); });
        button.classList.add('active');
        typeInput.value = button.dataset.target === 'payload-file' ? 'file' : 'text';
        document.querySelectorAll('.payload-pane').forEach(function (pane) {
          var show = pane.id === button.dataset.target;
          pane.classList.toggle('hidden', !show);
          if (show) {
            var input = pane.querySelector('[name="secret_text"], [name="secret_file"]');
            if (input) { input.removeAttribute('disabled'); }
          } else {
            var disabled = pane.querySelector('[name="secret_text"], [name="secret_file"]');
            if (disabled) { disabled.setAttribute('disabled', 'disabled'); }
          }
        });
      });
    });
  });

  document.querySelectorAll('[data-file-label]').forEach(function (input) {
    input.addEventListener('change', function () {
      var hint = input.closest('.field');
      var previous = hint && hint.querySelector('.chosen-label');
      if (previous) { previous.remove(); }
      if (input.files && input.files.length) {
        var label = document.createElement('span');
        label.className = 'file-hint chosen-label';
        label.textContent = 'Selected: ' + input.files[0].name;
        if (hint) { hint.appendChild(label); }
      }
    });
  });

  var flashes = document.querySelectorAll('.flash');
  var clearFlash = function (flash) {
    flash.style.transition = 'opacity 0.35s, transform 0.35s';
    flash.style.opacity = '0';
    flash.style.transform = 'translateY(-6px)';
    setTimeout(function () { flash.remove(); }, 350);
  };
  flashes.forEach(function (flash) {
    var close = flash.querySelector('.flash-close');
    if (close) { close.addEventListener('click', function () { clearFlash(flash); }); }
    setTimeout(function () { clearFlash(flash); }, 7000);
  });
})();