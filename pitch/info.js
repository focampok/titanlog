/* focampo.com — caso · selector ES/EN
   ES es el idioma por defecto. Guarda la elección y actualiza
   document.documentElement.lang y aria-pressed. Sin dependencias. */

(function () {
  "use strict";

  var STORAGE_KEY = "focampo-info-lang";
  var buttons = Array.prototype.slice.call(
    document.querySelectorAll("[data-lang]"),
  );
  var nodes = Array.prototype.slice.call(
    document.querySelectorAll("[data-es][data-en]"),
  );

  function apply(lang, persist) {
    var normalized = lang === "en" ? "en" : "es";
    document.documentElement.lang = normalized;

    nodes.forEach(function (node) {
      var value = node.getAttribute("data-" + normalized);
      if (value === null) return;

      if (node.tagName === "META") {
        node.setAttribute("content", value);
      } else if (node.tagName === "TITLE") {
        document.title = value;
      } else {
        node.textContent = value;
      }
    });

    buttons.forEach(function (button) {
      var active = button.getAttribute("data-lang") === normalized;
      button.setAttribute("aria-pressed", active ? "true" : "false");
    });

    if (persist) {
      try {
        localStorage.setItem(STORAGE_KEY, normalized);
      } catch (error) {
        /* El almacenamiento puede estar bloqueado; el idioma sigue cambiando. */
      }
    }
  }

  buttons.forEach(function (button) {
    button.addEventListener("click", function () {
      apply(button.getAttribute("data-lang"), true);
    });
  });

  var saved = null;
  try {
    saved = localStorage.getItem(STORAGE_KEY);
  } catch (error) {
    saved = null;
  }

  apply(saved === "en" || saved === "es" ? saved : "es", false);
})();
