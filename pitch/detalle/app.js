var lang = "en";
function applyLang() {
  document.documentElement.lang = lang;
  document.querySelectorAll("[data-en]").forEach(function (node) {
    var value = node.getAttribute(lang === "es" ? "data-es" : "data-en");
    if (node.tagName === "META") node.setAttribute("content", value);
    else node.textContent = value;
  });
  document.querySelectorAll(".svg-en").forEach(function (node) { node.hidden = lang === "es"; });
  document.querySelectorAll(".svg-es").forEach(function (node) { node.hidden = lang !== "es"; });
  document.getElementById("lang").textContent = lang === "es" ? "ES | EN" : "EN | ES";
  var nav = document.querySelector("nav");
  if (nav) nav.setAttribute("aria-label", lang === "es" ? "Secciones" : "Sections");
  try { localStorage.setItem("titanlog-deck-lang", lang); } catch (err) {}
}
function toggle() {
  lang = lang === "en" ? "es" : "en";
  applyLang();
}
document.getElementById("lang").addEventListener("click", toggle);
document.addEventListener("keydown", function (event) {
  if (event.key === "l" || event.key === "L") {
    var tag = event.target && event.target.tagName;
    if (tag === "INPUT" || tag === "TEXTAREA") return;
    event.preventDefault();
    toggle();
  }
});
try {
  if (localStorage.getItem("titanlog-deck-lang") === "es") lang = "es";
} catch (err) {}
applyLang();
