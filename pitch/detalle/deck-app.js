var slides = Array.prototype.slice.call(document.querySelectorAll(".slide"));
var index = 0;
var lang = "en";
function show(next) {
  index = (next + slides.length) % slides.length;
  slides.forEach(function (slide, n) {
    slide.classList.toggle("active", n === index);
  });
  document.getElementById("num").textContent = (index + 1) + " / " + slides.length;
}
function applyLang() {
  document.documentElement.lang = lang;
  document.querySelectorAll("[data-en]").forEach(function (node) {
    node.textContent = node.getAttribute(lang === "es" ? "data-es" : "data-en");
  });
  document.querySelectorAll(".svg-en").forEach(function (node) { node.hidden = lang === "es"; });
  document.querySelectorAll(".svg-es").forEach(function (node) { node.hidden = lang !== "es"; });
  document.getElementById("lang").textContent = lang === "es" ? "ES | EN" : "EN | ES";
  try { localStorage.setItem("titanlog-deck-lang", lang); } catch (err) {}
}
function toggle() {
  lang = lang === "en" ? "es" : "en";
  applyLang();
}
document.getElementById("lang").addEventListener("click", toggle);
document.addEventListener("keydown", function (event) {
  var key = event.key;
  if (key === "l" || key === "L") { event.preventDefault(); toggle(); return; }
  if (key === "ArrowRight" || key === "PageDown" || key === " ") { event.preventDefault(); show(index + 1); }
  if (key === "ArrowLeft" || key === "PageUp" || key === "Backspace") { event.preventDefault(); show(index - 1); }
}, true);
try {
  if (localStorage.getItem("titanlog-deck-lang") === "es") { lang = "es"; }
} catch (err) {}
applyLang();
show(0);
