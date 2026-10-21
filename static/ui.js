(function () {
  // Show only the form section that matches the chosen server type
  var sel = document.getElementById("protocol");
  if (sel) {
    var groups = document.querySelectorAll("[data-group]");
    var apply = function () {
      groups.forEach(function (g) {
        var on = g.dataset.group === sel.value;
        g.classList.toggle("hide", !on);
        // disabled fields are not submitted, which avoids duplicate host/port inputs
        g.querySelectorAll("input,textarea,select").forEach(function (el) { el.disabled = !on; });
      });
    };
    sel.addEventListener("change", apply);
    apply();
  }
  document.querySelectorAll("form[data-confirm]").forEach(function (f) {
    f.addEventListener("submit", function (e) { if (!confirm(f.dataset.confirm)) e.preventDefault(); });
  });
})();
