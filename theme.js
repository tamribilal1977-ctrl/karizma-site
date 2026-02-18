const THEME_KEY = "karizma_theme";
const THEMES = [
  { key: "white", label: "ابيض" },
  { key: "black", label: "اسود" },
  { key: "gray", label: "رمادي" }
];

function applyTheme(theme) {
  const safeTheme = THEMES.some((item) => item.key === theme) ? theme : "white";
  if (safeTheme === "white") {
    document.documentElement.removeAttribute("data-theme");
  } else {
    document.documentElement.setAttribute("data-theme", safeTheme);
  }
  localStorage.setItem(THEME_KEY, safeTheme);
}

function buildThemeSwitcher() {
  const wrap = document.createElement("div");
  wrap.className = "theme-switcher";

  const current = localStorage.getItem(THEME_KEY) || "white";
  THEMES.forEach((theme) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "theme-btn";
    btn.textContent = theme.label;
    btn.dataset.theme = theme.key;
    if (current === theme.key) {
      btn.classList.add("active");
    }

    btn.addEventListener("click", () => {
      applyTheme(theme.key);
      document.querySelectorAll(".theme-btn").forEach((item) => {
        item.classList.toggle("active", item.dataset.theme === theme.key);
      });
    });

    wrap.appendChild(btn);
  });

  document.body.appendChild(wrap);
}

(() => {
  const saved = localStorage.getItem(THEME_KEY) || "white";
  applyTheme(saved);
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", buildThemeSwitcher);
  } else {
    buildThemeSwitcher();
  }
})();
