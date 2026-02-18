const score = document.getElementById("score");
const scoreValue = document.getElementById("scoreValue");
const userBadge = document.getElementById("userBadge");
const authLinks = document.querySelectorAll(".auth-link");
const logoutBtn = document.getElementById("logoutBtn");

if (score && scoreValue) {
  score.addEventListener("input", () => {
    scoreValue.textContent = `${score.value}/10`;
  });
}

async function syncAuthUI() {
  if (!userBadge) {
    return;
  }

  let user = null;
  try {
    const response = await fetch("/api/me", { credentials: "same-origin" });
    if (response.ok) {
      const payload = await response.json();
      user = payload.user || null;
    }
  } catch (_error) {
    user = null;
  }

  const isLoggedIn = Boolean(user);
  userBadge.textContent = isLoggedIn ? `مرحبا ${user.name}` : "";

  authLinks.forEach((link) => {
    link.classList.toggle("hidden", isLoggedIn);
  });

  if (logoutBtn) {
    logoutBtn.classList.toggle("hidden", !isLoggedIn);
    logoutBtn.onclick = async () => {
      try {
        await fetch("/api/logout", {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest"
          },
          body: "{}"
        });
      } catch (_error) {
        // Always reload to reset local UI state.
      }
      window.location.reload();
    };
  }
}

syncAuthUI();
