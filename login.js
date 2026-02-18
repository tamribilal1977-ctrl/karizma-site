const loginForm = document.getElementById("loginForm");
const loginMessage = document.getElementById("loginMessage");
const loginEmail = document.getElementById("loginEmail");
const loginPassword = document.getElementById("loginPassword");
const togglePassword = document.getElementById("togglePassword");

function setAuthMessage(type, text) {
  loginMessage.classList.remove("error", "success");
  loginMessage.classList.add(type);
  loginMessage.textContent = text;
}

async function checkAuthenticatedRedirect() {
  try {
    const response = await fetch("/api/me", { credentials: "same-origin" });
    if (response.ok) {
      window.location.href = "index.html";
    }
  } catch (_error) {
    // Ignore network errors on initial guard check.
  }
}

if (togglePassword && loginPassword) {
  togglePassword.addEventListener("click", () => {
    const isPassword = loginPassword.type === "password";
    loginPassword.type = isPassword ? "text" : "password";
    togglePassword.textContent = isPassword ? "اخفاء" : "اظهار";
  });
}

if (loginForm && loginMessage && loginEmail && loginPassword) {
  checkAuthenticatedRedirect();

  loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const email = loginEmail.value.trim();
    const password = loginPassword.value.trim();

    if (!email || !password) {
      setAuthMessage("error", "دخل الايميل وكلمة المرور.");
      return;
    }

    if (!loginEmail.checkValidity()) {
      setAuthMessage("error", "الايميل غير صالح.");
      loginEmail.focus();
      return;
    }

    if (password.length < 6) {
      setAuthMessage("error", "كلمة المرور قصيرة.");
      loginPassword.focus();
      return;
    }

    try {
      const response = await fetch("/api/login", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-Requested-With": "XMLHttpRequest"
        },
        body: JSON.stringify({ email, password })
      });
      const payload = await response.json();

      if (!response.ok) {
        setAuthMessage("error", payload.error || "فشل تسجيل الدخول.");
        return;
      }

      setAuthMessage("success", `مرحبا ${payload.user.name}، تم تسجيل الدخول.`);
      loginForm.reset();
      setTimeout(() => {
        window.location.href = "index.html";
      }, 700);
    } catch (_error) {
      setAuthMessage("error", "الخادم غير متاح. شغّل server.py أولًا.");
    }
  });
}
