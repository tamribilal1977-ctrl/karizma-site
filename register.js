const registerForm = document.getElementById("registerForm");
const registerMessage = document.getElementById("registerMessage");
const registerPassword = document.getElementById("registerPassword");
const registerPasswordConfirm = document.getElementById("registerPasswordConfirm");
const toggleRegisterPassword = document.getElementById("toggleRegisterPassword");

function setRegisterMessage(type, text) {
  registerMessage.classList.remove("error", "success");
  registerMessage.classList.add(type);
  registerMessage.textContent = text;
}

async function checkAuthenticatedRedirect() {
  try {
    const response = await fetch("/api/me", { credentials: "same-origin" });
    if (response.ok) {
      window.location.href = "index.html";
    }
  } catch (_error) {
    // Ignore startup check errors.
  }
}

if (toggleRegisterPassword && registerPassword) {
  toggleRegisterPassword.addEventListener("click", () => {
    const hidden = registerPassword.type === "password";
    registerPassword.type = hidden ? "text" : "password";
    toggleRegisterPassword.textContent = hidden ? "اخفاء" : "اظهار";
  });
}

if (registerForm && registerMessage && registerPassword && registerPasswordConfirm) {
  checkAuthenticatedRedirect();

  registerForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const name = document.getElementById("registerName").value.trim();
    const emailField = document.getElementById("registerEmail");
    const email = emailField.value.trim();
    const password = registerPassword.value;
    const confirm = registerPasswordConfirm.value;

    if (name.length < 3) {
      setRegisterMessage("error", "الاسم لازم يكون 3 أحرف على الأقل.");
      return;
    }

    if (!email || !emailField.checkValidity()) {
      setRegisterMessage("error", "دخل ايميل صحيح.");
      return;
    }

    if (password.length < 10) {
      setRegisterMessage("error", "كلمة المرور لازم تكون 10 أحرف على الأقل.");
      return;
    }

    if (!/\d/.test(password)) {
      setRegisterMessage("error", "كلمة المرور لازم تحتوي على رقم.");
      return;
    }

    if (password !== confirm) {
      setRegisterMessage("error", "كلمة المرور وتأكيدها غير متطابقين.");
      return;
    }

    try {
      const response = await fetch("/api/register", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-Requested-With": "XMLHttpRequest"
        },
        body: JSON.stringify({ name, email, password })
      });

      const payload = await response.json();
      if (!response.ok) {
        setRegisterMessage("error", payload.error || "فشل انشاء الحساب.");
        return;
      }

      setRegisterMessage("success", "تم انشاء الحساب بنجاح. رايح نحولك لتسجيل الدخول.");
      registerForm.reset();
      setTimeout(() => {
        window.location.href = "login.html";
      }, 700);
    } catch (_error) {
      setRegisterMessage("error", "الخادم غير متاح. شغّل server.py أولًا.");
    }
  });
}
