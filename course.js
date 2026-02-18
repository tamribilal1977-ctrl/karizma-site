const trackButtons = document.querySelectorAll(".track-btn");
const trackPanels = document.querySelectorAll(".track-panel");
const courseHint = document.getElementById("courseHint");
const lessonOpenButtons = document.querySelectorAll(".open-lesson");
const closeLessonButtons = document.querySelectorAll(".close-lesson");

function openTrack(trackId) {
  let found = false;

  trackPanels.forEach((panel) => {
    const isActive = panel.id === trackId;
    panel.classList.toggle("hidden", !isActive);
    found = found || isActive;
  });

  trackButtons.forEach((button) => {
    const isActive = button.dataset.track === trackId;
    button.setAttribute("aria-expanded", String(isActive));
    button.classList.toggle("active-track", isActive);
  });

  if (courseHint) {
    courseHint.classList.toggle("hidden", found);
  }

  const activePanel = document.getElementById(trackId);
  if (activePanel) {
    activePanel.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

trackButtons.forEach((button) => {
  button.addEventListener("click", () => {
    openTrack(button.dataset.track);
  });
});

if (window.location.hash === "#confidence" || window.location.hash === "#charisma") {
  openTrack(window.location.hash.replace("#", ""));
}

lessonOpenButtons.forEach((button) => {
  button.addEventListener("click", () => {
    const lessonId = button.dataset.lesson;
    const lessonSection = document.getElementById(lessonId);
    if (!lessonSection) {
      return;
    }
    lessonSection.classList.remove("hidden");
    lessonSection.scrollIntoView({ behavior: "smooth", block: "start" });
  });
});

closeLessonButtons.forEach((button) => {
  button.addEventListener("click", () => {
    const lessonSection = button.closest(".lesson-detail");
    if (!lessonSection) {
      return;
    }
    lessonSection.classList.add("hidden");
  });
});

async function requireSession() {
  try {
    const response = await fetch("/api/me", { credentials: "same-origin" });
    if (!response.ok) {
      window.location.href = "login.html";
    }
  } catch (_error) {
    window.location.href = "login.html";
  }
}

requireSession();
