// ---------- Theme Management ----------
let currentTheme = localStorage.getItem('theme') || 'system';

function updateThemeIcon() {
  const resolvedTheme = getResolvedTheme();
  const icon = resolvedTheme === 'dark' ? '<i class="fas fa-moon"></i>' : '<i class="fas fa-sun"></i>';
  const systemIcon = currentTheme === 'system' ? '<i class="fas fa-desktop"></i>' : icon;
  document.getElementById('theme-icon').innerHTML = systemIcon;
}

function getResolvedTheme() {
  if (currentTheme === 'system') {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  return currentTheme;
}

function applyTheme() {
  const resolvedTheme = getResolvedTheme();
  if (resolvedTheme === 'dark') document.body.classList.add('dark');
  else document.body.classList.remove('dark');
  updateThemeIcon();
}

function setTheme(theme) {
  currentTheme = theme;
  localStorage.setItem('theme', theme);
  applyTheme();
  toggleThemeMenu();
}

function toggleThemeMenu() {
  const menu = document.getElementById('theme-menu');
  menu.classList.toggle('show');
}

function handleOutsideClick(event) {
  const themeMenu = document.getElementById('theme-menu');
  if (!event.target.closest('.theme-dropdown')) themeMenu.classList.remove('show');
}

// ---------- Scroll Animations ----------
function initScrollAnimations() {
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) entry.target.classList.add('animate-in');
    });
  }, { threshold: 0.1, rootMargin: '0px 0px -50px 0px' });
  document.querySelectorAll('.animate-on-scroll').forEach(el => observer.observe(el));
}

// ---------- Logout ----------
function logout(){
  localStorage.removeItem("loggedIn");
  localStorage.removeItem("user");
  window.location.href = "signin.html";
}

// ---------- Initialization ----------
document.addEventListener('DOMContentLoaded', function() {
  applyTheme();
  initScrollAnimations();
  document.addEventListener('click', handleOutsideClick);
  window.matchMedia('(prefers-color-scheme: dark)')?.addEventListener('change', () => {
    if (currentTheme === 'system') applyTheme();
  });
});