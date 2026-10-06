// Counter animation
function animateCounter(el) {
  const target = parseFloat(el.dataset.target);
  const duration = 1800;
  const step = target / (duration / 16);
  let current = 0;
  const timer = setInterval(() => {
    current += step;
    if (current >= target) { current = target; clearInterval(timer); }
    el.textContent = Number.isInteger(target) ? Math.floor(current) : current.toFixed(1);
  }, 16);
}
const counters = document.querySelectorAll('.counter');
const observer = new IntersectionObserver(entries => {
  entries.forEach(e => { if (e.isIntersecting) { animateCounter(e.target); observer.unobserve(e.target); } });
}, { threshold: 0.5 });
counters.forEach(c => observer.observe(c));

// Update nav based on auth
const uta = document.getElementById('nav-actions');
const utoken = localStorage.getItem('Utoken');
const atoken = localStorage.getItem('Atoken');
if (utoken) {
  uta.innerHTML = `<a href="dashboard.html" class="btn btn-outline btn-sm">Dashboard</a><a href="scan.html" class="btn btn-primary btn-sm"><i class="fas fa-search"></i> Scan</a>`;
} else if (atoken) {
  uta.innerHTML = `<a href="admin.html" class="btn btn-primary btn-sm"><i class="fas fa-crown"></i> Admin Panel</a>`;
}
