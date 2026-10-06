if (sessionStorage.getItem('Utoken')) {
  window.location.href = 'dashboard.html';
}

function togglePw() {
  const pw = document.getElementById('password');
  const eye = document.getElementById('pw-eye');
  pw.type = pw.type === 'password' ? 'text' : 'password';
  eye.className = pw.type === 'text' ? 'fas fa-eye-slash' : 'fas fa-eye';
}

function checkStrength(pw) {
  const bar = document.getElementById('pw-bar');
  const lbl = document.getElementById('pw-label');
  let score = 0;
  if (pw.length >= 6) score++;
  if (pw.length >= 10) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^a-zA-Z0-9]/.test(pw)) score++;
  const levels = [
    { pct: '0%', color: '#ccc', label: 'Enter password' },
    { pct: '20%', color: '#ff4757', label: 'Very Weak' },
    { pct: '40%', color: '#ffa502', label: 'Weak' },
    { pct: '65%', color: '#eccc68', label: 'Fair' },
    { pct: '80%', color: '#2ed573', label: 'Strong' },
    { pct: '100%', color: '#1e90ff', label: 'Very Strong' },
  ];
  const lvl = levels[score] || levels[0];
  bar.style.width = lvl.pct;
  bar.style.background = lvl.color;
  lbl.textContent = lvl.label;
  lbl.style.color = lvl.color;
}

document.getElementById('reg-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = document.getElementById('name').value.trim();
  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;
  const confirm = document.getElementById('confirm-pw').value;
  const alertArea = document.getElementById('alert-area');
  const btn = document.getElementById('reg-btn');

  if (!name || !email || !password) {
    alertArea.innerHTML = `<div class="alert alert-danger"><i class="fas fa-exclamation-circle"></i> All fields are required.</div>`;
    return;
  }
  if (password.length < 6) {
    alertArea.innerHTML = `<div class="alert alert-danger"><i class="fas fa-exclamation-circle"></i> Password must be at least 6 characters.</div>`;
    return;
  }
  if (password !== confirm) {
    alertArea.innerHTML = `<div class="alert alert-danger"><i class="fas fa-exclamation-circle"></i> Passwords do not match.</div>`;
    return;
  }

  btn.disabled = true;
  btn.innerHTML = `<span class="spinner"></span> Creating account...`;

  try {
    const res = await API.post('/api/auth/register', { name, email, password });
    const data = await res.json();
    if (!res.ok || !data.success) throw new Error(data.message || 'Registration failed');
    localStorage.setItem('Utoken', data.token);
    localStorage.setItem('user_data', JSON.stringify(data.user));
    showToast('Account created! Welcome to CyberSentinel Pro!', 'success');
    setTimeout(() => window.location.href = 'dashboard.html', 1200);
  } catch (err) {
    alertArea.innerHTML = `<div class="alert alert-danger"><i class="fas fa-exclamation-circle"></i> ${err.message}</div>`;
    btn.disabled = false;
    btn.innerHTML = `<i class="fas fa-user-plus"></i> Create Account`;
  }
});

// Ripple
document.querySelectorAll('.btn-ripple').forEach(btn => {
  btn.addEventListener('click', function(e) {
    const ripple = document.createElement('span');
    ripple.className = 'ripple-wave';
    const rect = this.getBoundingClientRect();
    const size = Math.max(rect.width, rect.height);
    ripple.style.cssText = `width:${size}px;height:${size}px;left:${e.clientX-rect.left-size/2}px;top:${e.clientY-rect.top-size/2}px`;
    this.appendChild(ripple);
    setTimeout(() => ripple.remove(), 600);
  });
});
