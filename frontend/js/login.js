let currentTab = 'user';

function switchTab(tab) {
  currentTab = tab;
  document.getElementById('tab-user').classList.toggle('active', tab === 'user');
  document.getElementById('tab-admin').classList.toggle('active', tab === 'admin');
  document.getElementById('user-form-area').classList.toggle('hidden', tab !== 'user');
  document.getElementById('admin-form-area').classList.toggle('hidden', tab !== 'admin');
  document.getElementById('btn-label').textContent = tab === 'admin' ? 'Admin Sign In' : 'Sign In';
  document.getElementById('alert-area').innerHTML = '';
}

function togglePw() {
  const pw = document.getElementById('password');
  const eye = document.getElementById('pw-eye');
  if (pw.type === 'password') {
    pw.type = 'text';
    eye.className = 'fas fa-eye-slash';
  } else {
    pw.type = 'password';
    eye.className = 'fas fa-eye';
  }
}

const loginForm = document.getElementById('login-form');
const resetForm = document.getElementById('reset-form');
const forgotLink = document.getElementById('forgot-link');

forgotLink.addEventListener('click', (e) => {
  e.preventDefault();
  document.getElementById('reset-email').value = document.getElementById('email').value.trim();
  loginForm.classList.add('hidden');
  resetForm.classList.remove('hidden');
  document.getElementById('alert-area').innerHTML = '';
  document.getElementById('reset-email').focus();
});

document.getElementById('back-to-login').addEventListener('click', () => {
  resetForm.classList.add('hidden');
  loginForm.classList.remove('hidden');
  document.getElementById('alert-area').innerHTML = '';
});

resetForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('reset-email').value.trim();
  const newPassword = document.getElementById('new-password').value;
  const confirmPassword = document.getElementById('confirm-password').value;
  const alertArea = document.getElementById('alert-area');
  const resetButton = document.getElementById('reset-btn');

  if (!email || !newPassword || !confirmPassword) {
    alertArea.innerHTML = `<div class="alert alert-danger"><i class="fas fa-exclamation-circle"></i> Please fill in all fields.</div>`;
    return;
  }
  if (newPassword.length < 6) {
    alertArea.innerHTML = `<div class="alert alert-danger"><i class="fas fa-exclamation-circle"></i> Password must be at least 6 characters.</div>`;
    return;
  }
  if (newPassword !== confirmPassword) {
    alertArea.innerHTML = `<div class="alert alert-danger"><i class="fas fa-exclamation-circle"></i> Passwords do not match.</div>`;
    return;
  }

  resetButton.disabled = true;
  resetButton.innerHTML = `<span class="spinner"></span> Resetting...`;

  try {
    const res = await API.post('/api/auth/reset-password', { email, new_password: newPassword });
    const responseText = await res.text();
    let data;
    try {
      data = JSON.parse(responseText);
    } catch (parseError) {
      throw new Error(`Password reset service returned an unexpected response (${res.status}). Please restart the backend.`);
    }
    if (!res.ok || !data.success) throw new Error(data.message || 'Password reset failed');

    document.getElementById('email').value = email;
    document.getElementById('password').value = '';
    resetForm.reset();
    resetForm.classList.add('hidden');
    loginForm.classList.remove('hidden');
    alertArea.innerHTML = `<div class="alert alert-success"><i class="fas fa-check-circle"></i> ${data.message}</div>`;
  } catch (err) {
    alertArea.innerHTML = `<div class="alert alert-danger"><i class="fas fa-exclamation-circle"></i> ${err.message}</div>`;
  } finally {
    resetButton.disabled = false;
    resetButton.innerHTML = `<i class="fas fa-key"></i> Reset Password`;
  }
});

loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;
  const alertArea = document.getElementById('alert-area');
  const btn = document.getElementById('login-btn');

  if (!email || !password) {
    alertArea.innerHTML = `<div class="alert alert-danger"><i class="fas fa-exclamation-circle"></i> Please fill in all fields.</div>`;
    return;
  }

  btn.disabled = true;
  btn.innerHTML = `<span class="spinner"></span> Signing in...`;

  try {
    const res = await API.post('/api/auth/login', { email, password, role: currentTab });
    const data = await res.json();
    if (!res.ok || !data.success) throw new Error(data.message || 'Login failed');

    if (data.token_name === 'Atoken') {
      sessionStorage.setItem('Atoken', data.token);
      sessionStorage.setItem('admin_data', JSON.stringify(data.user));

      showToast('Admin login successful! Redirecting...', 'success');
      setTimeout(() => window.location.href = 'admin.html', 1000);
    } else {
      sessionStorage.setItem('Utoken', data.token);
      sessionStorage.setItem('user_data', JSON.stringify(data.user));

      showToast('Welcome back! Redirecting...', 'success');
      setTimeout(() => window.location.href = 'dashboard.html', 1000);
    }
  } catch (err) {
    alertArea.innerHTML = `<div class="alert alert-danger"><i class="fas fa-exclamation-circle"></i> ${err.message}</div>`;
    btn.disabled = false;
    btn.innerHTML = `<i class="fas fa-sign-in-alt"></i> <span id="btn-label">${currentTab === 'admin' ? 'Admin Sign In' : 'Sign In'}</span>`;
  }
});

// Ripple effect
document.querySelectorAll('.btn-ripple').forEach(btn => {
  btn.addEventListener('click', function (e) {
    const ripple = document.createElement('span');
    ripple.className = 'ripple-wave';
    const rect = this.getBoundingClientRect();
    const size = Math.max(rect.width, rect.height);
    ripple.style.cssText = `width:${size}px;height:${size}px;left:${e.clientX - rect.left - size / 2}px;top:${e.clientY - rect.top - size / 2}px`;
    this.appendChild(ripple);
    setTimeout(() => ripple.remove(), 600);
  });
});
