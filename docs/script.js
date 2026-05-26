/**
 * Cybersecurity Portfolio — Interactive JavaScript
 * Features:
 *   - Sticky nav with scroll detection
 *   - Mobile hamburger menu
 *   - Typing animation effect for hero roles
 *   - Floating particle system
 *   - Counter animations with Intersection Observer
 *   - Scroll-triggered reveal animations
 *   - Project card filtering
 *   - Tools strip duplication for seamless scroll
 */

'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TYPED_ROLES = [
  'SOC Analyst',
  'Security Analyst',
  'Digital Forensics Analyst',
  'Incident Response Analyst',
  'Threat Intelligence Analyst',
  'SIEM Analyst',
  'Blue Team Engineer',
  'Security Monitoring Analyst',
];

const PARTICLE_COUNT = 25;

// ─────────────────────────────────────────────────────────────────────────────
// Utility
// ─────────────────────────────────────────────────────────────────────────────

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => document.querySelectorAll(selector);
const rand = (min, max) => Math.random() * (max - min) + min;

// ─────────────────────────────────────────────────────────────────────────────
// Navigation — Sticky + Mobile
// ─────────────────────────────────────────────────────────────────────────────

function initNav() {
  const nav = $('#nav');
  const hamburger = $('#hamburger');
  const navLinks = $('.nav__links');

  // Sticky scroll effect
  const handleScroll = () => {
    nav.classList.toggle('scrolled', window.scrollY > 50);
  };

  window.addEventListener('scroll', handleScroll, { passive: true });

  // Mobile menu toggle
  if (hamburger && navLinks) {
    hamburger.addEventListener('click', () => {
      const isOpen = navLinks.classList.toggle('open');
      hamburger.setAttribute('aria-expanded', String(isOpen));
    });

    // Close menu when a link is clicked
    navLinks.querySelectorAll('.nav__link').forEach((link) => {
      link.addEventListener('click', () => {
        navLinks.classList.remove('open');
        hamburger.setAttribute('aria-expanded', 'false');
      });
    });

    // Close menu on outside click
    document.addEventListener('click', (e) => {
      if (!nav.contains(e.target)) {
        navLinks.classList.remove('open');
        hamburger.setAttribute('aria-expanded', 'false');
      }
    });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Typing Animation
// ─────────────────────────────────────────────────────────────────────────────

function initTypingAnimation() {
  const el = $('#typed-text');
  if (!el) return;

  let roleIndex = 0;
  let charIndex = 0;
  let isDeleting = false;
  let pauseTime = 0;

  function type() {
    const currentRole = TYPED_ROLES[roleIndex];
    const speed = isDeleting ? 50 : 80;

    if (!isDeleting && charIndex === currentRole.length) {
      // Pause at end of word
      pauseTime = 2000;
      isDeleting = true;
    } else if (isDeleting && charIndex === 0) {
      // Move to next role
      isDeleting = false;
      roleIndex = (roleIndex + 1) % TYPED_ROLES.length;
      pauseTime = 300;
    }

    el.textContent = currentRole.slice(0, charIndex);
    charIndex += isDeleting ? -1 : 1;

    setTimeout(type, pauseTime || speed);
    pauseTime = 0;
  }

  // Delay start slightly
  setTimeout(type, 800);
}

// ─────────────────────────────────────────────────────────────────────────────
// Particle System
// ─────────────────────────────────────────────────────────────────────────────

function initParticles() {
  const container = $('#particles');
  if (!container) return;

  // Create particles
  for (let i = 0; i < PARTICLE_COUNT; i++) {
    const particle = document.createElement('div');
    particle.className = 'particle';

    // Random positioning and animation
    const size = rand(2, 5);
    particle.style.cssText = `
      left: ${rand(0, 100)}%;
      width: ${size}px;
      height: ${size}px;
      animation-duration: ${rand(8, 20)}s;
      animation-delay: ${rand(0, 15)}s;
      opacity: ${rand(0.2, 0.7)};
    `;

    container.appendChild(particle);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Counter Animation
// ─────────────────────────────────────────────────────────────────────────────

function initCounters() {
  const counters = $$('[data-target]');
  if (!counters.length) return;

  const animateCounter = (el) => {
    const target = parseInt(el.dataset.target, 10);
    const duration = 1500;
    const startTime = performance.now();

    function update(currentTime) {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // Ease out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      el.textContent = Math.round(eased * target) + '+';

      if (progress < 1) {
        requestAnimationFrame(update);
      }
    }

    requestAnimationFrame(update);
  };

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          animateCounter(entry.target);
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.5 }
  );

  counters.forEach((counter) => observer.observe(counter));
}

// ─────────────────────────────────────────────────────────────────────────────
// Scroll Reveal Animations
// ─────────────────────────────────────────────────────────────────────────────

function initScrollReveal() {
  // Add animate-in class to elements we want to reveal
  const targets = [
    '.skill-card',
    '.project-card',
    '.stat-card',
    '.cert-item',
    '.contact-card',
    '.about__text',
    '.about__stats',
  ];

  targets.forEach((selector) => {
    $$(selector).forEach((el) => {
      el.classList.add('animate-in');
    });
  });

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add('visible');
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.1, rootMargin: '0px 0px -60px 0px' }
  );

  $$('.animate-in').forEach((el, i) => {
    // Stagger animations within the same section
    el.style.transitionDelay = `${(i % 6) * 80}ms`;
    observer.observe(el);
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Project Filtering
// ─────────────────────────────────────────────────────────────────────────────

function initProjectFilter() {
  const filterBtns = $$('.filter-btn');
  const projectCards = $$('.project-card');

  filterBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      const filter = btn.dataset.filter;

      // Update active button
      filterBtns.forEach((b) => b.classList.remove('filter-btn--active'));
      btn.classList.add('filter-btn--active');

      // Show/hide cards with animation
      projectCards.forEach((card) => {
        if (filter === 'all' || card.dataset.category === filter) {
          card.classList.remove('hidden');
          // Trigger reflow for animation
          requestAnimationFrame(() => {
            card.style.opacity = '1';
            card.style.transform = 'translateY(0)';
          });
        } else {
          card.style.opacity = '0';
          card.style.transform = 'translateY(20px)';
          setTimeout(() => card.classList.add('hidden'), 250);
        }
      });
    });
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Tools Strip — Duplicate for seamless loop
// ─────────────────────────────────────────────────────────────────────────────

function initToolsStrip() {
  const track = $('#tools-track');
  if (!track) return;

  // Duplicate content for seamless scrolling
  track.innerHTML += track.innerHTML;
}

// ─────────────────────────────────────────────────────────────────────────────
// Smooth active nav link on scroll
// ─────────────────────────────────────────────────────────────────────────────

function initActiveNavLink() {
  const sections = $$('section[id], header[id]');
  const navLinks = $$('.nav__link');

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          const id = entry.target.id;
          navLinks.forEach((link) => {
            const href = link.getAttribute('href');
            if (href === `#${id}`) {
              link.style.color = 'var(--clr-primary)';
            } else {
              link.style.color = '';
            }
          });
        }
      });
    },
    { threshold: 0.3 }
  );

  sections.forEach((section) => observer.observe(section));
}

// ─────────────────────────────────────────────────────────────────────────────
// Keyboard accessibility — skip to content
// ─────────────────────────────────────────────────────────────────────────────

function initKeyboardNav() {
  document.addEventListener('keydown', (e) => {
    // Close mobile menu with Escape
    if (e.key === 'Escape') {
      const navLinks = $('.nav__links');
      const hamburger = $('#hamburger');
      if (navLinks && navLinks.classList.contains('open')) {
        navLinks.classList.remove('open');
        hamburger?.setAttribute('aria-expanded', 'false');
        hamburger?.focus();
      }
    }
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Initialize all on DOM ready
// ─────────────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  initNav();
  initTypingAnimation();
  initParticles();
  initCounters();
  initScrollReveal();
  initProjectFilter();
  initToolsStrip();
  initActiveNavLink();
  initKeyboardNav();

  // Console easter egg for security-minded visitors
  console.log(
    `%c🛡️ Cybersecurity Portfolio
%cBuilt by a future SOC Analyst.
%cIf you're inspecting this, you're thinking like a security engineer! 👏
%c
Tools: Python • Bash • Nmap • Wireshark • Burp Suite • Autopsy • FTK Imager
Projects: Blockchain Voting • ARSS Steganography • SOC Monitor • Threat Intel Aggregator
    `,
    'color: #00d4ff; font-size: 18px; font-weight: bold;',
    'color: #94a3b8; font-size: 14px;',
    'color: #10b981; font-size: 12px;',
    'color: #64748b; font-size: 11px; font-family: monospace;'
  );
});
