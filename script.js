const observer = new IntersectionObserver(
  (entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.classList.add("is-visible");
        observer.unobserve(entry.target);
      }
    });
  },
  {
    threshold: 0.18,
  }
);

document
  .querySelectorAll(".hero-copy, .hero-panel, .section-heading, .feature-card, .workflow-step, .terminal-card, .query-card, .pillars article, .cta-section")
  .forEach((element) => {
    element.classList.add("reveal");
    observer.observe(element);
  });
