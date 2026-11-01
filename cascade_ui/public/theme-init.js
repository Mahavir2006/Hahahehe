// Apply the saved or system theme before first paint (no flash). External file so the CSP can forbid inline scripts.
try {
  var t = localStorage.getItem("cs-theme") || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark")
  document.documentElement.dataset.theme = t
} catch (e) {}
