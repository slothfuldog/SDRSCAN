// Dark mode follows the operating system. Nuxt UI themes on the `dark` class; we toggle it here
// (a regular bundled script, so no inline script is needed for the CSP).
export default defineNuxtPlugin(() => {
  const query = window.matchMedia('(prefers-color-scheme: dark)')
  const apply = () => document.documentElement.classList.toggle('dark', query.matches)
  apply()
  query.addEventListener('change', apply)
})
