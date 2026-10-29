/** Thin wrapper over Nuxt UI's toaster with the three message kinds this app uses. Messages are plain text. */
export function useNotify() {
  const toast = useToast()
  return {
    success: (title: string) => toast.add({ title, color: 'success', icon: 'i-lucide-circle-check', duration: 5000 }),
    error: (title: string) => toast.add({ title, color: 'error', icon: 'i-lucide-circle-alert', duration: 8000 }),
    info: (title: string) => toast.add({ title, color: 'info', icon: 'i-lucide-info', duration: 5000 }),
  }
}
