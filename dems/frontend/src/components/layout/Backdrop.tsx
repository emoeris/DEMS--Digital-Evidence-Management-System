/** Soft luminous blue and orange light behind every screen (the glow in the reference, tuned for a light canvas). */
export function Backdrop() {
  return (
    <div aria-hidden className="pointer-events-none fixed inset-0 -z-10 overflow-hidden">
      <div className="absolute -left-40 -top-48 h-[620px] w-[620px] rounded-full bg-apple-blue/25 blur-[130px]" />
      <div className="absolute -right-48 top-6 h-[640px] w-[640px] rounded-full bg-accent/25 blur-[140px]" />
      <div className="absolute -bottom-64 left-[26%] h-[520px] w-[520px] rounded-full bg-accent-soft/25 blur-[150px]" />
    </div>
  )
}
