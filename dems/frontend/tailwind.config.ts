import type { Config } from 'tailwindcss'

/** Colour tokens live in src/index.css as space-separated RGB channels so Tailwind's opacity modifiers work. */
const token = (name: string) => `rgb(var(--${name}) / <alpha-value>)`

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        canvas: { from: token('canvas-from'), to: token('canvas-to') },
        ink: { DEFAULT: token('ink'), soft: token('ink-soft'), faint: token('ink-faint') },
        // Dark orange accent (#D9480F / #C2410C)
        accent: { DEFAULT: token('accent'), strong: token('accent-strong'), soft: token('accent-soft') },
        // Apple system colours (fills) and their AA-contrast text variants (-ink)
        apple: {
          blue: token('apple-blue'), 'blue-ink': token('apple-blue-ink'),
          green: token('apple-green'), 'green-ink': token('apple-green-ink'),
          red: token('apple-red'), 'red-ink': token('apple-red-ink'),
          amber: token('apple-amber'), 'amber-ink': token('apple-amber-ink'),
        },
        hairline: 'rgba(0, 0, 0, 0.06)',
      },
      fontFamily: {
        // Inter only, everywhere. `font-mono` deliberately maps to Inter as well (hashes use tabular figures).
        sans: ['Inter', 'ui-sans-serif', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['Inter', 'ui-sans-serif', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
      },
      borderRadius: { '2xl': '1.25rem', '3xl': '1.75rem', '4xl': '2.25rem' },
      letterSpacing: { display: '-0.045em', heading: '-0.03em' },
      backdropBlur: { glass: '20px', 'glass-lg': '32px' },
      boxShadow: {
        'glass-sm': '0 1px 2px rgba(0, 0, 0, 0.04), 0 2px 8px -2px rgba(0, 0, 0, 0.06)',
        'glass-md': '0 1px 2px rgba(0, 0, 0, 0.04), 0 10px 30px -10px rgba(0, 0, 0, 0.12)',
        'glass-lg': '0 2px 4px rgba(0, 0, 0, 0.04), 0 24px 60px -20px rgba(0, 0, 0, 0.18)',
      },
      keyframes: {
        'fade-up': { from: { opacity: '0', transform: 'translateY(8px)' }, to: { opacity: '1', transform: 'translateY(0)' } },
        'scale-in': { from: { opacity: '0', transform: 'scale(0.97)' }, to: { opacity: '1', transform: 'scale(1)' } },
        'slide-in-left': { from: { transform: 'translateX(-100%)' }, to: { transform: 'translateX(0)' } },
        shimmer: { '100%': { transform: 'translateX(100%)' } },
      },
      animation: {
        'fade-up': 'fade-up 0.45s cubic-bezier(0.22, 1, 0.36, 1) both',
        'scale-in': 'scale-in 0.18s cubic-bezier(0.22, 1, 0.36, 1) both',
        'slide-in-left': 'slide-in-left 0.28s cubic-bezier(0.22, 1, 0.36, 1) both',
        shimmer: 'shimmer 1.6s infinite',
      },
    },
  },
  plugins: [],
} satisfies Config
