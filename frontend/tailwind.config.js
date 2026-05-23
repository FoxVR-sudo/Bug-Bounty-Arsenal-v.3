/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          DEFAULT: '#4F46E5',
          600: '#4338CA',
          700: '#3730A3',
        },
        secondary: {
          DEFAULT: '#10B981',
          600: '#059669',
          700: '#047857',
        },
        danger: {
          DEFAULT: '#EF4444',
          600: '#DC2626',
          700: '#B91C1C',
        },
        warning: {
          DEFAULT: '#F59E0B',
          600: '#D97706',
          700: '#B45309',
        },
        info: {
          DEFAULT: '#3B82F6',
          600: '#2563EB',
          700: '#1D4ED8',
        },
      },
    },
  },
  plugins: [require('@tailwindcss/typography')],
}
