/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  darkMode: ['class'],
  corePlugins: {
    preflight: false
  },
  theme: {
    extend: {
      boxShadow: {
        soft: '0 18px 46px rgba(17, 24, 39, 0.1)'
      }
    }
  },
  plugins: []
};
