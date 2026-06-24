/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#0a0a0a',
          accent: '#00ff9f',
          purple: '#9d4edd',
        }
      }
    },
  },
  plugins: [],
}