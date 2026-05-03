import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  output: 'static',
  vite: {
    plugins: [tailwindcss()],
  },
  build: {
    assets: 'assets', // Changed from '_astro' to fix Go embed issue (_ dirs are excluded)
  },
});
