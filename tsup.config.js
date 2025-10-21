import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    'index': 'index.js',
    'ipcrypt-deterministic': 'src/ipcrypt-deterministic.js',
    'ipcrypt-nd': 'src/ipcrypt-nd.js',
    'ipcrypt-ndx': 'src/ipcrypt-ndx.js',
    'ipcrypt-pfx': 'src/ipcrypt-pfx.js',
    'utils': 'src/utils.js',
  },
  format: ['cjs', 'esm'],
  dts: true,
  clean: true,
  sourcemap: true,
  splitting: false,
  treeshake: true,
  minify: false,
  outDir: 'dist',
  external: ['crypto'],
  skipNodeModulesBundle: true,
});
