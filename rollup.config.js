/* eslint-disable no-process-env */

import { builtinModules } from 'module';

import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import replace from '@rollup/plugin-replace';
import { terser } from 'rollup-plugin-terser';
import { wasm } from '@rollup/plugin-wasm';


import pkg from './package.json';

const nodeDependencies = Object.keys(pkg.dependencies);
const wasmOptions = {
  node: { targetEnv: 'node' },
  browser: { targetEnv: 'browser', maxFileSize: undefined } // always inlline (our wasm files are small)
};

const getChunkFileName = (chunkInfo, extension) => {
  // index files result in chunks named simply 'index', so we rename them to include the package name
  if (chunkInfo.name === 'index') {
    const packageName = chunkInfo.facadeModuleId.split('/').at(-2); // assume index file is under the root folder
    return `${packageName}.${extension}`;
  }
  return `[name].${extension}`;
};

const banner =
  `/*! OpenPGP.js v${pkg.version} - ` +
  `${new Date().toISOString().split('T')[0]} - ` +
  `this is LGPL licensed code, see LICENSE/our website ${pkg.homepage} for more information. */`;

const intro = "const globalThis = typeof window !== 'undefined' ? window : typeof global !== 'undefined' ? global : typeof self !== 'undefined' ? self : {};";

const terserOptions = {
  ecma: 2017,
  compress: {
    unsafe: true
  },
  output: {
    comments: '/^(?:!|#__)/',
    preserve_annotations: true
  }
};

export default Object.assign([
  {
    input: 'src/index.js',
    output: [
      { file: 'dist/openpgp.js', format: 'iife', name: 'openpgp', banner, intro },
      { file: 'dist/openpgp.min.js', format: 'iife', name: 'openpgp', banner, intro, plugins: [terser(terserOptions)], sourcemap: true },
      { file: 'dist/openpgp.mjs', format: 'es', banner, intro },
      { file: 'dist/openpgp.min.mjs', format: 'es', banner, intro, plugins: [terser(terserOptions)], sourcemap: true }
    ],
    inlineDynamicImports: true,
    plugins: [
      resolve({
        browser: true
      }),
      commonjs({
        ignore: builtinModules.concat(nodeDependencies)
      }),
      replace({
        'OpenPGP.js VERSION': `OpenPGP.js ${pkg.version}`,
        'require(': 'void(',
        delimiters: ['', '']
      }),
      wasm(wasmOptions.browser)
    ]
  },
  {
    input: 'src/index.js',
    inlineDynamicImports: true,
    external: builtinModules.concat(nodeDependencies),
    output: [
      { file: 'dist/node/openpgp.js', format: 'cjs', name: 'openpgp', banner, intro },
      { file: 'dist/node/openpgp.min.js', format: 'cjs', name: 'openpgp', banner, intro, plugins: [terser(terserOptions)], sourcemap: true },
      { file: 'dist/node/openpgp.mjs', format: 'es', banner, intro },
      { file: 'dist/node/openpgp.min.mjs', format: 'es', banner, intro, plugins: [terser(terserOptions)], sourcemap: true }
    ],
    plugins: [
      resolve(),
      commonjs(),
      replace({
        'OpenPGP.js VERSION': `OpenPGP.js ${pkg.version}`
      }),
      wasm(wasmOptions.node)
    ]
  },
  {
    input: 'src/index.js',
    output: [
      { dir: 'dist/lightweight', entryFileNames: 'openpgp.mjs', chunkFileNames: chunkInfo => getChunkFileName(chunkInfo, 'mjs'), format: 'es', banner, intro },
      { dir: 'dist/lightweight', entryFileNames: 'openpgp.min.mjs', chunkFileNames: chunkInfo => getChunkFileName(chunkInfo, 'min.mjs'), format: 'es', banner, intro, plugins: [terser(terserOptions)], sourcemap: true }
    ],
    preserveEntrySignatures: 'allow-extension',
    plugins: [
      resolve({
        browser: true
      }),
      commonjs({
        ignore: builtinModules.concat(nodeDependencies)
      }),
      replace({
        'OpenPGP.js VERSION': `OpenPGP.js ${pkg.version}`,
        'require(': 'void(',
        delimiters: ['', '']
      }),
      wasm(wasmOptions.browser)
    ]
  },
  {
    input: 'test/unittests.js',
    output: [
      { file: 'test/lib/unittests-bundle.js', format: 'es', intro, sourcemap: true }
    ],
    inlineDynamicImports: true,
    external: ['../..', '../../..'],
    plugins: [
      resolve({
        browser: true
      }),
      commonjs({
        ignore: builtinModules.concat(nodeDependencies)
      }),
      replace({
        "import openpgpjs from '../../..';": `import * as openpgpjs from '/dist/${process.env.npm_config_lightweight ? 'lightweight/' : ''}openpgp.mjs'; window.openpgp = openpgpjs;`,
        'require(': 'void(',
        delimiters: ['', '']
      }),
      wasm(wasmOptions.browser)
    ]
  }
].filter(config => {
  config.output = config.output.filter(output => {
    return (output.file || output.dir + '/' + output.entryFileNames).includes(
      process.env.npm_config_build_only || // E.g. `npm install --build-only=lightweight`.
      'dist' // Don't build test bundle by default.
    );
  });
  return config.output.length;
}), {
  allow_empty: true // Fake option to trick rollup into accepting empty config array when filtered above.
});
