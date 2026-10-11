import {build} from 'esbuild';
import {writeFile} from 'node:fs/promises';

const common = {
  entryPoints: ['src/index.ts'],
  bundle: true,
  platform: 'browser',
  target: 'es2022',
  sourcemap: true,
  legalComments: 'linked',
};
await Promise.all([
  build({...common, format: 'esm', outfile: 'build/index.js'}),
  build({...common, format: 'cjs', outfile: 'build/index.cjs'}),
  build({
    ...common,
    format: 'iife',
    globalName: 'PasswordsSqnfaWeb',
    minify: true,
    outfile: 'build/passwords-sqnfa-web.min.js',
  }),
]);
await writeFile('build/package.json', JSON.stringify({type: 'module'}) + '\n');
