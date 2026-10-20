import { spawnSync } from 'node:child_process';
import { readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

let failed = false;
for (const directory of ['src', 'test', 'scripts']) {
  for (const file of await readdir(new URL(`../${directory}/`, import.meta.url))) {
    if (!file.endsWith('.mjs')) continue;
    const result = spawnSync(process.execPath, ['--check', fileURLToPath(new URL(`../${directory}/${file}`, import.meta.url))], { encoding: 'utf8' });
    if (result.status !== 0) { failed = true; process.stderr.write(result.stderr); }
  }
}
if (failed) process.exitCode = 1;
else process.stdout.write('JavaScript syntax checks passed.\n');
