import { loadSpec } from '@writ/core';
import { corazaGenerator } from '../src/generators/coraza/index.js';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

process.env['JWKS_ENDPOINT'] ??= 'https://example.com/.well-known/jwks.json';
process.env['AUTH_ISSUER'] ??= 'https://auth.example.com';
process.env['AUTH_AUDIENCE'] ??= 'api.example.com';

const here = new URL('.', import.meta.url).pathname;
const spec = await loadSpec(resolve(here, '../../../fixtures/specs/example.yaml'));
const arts = await corazaGenerator.generate(spec);
const out = resolve(here, '../../../fixtures/configs/coraza/example.expected.yml');
writeFileSync(out, arts[0]!.content);
console.log('Wrote', arts[0]!.content.length, 'bytes →', out);
