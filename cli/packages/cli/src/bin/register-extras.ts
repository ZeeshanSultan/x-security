// Registration surface for the FULL bin only (x-security.ts / npm bundle). Bundles the
// BYO correctness verbs with the operator-facing extras (doctor, completion,
// update-check, config defaults) so x-security.ts stays within its line budget.
// Deliberately NOT imported by the trimmed `byo` bin: doctor/update-check pull
// in dockerode/undici, which the BYO bundle intentionally excludes.

import type { Command } from 'commander';
import { registerByoCommands } from './byo-commands.js';
import { registerDoctor } from '../commands/doctor.js';
import { registerCompletion } from './completion.js';
import { registerUpdateCheck } from './update-check.js';
import { applyConfigDefaults } from '../config/defaults.js';

export function registerExtras(program: Command): void {
  registerByoCommands(program);
  registerDoctor(program);
  registerCompletion(program);
  registerUpdateCheck(program);
  // Register last: fills unset --format/--timeout/--out from a config file via a
  // preAction hook, so explicit flags and env always win over config.
  applyConfigDefaults(program);
}
