import LoosePreset from './presets/loose.js';
import NonePreset, { Preset } from './presets/none.js';
import StrictPreset from './presets/strict.js';

export enum AuditInitPresets {
  strict = 'strict',
  loose = 'loose',
}

export function loadPreset(presetName?: AuditInitPresets): Preset {
  switch (presetName) {
    case AuditInitPresets.loose:
      return new LoosePreset();
    case AuditInitPresets.strict:
      return new StrictPreset();
    default:
      return new NonePreset();
  }
}
