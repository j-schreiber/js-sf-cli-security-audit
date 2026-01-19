import { AuditInitPresets, Preset } from './init.types.js';
import LoosePreset from './presets/loose.js';
import NonePreset from './presets/none.js';
import StrictPreset from './presets/strict.js';

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
