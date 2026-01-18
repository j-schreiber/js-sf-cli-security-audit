import { expect } from 'chai';
import { permissionAllowedInPreset } from '../../src/libs/audit-engine/registry/helpers/permissionsScanning.js';

describe('is allowed in preset', () => {
  it('allows LOW in STANDARD_USER', () => {
    expect(permissionAllowedInPreset('low', 'standard user')).to.be.true;
    expect(permissionAllowedInPreset('low', 'standard_user')).to.be.true;
    expect(permissionAllowedInPreset('LOW', 'STANDARD_USER')).to.be.true;
  });
  it('allows LOW in POWER_USER', () => {
    expect(permissionAllowedInPreset('low', 'power user')).to.be.true;
    expect(permissionAllowedInPreset('low', 'power_user')).to.be.true;
    expect(permissionAllowedInPreset('LOW', 'POWER_USER')).to.be.true;
  });
  it('allows LOW in ADMIN', () => {
    expect(permissionAllowedInPreset('low', 'admin')).to.be.true;
    expect(permissionAllowedInPreset('LOW', 'ADMIN')).to.be.true;
  });
  it('allows LOW in DEVELOPER', () => {
    expect(permissionAllowedInPreset('low', 'developer')).to.be.true;
    expect(permissionAllowedInPreset('LOW', 'DEVELOPER')).to.be.true;
  });
  it('forbids MEDIUM in STANDARD_USER', () => {
    expect(permissionAllowedInPreset('medium', 'standard user')).to.be.false;
    expect(permissionAllowedInPreset('medium', 'standard_user')).to.be.false;
    expect(permissionAllowedInPreset('MEDIUM', 'STANDARD_USER')).to.be.false;
  });
  it('allows MEDIUM in POWER_USER', () => {
    expect(permissionAllowedInPreset('medium', 'power user')).to.be.true;
    expect(permissionAllowedInPreset('medium', 'power_user')).to.be.true;
    expect(permissionAllowedInPreset('MEDIUM', 'POWER_USER')).to.be.true;
  });
  it('allows MEDIUM in ADMIN', () => {
    expect(permissionAllowedInPreset('medium', 'admin')).to.be.true;
    expect(permissionAllowedInPreset('MEDIUM', 'ADMIN')).to.be.true;
  });
  it('allows MEDIUM in DEVELOPER', () => {
    expect(permissionAllowedInPreset('medium', 'developer')).to.be.true;
    expect(permissionAllowedInPreset('MEDIUM', 'DEVELOPER')).to.be.true;
  });
  it('forbids HIGH in STANDARD_USER', () => {
    expect(permissionAllowedInPreset('high', 'standard user')).to.be.false;
    expect(permissionAllowedInPreset('high', 'standard_user')).to.be.false;
    expect(permissionAllowedInPreset('HIGH', 'STANDARD_USER')).to.be.false;
  });
  it('forbids HIGH in POWER_USER', () => {
    expect(permissionAllowedInPreset('high', 'power user')).to.be.false;
    expect(permissionAllowedInPreset('high', 'power_user')).to.be.false;
    expect(permissionAllowedInPreset('HIGH', 'POWER_USER')).to.be.false;
  });
  it('allows HIGH in ADMIN', () => {
    expect(permissionAllowedInPreset('high', 'admin')).to.be.true;
    expect(permissionAllowedInPreset('HIGH', 'ADMIN')).to.be.true;
  });
  it('allows HIGH in DEVELOPER', () => {
    expect(permissionAllowedInPreset('high', 'developer')).to.be.true;
    expect(permissionAllowedInPreset('HIGH', 'DEVELOPER')).to.be.true;
  });
});
