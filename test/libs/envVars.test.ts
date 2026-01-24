import { expect } from 'chai';
import EnvVars from '../../src/ux/environment.js';

describe('env vars', () => {
  afterEach(() => {
    delete process.env.SAE_MAX_RESULT_VIOLATION_ROWS;
  });

  it('reads default value from env var if no var is set', () => {
    // Act
    const env = new EnvVars();
    const maxRows = env.resolve('SAE_MAX_RESULT_VIOLATION_ROWS');

    // Assert
    expect(maxRows).to.equal(30);
  });

  it('reads default value from env var when var is set', () => {
    // Arrange
    process.env['SAE_MAX_RESULT_VIOLATION_ROWS'] = '40';

    // Act
    const env = new EnvVars();
    const maxRows = env.resolve('SAE_MAX_RESULT_VIOLATION_ROWS');

    // Assert
    expect(maxRows).to.equal(40);
  });
});
