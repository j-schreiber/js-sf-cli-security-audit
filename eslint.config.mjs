import sfConfig from 'eslint-config-salesforce-typescript';
import sfPlugin from 'eslint-plugin-sf-plugin';

export default [
  { ignores: ['scripts/**'] },
  ...sfConfig,
  ...sfPlugin.configs.recommended,
  {
    rules: {
      'header/header': 'off',
      '@typescript-eslint/switch-exhaustiveness-check': ['error', { considerDefaultExhaustiveForUnions: true }],
    },
  },
];
