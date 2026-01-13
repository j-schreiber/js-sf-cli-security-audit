import { expect } from 'chai';
import { formatToLocale, isParseableDate } from '../../src/utils.js';

describe('utils', () => {
  [
    '2025-01-11',
    '2024-01-15T12:34:56Z',
    '2025-01-11T12:00:00',
    '2025-01-11T12:00:00.000Z',
    '2025-01-11T12:00:00Z',
    '2025-02-31',
  ].forEach((input) => {
    it(`returns true for valid date input: ${input}`, () => {
      expect(isParseableDate(input)).to.be.true;
    });
  });

  ['not-a-date', '21.12.2025', 0, 19_000_000_000].forEach((input) => {
    it(`returns false for invalid date input: ${input}`, () => {
      expect(isParseableDate(input)).to.be.false;
    });
  });

  const formatTests = [
    { arg: '2025-01-11', expected: new Date('2025-01-11').toLocaleString() },
    { arg: new Date('2025-01-11'), expected: new Date('2025-01-11').toLocaleString(), testName: 'date-input' },
    { arg: 'Some string', expected: 'Some string' },
    { arg: 1000, expected: Number(1000).toLocaleString() },
    { arg: { nested: 'object' }, expected: '{"nested":"object"}', testName: 'complex-object' },
  ];

  formatTests.forEach(({ arg, expected, testName }) => {
    it(`correctly formats ${testName ?? (arg as string)} to ${expected}`, () => {
      const result = formatToLocale(arg);
      expect(result).to.equal(expected);
    });
  });
});
