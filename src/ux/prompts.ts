import select from '@inquirer/select';
import checkbox from '@inquirer/checkbox';

/**
 * Thin indirection around inquirer prompts. Commands call through this object
 * so tests can stub the prompt (inquirer default exports cannot be stubbed
 * directly under ESM).
 */
const Prompts: { select: typeof select; checkbox: typeof checkbox } = {
  select,
  checkbox,
};

export default Prompts;
