import select from '@inquirer/select';

/**
 * Thin indirection around inquirer prompts. Commands call through this object
 * so tests can stub the prompt (inquirer default exports cannot be stubbed
 * directly under ESM).
 */
const Prompts: { select: typeof select } = {
  select,
};

export default Prompts;
