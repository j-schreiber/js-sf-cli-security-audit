import z from 'zod';
import { Messages } from '@salesforce/core';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'org.audit.run');

export function throwAsSfError(fileName: string, parseError: z.ZodError, rulePath?: PropertyKey[]): never {
  const issues = parseError.issues.map((zodIssue) => {
    const definitivePath = rulePath ? [...rulePath, ...zodIssue.path] : zodIssue.path;
    return definitivePath.length > 0 ? `${zodIssue.message} in "${definitivePath.join('.')}"` : zodIssue.message;
  });
  throw messages.createError('error.InvalidConfigFileSchema', [fileName, issues.join(', ')]);
}
