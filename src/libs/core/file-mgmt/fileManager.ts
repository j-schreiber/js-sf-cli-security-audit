import path from 'node:path';
import fs, { PathLike } from 'node:fs';
import yaml from 'js-yaml';
import { Messages } from '@salesforce/core';
import { throwAsSfError } from './schema.js';
import { AuditConfigSchema, ConfigFileDependency, ParsedAuditConfig } from './fileManager.types.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'org.audit.run');

/**
 * The file manager streamlines initialisation of an audit config from
 * a source directory and writing updated content back to disk. The directory
 * structure is configurable, but most of the time using the default file manager
 * will be enough.
 */
export default class FileManager<ConfShape extends AuditConfigSchema> {
  public constructor(private schema: ConfShape) {}

  /**
   * Parses a directory path for policy and classification files
   * and initialises an audit config from file contents.
   *
   * @param dirPath
   * @returns
   */
  public parse(dirPath: PathLike): ParsedAuditConfig<ConfShape> {
    const parseResult = {} as ParsedAuditConfig<ConfShape>;
    for (const dirName of typedKeys(this.schema)) {
      // no idea if there is not a better solution than casting to "any"
      // but it works, and tests prove that its somewhat save :).
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-explicit-any
      (parseResult as any)[dirName] = this.parseSubdir(dirName, dirPath);
    }
    assertIsMinimalConfig(parseResult, dirPath);
    this.validateDependencies(parseResult);
    return parseResult;
  }

  private parseSubdir<K extends keyof ConfShape>(
    configType: K,
    dirPath: PathLike
  ): Record<string, ParsedAuditConfig<ConfShape>[K]> {
    const parseResults: Record<string, ParsedAuditConfig<ConfShape>[K]> = {};
    Object.entries(this.schema[configType]).forEach(([fileName, fileConfig]) => {
      const filePath = path.join(dirPath.toString(), configType as string, `${fileName}.yml`);
      if (fs.existsSync(filePath)) {
        const fileContent = yaml.load(fs.readFileSync(filePath, 'utf-8'));
        const parseResult = fileConfig.schema.safeParse(fileContent);
        if (parseResult.success) {
          parseResults[fileName] = parseResult.data as ParsedAuditConfig<ConfShape>[K];
        } else {
          throwAsSfError(`${fileName}.yml`, parseResult.error);
        }
      }
    });
    return parseResults;
  }

  private validateDependencies(parseResult: ParsedAuditConfig<ConfShape>): void {
    for (const config of Object.values(this.schema)) {
      for (const detailShape of Object.values(config)) {
        if (detailShape.dependencies) {
          assertDependencies(detailShape.dependencies, parseResult);
        }
      }
    }
  }
}

function assertIsMinimalConfig(conf: ParsedAuditConfig<AuditConfigSchema>, dirPath: PathLike): void {
  if (Object.keys(conf.policies).length === 0) {
    const formattedDirPath = !dirPath || dirPath.toString().length === 0 ? '<root-dir>' : dirPath.toString();
    throw messages.createError('NoAuditConfigFound', [formattedDirPath]);
  }
}

function typedKeys<T extends object>(obj: T): Array<keyof T> {
  return Object.keys(obj) as Array<keyof T>;
}

function assertDependencies(dependencies: ConfigFileDependency[], parseResult: Record<string, unknown>): void {
  for (const dep of dependencies) {
    if (!dependencyExists(dep.path, parseResult)) {
      throw messages.createError(dep.errorName);
    }
  }
}

function dependencyExists(fullPath: string[], rootNode: Record<string, unknown>): boolean {
  const dep = traverseDependencyPath(fullPath, rootNode);
  return Boolean(dep);
}

function traverseDependencyPath(remainingPath: string[], rootNode: Record<string, unknown>): unknown {
  if (remainingPath.length >= 2) {
    return traverseDependencyPath(remainingPath.slice(1), rootNode[remainingPath[0]] as Record<string, unknown>);
  } else if (remainingPath.length === 0) {
    return undefined;
  } else {
    return rootNode[remainingPath[0]];
  }
}
