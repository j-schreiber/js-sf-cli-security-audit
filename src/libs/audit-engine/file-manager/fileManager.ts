import path from 'node:path';
import fs, { PathLike } from 'node:fs';
import yaml from 'js-yaml';
import { ZodError } from 'zod';
import { Messages } from '@salesforce/core';
import {
  AuditConfigFileSchema,
  AuditConfigSaveResult,
  ConfigFileDependency,
  ParsedAuditConfig,
} from './fileManager.types.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'org.audit.run');

/**
 * The file manager streamlines initialisation of an audit config from
 * a source directory and writing updated content back to disk. The directory
 * structure is configurable, but most of the time using the default file manager
 * will be enough.
 */
export default class FileManager<ConfShape extends AuditConfigFileSchema> {
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

  /**
   * Writes a full audit config to disk. The file manager attempts
   * to save the config based on the injected schema.
   *
   * @param targetDirPath
   * @param conf AuditConfig to save
   * @returns
   */
  public save(targetDirPath: string, conf: Record<string, unknown>): AuditConfigSaveResult<ConfShape> {
    const saveResult: Record<string, unknown> = {};
    for (const dirName of typedKeys(this.schema)) {
      if (!conf[dirName as string]) {
        continue;
      }
      const dirPath = path.join(targetDirPath.toString(), dirName as string);
      fs.mkdirSync(dirPath, { recursive: true });
      const subSaveResult: Record<string, unknown> = {};
      for (const [key, def] of Object.entries(this.schema[dirName])) {
        const maybeContent = (conf[dirName as string] as Record<string, unknown>)[key] as Record<string, unknown>;
        if (maybeContent) {
          const filePath = path.join(dirPath, `${key}.yml`);
          const entitiesCount = def.entities ? countEntities(maybeContent[def.entities]) : 0;
          subSaveResult[key] = { filePath, content: maybeContent, totalEntities: entitiesCount };
          fs.writeFileSync(filePath, yaml.dump(maybeContent));
        }
      }
      saveResult[dirName as string] = subSaveResult;
    }
    return saveResult as AuditConfigSaveResult<ConfShape>;
  }

  //      PRIVATE ZONE

  private parseSubdir<K extends keyof ConfShape>(
    configType: K,
    dirPath: PathLike
  ): Record<string, ParsedAuditConfig<ConfShape>[K]> {
    const parseResults: Record<string, ParsedAuditConfig<ConfShape>[K]> = {};
    for (const [fileName, fileConfig] of Object.entries(this.schema[configType])) {
      const filePath = path.join(dirPath.toString(), configType as string, `${fileName}.yml`);
      if (!fs.existsSync(filePath)) {
        continue;
      }
      const fileContent = yaml.load(fs.readFileSync(filePath, 'utf-8'));
      const parseResult = fileConfig.schema.safeParse(fileContent);
      if (parseResult.success) {
        parseResults[fileName] = parseResult.data as ParsedAuditConfig<ConfShape>[K];
      } else {
        throwAsSfError(`${fileName}.yml`, parseResult.error);
      }
    }
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

function countEntities(content: unknown): number {
  if (content) {
    return Object.entries(content).length;
  } else {
    return 0;
  }
}

function assertIsMinimalConfig(conf: ParsedAuditConfig<AuditConfigFileSchema>, dirPath: PathLike): void {
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

function throwAsSfError(fileName: string, parseError: ZodError): never {
  const issues = parseError.issues.map((zodIssue) =>
    zodIssue.path.length > 0 ? `${zodIssue.message} in "${zodIssue.path.join('.')}"` : zodIssue.message
  );
  throw messages.createError('error.InvalidConfigFileSchema', [fileName, issues.join(', ')]);
}
