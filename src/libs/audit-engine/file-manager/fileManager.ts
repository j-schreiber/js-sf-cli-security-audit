/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-explicit-any */
import path from 'node:path';
import fs, { PathLike } from 'node:fs';
import yaml from 'js-yaml';
import { ZodError } from 'zod';
import { Messages } from '@salesforce/core';
import {
  AuditConfigShapeDefinition,
  AuditShapeSaveResult,
  ConfigFileDependency,
  ConfigsFileDir,
  ExtractAuditConfigTypes,
  FileResult,
  NestedConfigDir,
} from './fileManager.types.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'org.audit.run');

/**
 * The file manager streamlines initialisation of an audit config from
 * a source directory and writing updated content back to disk. The directory
 * structure is configurable, but most of the time using the default file manager
 * will be enough.
 */
export default class FileManager<ConfShape extends AuditConfigShapeDefinition> {
  public constructor(private schema: ConfShape) {}

  /**
   * Parses a directory path for policy and classification files
   * and initialises an audit config from file contents.
   *
   * @param dirPath
   * @returns
   */
  public parse(dirPath: PathLike): ExtractAuditConfigTypes<ConfShape> {
    // no idea if there is not a better solution than casting to "any"
    // but it works, and tests prove that its somewhat save :).
    const parseResult: any = {};
    for (const dirName of typedKeys(this.schema)) {
      parseResult[dirName] = this.parseSubdir(dirName, dirPath);
    }
    assertIsMinimalConfig(parseResult, dirPath);
    this.validateDependencies(parseResult);
    return parseResult as ExtractAuditConfigTypes<ConfShape>;
  }

  /**
   * Writes a full audit config to disk. The file manager attempts
   * to save the config based on the injected schema.
   *
   * @param targetDirPath
   * @param conf AuditConfig to save
   * @returns
   */
  public save(targetDirPath: string, conf: Record<string, unknown>): AuditShapeSaveResult<ConfShape> {
    const saveResult: Record<string, unknown> = {};
    for (const dirName of typedKeys(this.schema)) {
      if (!conf[dirName.toString()]) {
        continue;
      }
      const dirDefinition = this.schema[dirName.toString()];
      if (isFilesDir(dirDefinition)) {
        const dirConf: DirSaveConfig = {
          dirContent: conf[dirName.toString()],
          targetPath: path.join(targetDirPath.toString(), dirName.toString()),
          dirDefinition,
        };
        fs.mkdirSync(dirConf.targetPath, { recursive: true });
        saveResult[dirName.toString()] = writeSubdir(dirConf);
      }
    }
    return saveResult as AuditShapeSaveResult<ConfShape>;
  }

  //      PRIVATE ZONE

  private parseSubdir<K extends keyof ConfShape>(configType: K, dirPath: PathLike): Record<string, unknown> {
    const dirToParse = this.schema[configType];
    if (isFilesDir(dirToParse)) {
      return parseFilesDirectory(dirToParse, path.join(dirPath.toString(), configType.toString()));
    } else if (isNestedDir(dirToParse)) {
      const subResults: Record<string, unknown> = {};
      for (const [subDirName, subDirConfig] of Object.entries(dirToParse.dirs)) {
        subResults[subDirName] = parseFilesDirectory(
          subDirConfig,
          path.join(dirPath.toString(), configType.toString(), subDirName)
        );
      }
      return subResults;
    }
    return {};
  }

  private validateDependencies(parseResult: ExtractAuditConfigTypes<ConfShape>): void {
    for (const [configType, config] of Object.entries(this.schema)) {
      if (isFilesDir(config)) {
        for (const [configName, detailShape] of Object.entries(config.files)) {
          if (detailShape.dependencies && parseResult[configType][configName]) {
            assertDependencies(detailShape.dependencies, parseResult);
          }
        }
      }
    }
  }
}

function writeSubdir(conf: DirSaveConfig): Record<string, FileResult<unknown>> {
  const dirSaveResults: Record<string, FileResult<unknown>> = {};
  for (const [fileName, fileDefinition] of Object.entries(conf.dirDefinition.files)) {
    const maybeContent = conf.dirContent[fileName];
    if (maybeContent) {
      const filePath = path.join(conf.targetPath, `${fileName}.yml`);
      const entitiesCount = fileDefinition.entities ? countEntities(maybeContent[fileDefinition.entities]) : 0;
      dirSaveResults[fileName] = { filePath, content: maybeContent, totalEntities: entitiesCount };
      fs.writeFileSync(filePath, yaml.dump(maybeContent));
    }
  }
  return dirSaveResults;
}

type DirSaveConfig = {
  dirDefinition: ConfigsFileDir;
  targetPath: string;
  dirContent: any;
};

function parseFilesDirectory(def: ConfigsFileDir, dirPath: PathLike): Record<string, unknown> {
  const parseResults: Record<string, unknown> = {};
  for (const [fileName, fileConfig] of Object.entries(def.files)) {
    const filePath = path.join(dirPath.toString(), `${fileName}.yml`);
    if (!fs.existsSync(filePath)) {
      continue;
    }
    const fileContent = yaml.load(fs.readFileSync(filePath, 'utf-8'));
    const parseResult = fileConfig.schema.safeParse(fileContent);
    if (parseResult.success) {
      parseResults[fileName] = parseResult.data;
    } else {
      throwAsSfError(`${fileName}.yml`, parseResult.error);
    }
  }
  return parseResults;
}

function isFilesDir(dir: ConfigsFileDir | NestedConfigDir): dir is ConfigsFileDir {
  return 'files' in dir;
}

function isNestedDir(dir: ConfigsFileDir | NestedConfigDir): dir is NestedConfigDir {
  return 'dirs' in dir;
}

function countEntities(content: unknown): number {
  if (content) {
    return Object.entries(content).length;
  } else {
    return 0;
  }
}

function assertIsMinimalConfig(conf: any, dirPath: PathLike): void {
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
