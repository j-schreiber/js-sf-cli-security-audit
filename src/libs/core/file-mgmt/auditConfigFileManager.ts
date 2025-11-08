import path from 'node:path';
import fs, { PathLike } from 'node:fs';
import yaml from 'js-yaml';
import { Messages } from '@salesforce/core';
import { isEmpty } from '../utils.js';
import { classificationDefs, ClassificationNames, policyDefs, PolicyNames } from '../policyRegistry.js';
import { AuditRunConfig, AuditRunConfigClassifications, AuditRunConfigPolicies, ConfigFile } from './schema.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'org.audit.run');

/**
 * Loads an audit run config with the default file manager
 *
 * @param dirPath
 * @returns
 */
export const loadAuditConfig = (dirPath: string): AuditRunConfig => DefaultFileManager.parse(dirPath);

/**
 * Saves a new or modified audit run config with the default file manager
 *
 * @param dirPath
 * @param conf
 */
export const saveAuditConfig = (dirPath: string, conf: AuditRunConfig): void => {
  DefaultFileManager.save(dirPath, conf);
};

/**
 * The file manager streamlines initialisation of an audit config from
 * a source directory and writing updated content back to disk. The directory
 * structure is configurable, but most of the time using the default file manager
 * will be enough.
 */
export default class AuditConfigFileManager {
  private directoryStructure;

  public constructor() {
    this.directoryStructure = {
      policies: policyDefs,
      classifications: classificationDefs,
    };
  }

  /**
   * Parses a directory path for policy and classification files
   * and initialises an audit config from file contents.
   *
   * @param dirPath
   * @returns
   */
  public parse(dirPath: PathLike): AuditRunConfig {
    const classifications = this.parseSubdir(dirPath, 'classifications');
    const policies = this.parseSubdir(dirPath, 'policies');
    const conf = { classifications, policies };
    assertIsMinimalConfig(conf, dirPath);
    this.validateDependencies(conf);
    return conf;
  }

  /**
   * Writes a full audit config to disk. If the config was not
   * saved yet, initialises filePath on each element.
   *
   * @param dirPath
   * @param subdirName
   * @returns
   */
  public save(targetDirPath: string, conf: AuditRunConfig): void {
    this.writeClassifications(conf.classifications, targetDirPath);
    this.writePolicies(conf.policies, targetDirPath);
  }

  private parseSubdir(
    dirPath: PathLike,
    subdirName: keyof typeof this.directoryStructure
  ): Record<string, ConfigFile<unknown>> {
    const parseResults: Record<string, ConfigFile<unknown>> = {};
    Object.entries(this.directoryStructure[subdirName]).forEach(([fileName, fileConfig]) => {
      const filePath = path.join(dirPath.toString(), subdirName, `${fileName}.yml`);
      if (fs.existsSync(filePath)) {
        const fileContent = yaml.load(fs.readFileSync(filePath, 'utf-8'));
        const content = fileConfig.schema.parse(fileContent);
        parseResults[fileName] = { filePath, content };
      }
    });
    return parseResults;
  }

  private writeClassifications(content: AuditRunConfigClassifications, targetDirPath: PathLike): void {
    const dirPath = path.join(targetDirPath.toString(), 'classifications');
    fs.mkdirSync(dirPath, { recursive: true });
    const dirConf = this.directoryStructure.classifications;
    Object.entries(content).forEach(([fileKey, confFile]) => {
      const fileDef = dirConf[fileKey as ClassificationNames];
      if (fileDef && !isEmpty(confFile.content)) {
        // eslint-disable-next-line no-param-reassign
        confFile.filePath = path.join(dirPath, `${fileKey}.yml`);
        fs.writeFileSync(confFile.filePath, yaml.dump(confFile.content));
      }
    });
  }

  private writePolicies(content: AuditRunConfigPolicies, targetDirPath: PathLike): void {
    const dirPath = path.join(targetDirPath.toString(), 'policies');
    fs.mkdirSync(dirPath, { recursive: true });
    const dirConf = this.directoryStructure.policies;
    Object.entries(content).forEach(([fileKey, confFile]) => {
      const fileDef = dirConf[fileKey as PolicyNames];
      if (fileDef && !isEmpty(confFile.content)) {
        // eslint-disable-next-line no-param-reassign
        confFile.filePath = path.join(dirPath, `${fileKey}.yml`);
        fs.writeFileSync(confFile.filePath, yaml.dump(confFile.content));
      }
    });
  }

  private validateDependencies(conf: AuditRunConfig): void {
    Object.keys(conf.policies).forEach((policyName) => {
      const policyDef = this.directoryStructure.policies[policyName as PolicyNames];
      if (policyDef?.dependencies) {
        policyDef.dependencies.forEach((dependency) => {
          if (!dependencyExists(dependency.path, conf)) {
            throw messages.createError(dependency.errorName);
          }
        });
      }
    });
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

function assertIsMinimalConfig(conf: AuditRunConfig, dirPath: PathLike): void {
  if (Object.keys(conf.policies).length === 0) {
    const formattedDirPath = !dirPath || dirPath.toString().length === 0 ? '<root-dir>' : dirPath.toString();
    throw messages.createError('NoAuditConfigFound', [formattedDirPath]);
  }
}

export const DefaultFileManager = new AuditConfigFileManager();
