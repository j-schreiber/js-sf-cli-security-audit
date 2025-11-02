import path from 'node:path';
import fs from 'node:fs';
import yaml from 'js-yaml';
import z from 'zod';
import { Messages } from '@salesforce/core';
import { isEmpty } from '../utils.js';
import {
  AuditRunConfig,
  ConfigFile,
  PermissionsConfigFileSchema,
  PermSetsPolicyFileSchema,
  PolicyFileSchema,
  ProfilesPolicyFileSchema,
} from './schema.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'org.audit.run');

type FileConfig = {
  schema: z.ZodObject;
};

type DirConfig = {
  [fileName: string]: FileConfig;
};

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
  private directoryStructure: Record<string, DirConfig>;

  public constructor() {
    this.directoryStructure = {
      policies: {
        profiles: {
          schema: ProfilesPolicyFileSchema,
        },
        permissionSets: {
          schema: PermSetsPolicyFileSchema,
        },
        connectedApps: {
          schema: PolicyFileSchema,
        },
      },
      classifications: {
        userPermissions: {
          schema: PermissionsConfigFileSchema,
        },
        customPermissions: {
          schema: PermissionsConfigFileSchema,
        },
      },
    };
  }

  /**
   * Parses a directory path for policy and classification files
   * and initialises an audit config from file contents.
   *
   * @param dirPath
   * @returns
   */
  public parse(dirPath: string): AuditRunConfig {
    const classifications = this.parseSubdir(dirPath, 'classifications');
    const policies = capitalizeKeys(this.parseSubdir(dirPath, 'policies'));
    const conf = { classifications, policies };
    assertIsMinimalConfig(conf, dirPath);
    return { classifications, policies };
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
    Object.entries(conf).forEach(([dirName, configFiles]) => {
      fs.mkdirSync(path.join(targetDirPath, dirName), { recursive: true });
      this.writeSubdir(configFiles as Record<string, ConfigFile<unknown>>, dirName, targetDirPath);
    });
  }

  private parseSubdir(dirPath: string, subdirName: string): Record<string, ConfigFile<unknown>> {
    const parseResults: Record<string, ConfigFile<unknown>> = {};
    Object.entries(this.directoryStructure[subdirName]).forEach(([fileName, fileConfig]) => {
      const filePath = path.join(dirPath, subdirName, `${fileName}.yml`);
      if (fs.existsSync(filePath)) {
        const fileContent = yaml.load(fs.readFileSync(filePath, 'utf-8'));
        const content = fileConfig.schema.parse(fileContent);
        parseResults[fileName] = { filePath, content };
      }
    });
    return parseResults;
  }

  private writeSubdir(configFiles: Record<string, ConfigFile<unknown>>, dirName: string, targetDirPath: string): void {
    const dirConf = this.directoryStructure[dirName];
    if (!dirConf) {
      return;
    }
    Object.entries(configFiles).forEach(([fileKey, confFile]) => {
      const uncapitalizedKey = `${fileKey[0].toLowerCase()}${fileKey.slice(1)}`;
      const fileDef = dirConf[uncapitalizedKey];
      if (fileDef && !isEmpty(confFile.content)) {
        // eslint-disable-next-line no-param-reassign
        confFile.filePath = path.join(targetDirPath, dirName, `${uncapitalizedKey}.yml`);
        fs.writeFileSync(confFile.filePath, yaml.dump(confFile.content));
      }
    });
  }
}
}

function capitalizeKeys(object: Record<string, ConfigFile<unknown>>): Record<string, ConfigFile<unknown>> {
  const newObj: Record<string, ConfigFile<unknown>> = {};
  Object.keys(object).forEach((key) => (newObj[`${key[0].toUpperCase()}${key.slice(1)}`] = object[key]));
  return newObj;
}

function assertIsMinimalConfig(conf: AuditRunConfig, dirPath: string): void {
  if (Object.keys(conf.policies).length === 0) {
    const formattedDirPath = !dirPath || dirPath.length === 0 ? '<root-dir>' : dirPath;
    throw messages.createError('NoAuditConfigFound', [formattedDirPath]);
  }
}

export const DefaultFileManager = new AuditConfigFileManager();
