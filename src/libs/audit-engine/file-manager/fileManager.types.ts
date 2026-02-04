import z from 'zod';

// ACTUAL TYPES - THESE DEFINE THE SHAPE

/**
 * Traversable path to dependent config file from the resolved
 * structure (not the shape).
 */
export type ConfigFileDependency = {
  errorName: string;
  path: string[];
};

/**
 * Low-level configuration of a config file. Used to configure parser for
 * file contents and dependencies on other files.
 */
export type ConfigSchema = {
  schema: z.ZodType;
  dependencies?: ConfigFileDependency[];
  entities?: string;
};

/**
 * Config files, indexed by their name (without .yml file extension)
 */
export type IndexedConfigSchema = Record<string, ConfigSchema>;

/**
 * A directory of config files
 */
export type ConfigsFileDir = {
  files: IndexedConfigSchema;
};

/**
 * Index of config file directories (key is directory name)
 */
type IndexedConfigDirectories = Record<string, ConfigsFileDir>;

/**
 * Schema of a directory that contains subdirectories with
 * multiple config files.
 */
export type NestedConfigDir = {
  dirs: IndexedConfigDirectories;
};

/**
 * Final audit config schema type that is used to configure the "shape"
 * of an audit config.
 */
export type AuditConfigShapeDefinition = Record<string, NestedConfigDir | ConfigsFileDir>;

// TYPE EXTRACTION TYPES - Inferring the type from an audit config shape

/**
 * Infers the type from the schema of a config file
 */
type ExtractSchemaType<T> = T extends { schema: infer S extends z.ZodType } ? z.infer<S> : never;

/**
 * Infers the types of the content from a config file directory and
 * returns them indexed by the file names.
 */
type ExtractFilesTypes<T> = T extends { files: infer F } ? { [K in keyof F]?: ExtractSchemaType<F[K]> } : never;

/**
 * Recursively infers the types of config files from a nested directory
 * that contains directories of files. Returns the types indexed by
 * directory name > file name.
 */
type ExtractDirsTypes<T> = T extends { dirs: infer D } ? { [K in keyof D]?: ExtractFilesTypes<D[K]> } : never;

/**
 * Conditional mapping of nested dirs and file dirs
 */
type ExtractConfigTypes<T> = T extends { dirs: unknown }
  ? ExtractDirsTypes<T>
  : T extends { files: unknown }
  ? ExtractFilesTypes<T>
  : never;

/**
 * Top-level extraction type that uses the shape to recursively infer
 * types for nested dirs and file dirs.
 */
export type ExtractAuditConfigTypes<T extends AuditConfigShapeDefinition> = {
  [K in keyof T]: ExtractConfigTypes<T[K]>;
};

// SAVE RESULTS - type extraction that wraps extracted types

export type FileResult<T> = {
  filePath: string;
  totalEntities: number;
  content: T;
};

type ConfigTypeSaveResult<T> = T extends { schema: infer S extends z.ZodType } ? FileResult<z.infer<S>> : never;

type FilesDirectorySaveResult<T> = T extends { files: infer F }
  ? { [K in keyof F]: ConfigTypeSaveResult<F[K]> }
  : never;

type NestedDirectorySaveResult<T> = T extends { dirs: infer D }
  ? { [K in keyof D]: FilesDirectorySaveResult<D[K]> }
  : never;

type DirectoriesSaveResult<T> = T extends { dirs: unknown }
  ? NestedDirectorySaveResult<T>
  : T extends { files: unknown }
  ? FilesDirectorySaveResult<T>
  : never;

/**
 * Top-level type to recursively wrap all config files in a
 * save result.
 */
export type AuditShapeSaveResult<T extends AuditConfigShapeDefinition> = {
  [K in keyof T]: DirectoriesSaveResult<T[K]>;
};
