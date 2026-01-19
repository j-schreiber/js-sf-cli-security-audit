import z from 'zod';

export type ConfigSchema = {
  schema: z.ZodType;
  dependencies?: ConfigFileDependency[];
  entities?: string;
};

export type ConfigFileDependency = {
  errorName: string;
  path: string[];
};

export type IndexedConfigSchema = Record<string, ConfigSchema>;

export type AuditConfigFileSchema = Record<string, IndexedConfigSchema>;

type ParsedConfigSchemas<T extends IndexedConfigSchema> = {
  [K in keyof T]?: z.infer<T[K]['schema']>;
};

export type ParsedAuditConfig<T extends AuditConfigFileSchema> = {
  [K in keyof T]: T[K] extends IndexedConfigSchema ? ParsedConfigSchemas<T[K]> : never;
};

type ConfigFile<T> = {
  filePath: string;
  totalEntities: number;
  content: T;
};

export type ConfigTypeSaveResult<T extends IndexedConfigSchema> = {
  [K in keyof T]: ConfigFile<z.infer<T[K]['schema']>>;
};

export type AuditConfigSaveResult<T extends AuditConfigFileSchema> = {
  [K in keyof T]: ConfigTypeSaveResult<T[K]>;
};
