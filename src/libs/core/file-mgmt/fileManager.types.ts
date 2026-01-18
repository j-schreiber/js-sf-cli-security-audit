import z from 'zod';

type ConfigSchema = {
  schema: z.ZodType;
  dependencies?: ConfigFileDependency[];
};

export type ConfigFileDependency = {
  errorName: string;
  path: string[];
};

type IndexedConfigSchema = Record<string, ConfigSchema>;

export type AuditConfigSchema = Record<string, IndexedConfigSchema>;

type ParseSchemaMap<T extends IndexedConfigSchema> = {
  [K in keyof T]?: z.infer<T[K]['schema']>;
};

export type ParsedAuditConfig<T extends AuditConfigSchema> = {
  [K in keyof T]: T[K] extends IndexedConfigSchema ? ParseSchemaMap<T[K]> : never;
};

// export type ParsedAuditConfig<T extends AuditConfigSchema> = {
//   classifications: { [K in keyof T['classifications']]: z.infer<T['classifications'][K]['schema']> };
//   policies: { [K in keyof T['policies']]: z.infer<T['policies'][K]['schema']> };
// };
