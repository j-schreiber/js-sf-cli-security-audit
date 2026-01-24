import { Dictionary } from '@salesforce/ts-types';
import { Env } from '@salesforce/kit';

type EnvVarConfig<Type extends ExpectedTypes> = {
  description: string;
  /**
   * Optional default value, if the env var is not initialised.
   */
  defaultValue: TypeMap[Type];
  /**
   * Expected type for env to automatically cast values
   */
  expectedType: Type;
};

type ExpectedTypes = keyof TypeMap;

export const SUPPORTED_ENV_VARS = {
  SAE_MAX_RESULT_VIOLATION_ROWS: {
    description: 'Maximum number of rows that are displayed for violation tables.',
    expectedType: 'number',
    defaultValue: 30,
  },
} as const satisfies Record<string, EnvVarConfig<ExpectedTypes>>;

type EnvironmentVariable = keyof typeof SUPPORTED_ENV_VARS;
type EnvironmentConfig = typeof SUPPORTED_ENV_VARS;

type TypeMap = {
  string: string;
  number: number;
  boolean: boolean;
};

type InferType<K extends EnvironmentVariable> = TypeMap[EnvironmentConfig[K]['expectedType']];

export default class EnvVars extends Env {
  public constructor(env = process.env) {
    super(env);
  }

  public resolve<P extends EnvironmentVariable>(property: P): InferType<P> | undefined {
    const conf = SUPPORTED_ENV_VARS[property];
    switch (conf.expectedType) {
      case 'number':
        return (this.getNumber(property) ?? conf.defaultValue) as InferType<P>;
      // case 'boolean':
      //   return (this.getBoolean(property) ?? conf.defaultValue) as InferType<P>;
      // case 'string':
      //   return (this.getString(property) ?? conf.defaultValue) as InferType<P>;
      default:
        break;
    }
    return undefined;
  }

  public asDictionary(): Dictionary<unknown> {
    return Object.fromEntries(this.entries());
  }

  public asMap(): Map<string, unknown> {
    return new Map<string, unknown>(this.entries());
  }
}

export const envVars = new EnvVars();
