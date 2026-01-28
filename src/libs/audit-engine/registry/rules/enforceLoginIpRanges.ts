import z from 'zod';
import { Messages } from '@salesforce/core';
import { Optional } from '@jsforce/jsforce-node';
import { Profile } from '@jsforce/jsforce-node/lib/api/metadata.js';
import { createDigest } from '../../../../utils.js';
import { PartialPolicyRuleResult, RuleAuditContext } from '../context.types.js';
import { throwAsSfError } from '../schema.js';
import { ResolvedProfile } from '../policies/profiles.js';
import PolicyRule, { ConfigurableRuleOptions } from './policyRule.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const msgs = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'rules.enforceLoginIpRanges');

type IpRangesResult = {
  missingRanges: NormalizedIpRange[];
  excessiveRanges: NormalizedIpRange[];
};

type NormalizedIpRange = {
  /** Starting address for the range */
  startAddress: string;
  /** Ending address for the range */
  endAddress: string;
  /** 8-char length hash to normalize ip ranges */
  digest: string;
  /** Optional description */
  description?: Optional<string>;
};

type DefinitiveResolvedProfile = Required<ResolvedProfile>;

const EnforceLoginOptionsSchema = z.strictObject({
  noExcessiveRanges: z.boolean().default(false),
});

type EnforceLoginOptions = z.infer<typeof EnforceLoginOptionsSchema>;

export default class EnforceLoginIpRanges extends PolicyRule<ResolvedProfile> {
  private readonly ruleOpts: EnforceLoginOptions;

  public constructor(opts: ConfigurableRuleOptions<EnforceLoginOptions>) {
    super(opts);
    this.ruleOpts = parseRuleOptions(opts.ruleConfig);
  }

  public run(context: RuleAuditContext<ResolvedProfile>): Promise<PartialPolicyRuleResult> {
    const result = this.initResult();
    const resolvedProfiles = context.resolvedEntities;
    for (const profile of Object.values(resolvedProfiles)) {
      // if no IP ranges are defined, profile is not evaluated
      if (!ensureProperties(profile)) {
        continue;
      }
      const evalResult = evaluateLoginIps(profile);
      for (const missing of evalResult.missingRanges) {
        const actualRanges = aggregateActualRanges(profile.metadata.loginIpRanges);
        const rangeFormatted = `${missing.startAddress} - ${missing.endAddress}`;
        if (actualRanges.length > 0) {
          result.violations.push({
            identifier: [profile.name, missing.digest],
            message: msgs.getMessage('violation.profile-ip-ranges-do-not-satisfy', [
              rangeFormatted,
              actualRanges.length,
            ]),
            details: actualRanges,
          });
        } else {
          result.violations.push({
            identifier: [profile.name, missing.digest],
            message: msgs.getMessage('violation.profile-requires-ip-ranges', [rangeFormatted]),
          });
        }
      }
      if (this.ruleOpts.noExcessiveRanges) {
        for (const excessive of evalResult.excessiveRanges) {
          result.violations.push({
            identifier: [profile.name, excessive.digest],
            message: msgs.getMessage('violation.profile-allows-excessive-range', [formatIpRange(excessive)]),
          });
        }
      }
    }
    return Promise.resolve(result);
  }
}

function ensureProperties(profile: ResolvedProfile): profile is DefinitiveResolvedProfile {
  return profile.allowedLoginIps !== undefined && profile.allowedLoginIps.length > 0 && profile.metadata !== undefined;
}

function evaluateLoginIps(profile: DefinitiveResolvedProfile): IpRangesResult {
  const result: IpRangesResult = {
    missingRanges: [],
    excessiveRanges: profile.metadata.loginIpRanges.map((ipRange) => ({
      endAddress: ipRange.endAddress,
      startAddress: ipRange.startAddress,
      description: ipRange.description,
      digest: createDigest(`${ipRange.startAddress}-${ipRange.endAddress}`),
    })),
  };
  for (const allowedRange of profile.allowedLoginIps) {
    const digest = createDigest(`${allowedRange.from}-${allowedRange.to}`);
    const enforcingEntry = result.excessiveRanges.findIndex((range) => range.digest === digest);
    if (enforcingEntry >= 0) {
      result.excessiveRanges.splice(enforcingEntry, 1);
    } else {
      result.missingRanges.push({ startAddress: allowedRange.from, endAddress: allowedRange.to, digest });
    }
  }
  return result;
}

function aggregateActualRanges(actualRanges: Profile['loginIpRanges']): string[] {
  return actualRanges.map((range) => formatIpRange(range));
}

function formatIpRange(range: Omit<NormalizedIpRange, 'digest'>): string {
  return range.description
    ? `${range.startAddress} - ${range.endAddress} (${range.description})`
    : `${range.startAddress} - ${range.endAddress}`;
}

function parseRuleOptions(anyObject?: unknown): EnforceLoginOptions {
  const parseResult = EnforceLoginOptionsSchema.safeParse(anyObject ?? {});
  if (parseResult.success) {
    return parseResult.data;
  } else {
    throwAsSfError('profiles.yml', parseResult.error, ['rules', 'EnforceLoginIpRanges', 'options']);
  }
}
