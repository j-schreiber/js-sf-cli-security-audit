/**
 * A single violation from a policy rule execution.
 */
export type PolicyRuleViolation = RuleComponentMessage & {
  /**
   * Optional descriptive message that explains how to fix the violation.
   */
  hint?: string;
};

/**
 * A muted violation with additional information why it was muted
 */
export type PolicyRuleViolationMute = PolicyRuleViolation & {
  /**
   * Descriptive reason from allow-config why this violation is muted.
   */
  reason: string;
  /**
   * Path to the config file that allowed this violation for reference.
   */
  allowListEntryPath?: string;
};

/**
 * Details about s config entity of a policy (such as a profile, perm set, user)
 * that did not resolve successfully. This may be because the entity does not exist
 * on the target org or because it is not registered.
 */
export type EntityResolveError = {
  /**
   * Identifier of the entity, e.g. profile name, username, rule, policy, etc
   */
  name: string;
  /**
   * Message that explains, why the entity was not successfully resolved
   */
  message: string;
};

/**
 * Generic message for a particular element of a rule
 */
export type RuleComponentMessage = {
  /**
   * Path to a component. This can be a developer name of a connected app,
   * permission set name or the permission within a profile.
   */
  identifier: string | string[];
  /**
   * Descriptive message of the error, warning or violation.
   */
  message: string;
};

/**
 *
 */
export type PolicyRuleSkipResult = {
  /**
   * Identifier of the rule, as it is configured in the policy.yml.
   */
  name: string;
  /**
   * Descriptive message why the rule was skipped.
   */
  skipReason: string;
};

/**
 * Full execution summary of a single rule. Includes audited entities,
 * violations, execution errors, etc.
 */
export type PolicyRuleExecutionResult = {
  /**
   * Identifier of the rule, as it is configured in the policy.yml.
   */
  ruleName: string;

  /**
   * Short-hand accessor, if an execution had at least one violation.
   */
  isCompliant: boolean;

  /**
   * All violations of the rule that were reported.
   */
  violations: PolicyRuleViolation[];

  /**
   * Identifiers of compliant entities. An entity is compliant, if it has
   * zero violations.
   */
  compliantEntities: string[];

  /**
   * Identifiers of violated entities. Each entity may have several violations,
   * depending on the analysis depth of the rule.
   */
  violatedEntities: string[];

  /**
   * Violations that were identified, but were muted by a matching allow-list.
   * Muted violations do not affect compliance.
   */
  mutedViolations: PolicyRuleViolationMute[];

  /**
   * Components of a rule that were not successfully processed and returned errors from the org
   */
  errors: RuleComponentMessage[];

  /**
   * Components that were not auditable, but did not hinder the execution of the audit
   * Such as permissions on the org that are not classified.
   */
  warnings: RuleComponentMessage[];
};

/**
 * Full execution result of a policy. Contains full results of each executed
 * rule and more information about skipped rules, audited entities, etc.
 */
export type AuditPolicyResult = {
  /**
   * Flag that indicates, if the policy was executed.
   */
  enabled: boolean;

  /**
   * All executed rules were compliant.
   */
  isCompliant: boolean;

  /**
   * Record of rules that were executed. Rules are mapped by their name.
   */
  executedRules: {
    [ruleName: string]: PolicyRuleExecutionResult;
  };

  /**
   * List of rules that exist for the policy that were not executed.
   */
  skippedRules: PolicyRuleSkipResult[];

  /**
   * If the policy was not enabled, a brief message that explains why.
   */
  disabledReason?: string;

  /**
   * Path to the config file that was processed for this audit.
   */
  configPath?: string;

  /**
   * A full list of audited entities. Use together with violations to see, which
   * entities were not compliant.
   */
  auditedEntities: string[];

  /**
   * Full list of entities that were present in the config file, but could not
   * be resolved for this org.
   */
  ignoredEntities: EntityResolveError[];
};

/**
 * The final audit result, contains all policy results.
 */
export type AuditResult = {
  /**
   * All executed policies were compliant.
   */
  isCompliant: boolean;

  /**
   * Id of the audited org.
   */
  orgId: string;

  /**
   * ISO date time of the audit
   */
  auditDate: string;

  /**
   * Record map of all modules (policies) that were run.
   */
  policies: {
    [moduleName: string]: AuditPolicyResult;
  };
};
