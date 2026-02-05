import { Policies } from '../registry/definitions.js';

export type RiskTree = Partial<Record<Policies, RuleRisks>>;

export type RuleRisks = Record<string, TreeNode>;

export type TreeNode = LeafNode | BranchNode;

export type BranchNode = { [nodePath: string]: TreeNode };

export type LeafNode = { reason: string };
