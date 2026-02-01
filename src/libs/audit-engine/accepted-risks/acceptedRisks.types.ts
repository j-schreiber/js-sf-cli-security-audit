import { Policies } from '../registry/shape/auditConfigShape.js';

export type RiskTree = Record<Policies, TreeNode>;

export type TreeNode = LeafNode | BranchNode;

export type BranchNode = { [nodePath: string]: TreeNode };

export type LeafNode = { reason: string };
