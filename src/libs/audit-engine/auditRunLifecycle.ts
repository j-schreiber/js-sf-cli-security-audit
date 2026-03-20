import { EventEmitter } from 'node:events';

export type MessageEvent = {
  message: string;
};

/**
 * Internal event bus for audit run modules to share messages
 */
export default class AuditRunLifecycle extends EventEmitter {
  public constructor() {
    super();
  }

  public emitResolveWarn(message: string): void {
    this.emit('resolvewarning', {
      message,
    } as MessageEvent);
  }
}

export const AuditRunLifecycleBus = new AuditRunLifecycle();
