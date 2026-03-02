import { EventEmitter } from 'node:events';

export type MessageEvent = {
  message: string;
};

export default class ResolveEntityLifecycle extends EventEmitter {
  public constructor() {
    super();
  }

  public emitWarn(message: string): void {
    this.emit('resolvewarning', {
      message,
    } as MessageEvent);
  }
}

export const ResolveLifecycle = new ResolveEntityLifecycle();
