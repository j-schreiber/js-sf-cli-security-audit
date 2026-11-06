import { EventEmitter } from 'node:events';

export type MessageEvent = {
  message: string;
};

export default class ResolveEntityLifecycle extends EventEmitter<{ resolvewarning: [MessageEvent] }> {
  public constructor() {
    super();
  }

  public emitWarn(message: string): void {
    this.emit('resolvewarning', {
      message,
    });
  }
}

export const ResolveLifecycle = new ResolveEntityLifecycle();
