export { discardRoomOutbox } from "./outbox";

type Resume = (roomId: string) => Promise<unknown>;
interface Clock {
  now(): number;
  sleep(delayMs: number, signal: AbortSignal): Promise<void>;
}

interface PendingPass {
  controller: AbortController;
  requested: boolean;
  scheduled: boolean;
  running: boolean;
  promise: Promise<void>;
  resolve(): void;
  reject(error: unknown): void;
  failed: boolean;
  error?: unknown;
}

/** Each actual authentication event permits a pass; failures never schedule one. */
export const createOutboxResumeCoordinator = (
  clock: Clock = {
    now: () => Date.now(),
    sleep: (delayMs, signal) =>
      new Promise<void>((resolve) => {
        const done = () => {
          clearTimeout(timer);
          signal.removeEventListener("abort", done);
          resolve();
        };
        const timer = setTimeout(done, delayMs);
        signal.addEventListener("abort", done, { once: true });
      }),
  },
  debounceMs = 5000,
) => {
  let resume: Resume | undefined;
  const pending = new Map<string, PendingPass>();
  const attemptedAt = new Map<string, number>();

  const pump = (roomId: string, pass: PendingPass): void => {
    if (pass.running || pass.scheduled) return;
    pass.scheduled = true;
    const last = attemptedAt.get(roomId);
    const delay =
      last === undefined ? 0 : Math.max(0, last + debounceMs - clock.now());
    const ready =
      delay > 0
        ? clock.sleep(delay, pass.controller.signal)
        : Promise.resolve();
    void ready.then(async () => {
      if (pass.controller.signal.aborted) return;
      pass.scheduled = false;
      pass.running = true;
      // Events before this pass starts are covered by this pass. Events during
      // its awaits request exactly one additional pass, including on failure.
      pass.requested = false;
      attemptedAt.set(roomId, clock.now());
      if (attemptedAt.size > 128)
        attemptedAt.delete(attemptedAt.keys().next().value!);
      try {
        await resume?.(roomId);
      } catch (error) {
        pass.failed = true;
        pass.error = error;
      }
      pass.running = false;
      if (pass.controller.signal.aborted) return;
      if (pass.requested) pump(roomId, pass);
      else {
        // Delete and settle together: a new event after this point creates a
        // fresh entry instead of disappearing behind a settled promise.
        pending.delete(roomId);
        if (pass.failed) pass.reject(pass.error);
        else pass.resolve();
      }
    });
  };

  return {
    stop(roomId?: string): void {
      const ids = roomId === undefined ? [...pending.keys()] : [roomId];
      if (roomId === undefined) attemptedAt.clear();
      else attemptedAt.delete(roomId);
      for (const id of ids) {
        const pass = pending.get(id);
        if (!pass) continue;
        pending.delete(id);
        pass.controller.abort();
        pass.resolve();
      }
    },
    register(handler: Resume): void {
      resume = handler;
    },
    resume(roomId: string): Promise<void> {
      if (!resume) return Promise.resolve();
      const existing = pending.get(roomId);
      if (existing) {
        existing.requested = true;
        pump(roomId, existing);
        return existing.promise;
      }
      let resolve!: () => void;
      let reject!: (error: unknown) => void;
      const promise = new Promise<void>((ok, fail) => {
        resolve = ok;
        reject = fail;
      });
      const pass: PendingPass = {
        controller: new AbortController(),
        requested: true,
        scheduled: false,
        running: false,
        failed: false,
        promise,
        resolve,
        reject,
      };
      pending.set(roomId, pass);
      pump(roomId, pass);
      return promise;
    },
  };
};

const coordinator = createOutboxResumeCoordinator();
export const registerOutboxResume = coordinator.register;
export const resumeRoomOutbox = coordinator.resume;

export const stopRoomOutboxResume = coordinator.stop;
