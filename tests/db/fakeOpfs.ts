// In-memory OPFS for the worker tests: one Uint8Array per file name in one
// directory, with the directory-handle and sync-access-handle surface the
// worker uses. Every read is logged.
//
// It does what Chromium does, as measured by docs/e2e/opfs-remove/probe.mjs
// (result-2026-11-26.json, HeadlessChrome 159):
// - removeEntry of a file whose sync access handle is open rejects with
//   NoModificationAllowedError, and the file stays, its handle still working;
// - removeEntry(directory, { recursive: true }) with such a file inside
//   rejects the same way and removes nothing;
// - once the handle is closed, both resolve;
// - a second createSyncAccessHandle on a file whose first one is open rejects
//   with NoModificationAllowedError.
// (The File System Standard's removeEntry steps, §2.4.4, name no lock, and MDN
// lists no lock error; the browser enforces one anyway.) A non-empty directory
// without `recursive` is InvalidModificationError, a missing entry
// NotFoundError, and an `onRemove` hook that throws stands in for any other
// failure of the device.
//
// A closed handle refuses reads and writes, as a real one does.

export interface FakeOpfsHooks {
  onRead?: (name: string, at: number) => void;
  onWrite?: (name: string, at: number, bytes: Uint8Array) => void;
  /** Called before an entry is removed; throwing is the file system's failure. */
  onRemove?: (name: string, options: { recursive: boolean }) => void;
}

export interface FakeOpfsStats {
  directoryOpens: number;
  closes: string[];
  fileOpens: Array<{ name: string; create: boolean }>;
  reads: Array<{ name: string; at: number; length: number }>;
  /** Sync access handles not closed yet. */
  openHandles: () => number;
  /** The files in the directory, as listing it would show them. */
  list: () => string[];
}

export const fakeOpfs = (
  files: Map<string, Uint8Array>,
  extra: Record<string, unknown> = {},
  hooks: FakeOpfsHooks = {},
): { storage: Record<string, unknown>; stats: FakeOpfsStats } => {
  interface HandleState {
    closed: boolean;
  }
  const open = new Map<string, Set<HandleState>>();
  const stats: FakeOpfsStats = {
    directoryOpens: 0,
    closes: [],
    fileOpens: [],
    reads: [],
    openHandles: () =>
      [...open.values()].reduce(
        (count, handles) =>
          count + [...handles].filter((handle) => !handle.closed).length,
        0,
      ),
    list: () => [...files.keys()].sort(),
  };
  const inUse = (name: string): boolean =>
    [...(open.get(name) ?? [])].some((handle) => !handle.closed);
  const locked = (): DOMException =>
    new DOMException(
      "An attempt was made to modify an object where modifications are not allowed.",
      "NoModificationAllowedError",
    );
  const access = (name: string) => {
    if (inUse(name)) throw locked();
    const state: HandleState = { closed: false };
    let handles = open.get(name);
    if (!handles) {
      handles = new Set();
      open.set(name, handles);
    }
    handles.add(state);
    const usable = (): void => {
      if (state.closed)
        throw new DOMException("handle is closed", "InvalidStateError");
    };
    const bytes = (): Uint8Array => files.get(name) ?? new Uint8Array();
    const keep = (next: Uint8Array): void => {
      files.set(name, next);
    };
    return {
      getSize: () => bytes().length,
      read: (view: ArrayBufferView, { at }: { at: number }) => {
        usable();
        hooks.onRead?.(name, at);
        const buf = bytes();
        const into = new Uint8Array(
          view.buffer,
          view.byteOffset,
          view.byteLength,
        );
        const n = Math.max(0, Math.min(into.length, buf.length - at));
        into.set(buf.subarray(at, at + n));
        stats.reads.push({ name, at, length: n });
        return n;
      },
      truncate: (size: number) => {
        const old = bytes();
        const next = new Uint8Array(size);
        next.set(old.subarray(0, Math.min(size, old.length)));
        keep(next);
      },
      write: (view: ArrayBufferView, { at }: { at: number }) => {
        usable();
        const src = Uint8Array.from(
          new Uint8Array(view.buffer, view.byteOffset, view.byteLength),
        );
        hooks.onWrite?.(name, at, src);
        let buf = bytes();
        if (at + src.length > buf.length) {
          const grown = new Uint8Array(at + src.length);
          grown.set(buf);
          buf = grown;
        }
        buf.set(src, at);
        keep(buf);
        return src.length;
      },
      flush: () => {},
      close: () => {
        state.closed = true;
        stats.closes.push(name);
      },
    };
  };
  const directory = {
    removeEntry: async (
      name: string,
      { recursive = false }: { recursive?: boolean } = {},
    ) => {
      if (!files.has(name))
        throw new DOMException("no such entry", "NotFoundError");
      if (inUse(name)) throw locked();
      hooks.onRemove?.(name, { recursive });
      files.delete(name);
    },
    getFileHandle: async (name: string, options: { create?: boolean } = {}) => {
      if (!options.create && !files.has(name))
        throw new DOMException("no such file", "NotFoundError");
      stats.fileOpens.push({ name, create: options.create === true });
      return {
        createSyncAccessHandle: async () => access(name),
        getFile: async () =>
          new File(
            [(files.get(name) ?? new Uint8Array()) as Uint8Array<ArrayBuffer>],
            name,
          ),
      };
    },
  };
  return {
    storage: {
      getDirectory: async () => {
        stats.directoryOpens += 1;
        return {
          getDirectoryHandle: async () => directory,
          // The reassembly directory itself, removed by a purge.
          removeEntry: async (
            name: string,
            { recursive = false }: { recursive?: boolean } = {},
          ) => {
            if (files.size > 0 && !recursive)
              throw new DOMException(
                "directory is not empty",
                "InvalidModificationError",
              );
            if ([...files.keys()].some(inUse)) throw locked();
            hooks.onRemove?.(name, { recursive });
            files.clear();
          },
        };
      },
      ...extra,
    },
    stats,
  };
};
