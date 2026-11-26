// In-memory OPFS for the worker tests: one Uint8Array per file name in one
// directory, with the directory-handle and sync-access-handle surface the
// worker uses. Every read is logged.
//
// removeEntry follows the File System Standard (fs.spec.whatwg.org, §2.4.4,
// read 2026-11-26). Its steps take no lock and do not check one, so a file
// whose sync access handle is still open is removed like any other. The
// handle keeps reading and writing that file, which is no longer in the
// directory. A non-empty directory without `recursive` is
// InvalidModificationError, a missing entry NotFoundError, and an error from
// the underlying file system (here: `onRemove` throwing) rejects the call; a
// recursive removal can fail part-way. MDN documents the same exceptions and
// nothing about locks.
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
    /** Set once the file left the directory while this handle was open. */
    detached?: Uint8Array;
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
  const detach = (name: string): void => {
    const bytes = files.get(name) ?? new Uint8Array();
    for (const handle of open.get(name) ?? []) handle.detached ??= bytes;
    files.delete(name);
  };
  const access = (name: string) => {
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
    const bytes = (): Uint8Array =>
      state.detached ?? files.get(name) ?? new Uint8Array();
    const keep = (next: Uint8Array): void => {
      if (state.detached) state.detached = next;
      else files.set(name, next);
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
      hooks.onRemove?.(name, { recursive });
      detach(name);
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
            hooks.onRemove?.(name, { recursive });
            for (const file of [...files.keys()]) detach(file);
          },
        };
      },
      ...extra,
    },
    stats,
  };
};
