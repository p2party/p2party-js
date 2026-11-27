// In-memory OPFS for the worker tests: one Uint8Array per file name in one
// directory, with the directory-handle and sync-access-handle surface the
// worker uses. Every read is logged.
//
// Where the worker depends on what a browser does, this does what
// HeadlessChrome 159 was measured to do by docs/e2e/opfs-remove/probe.mjs
// (result-2026-11-26.json). No other browser was measured.
// - removeEntry of a file whose sync access handle is open rejects with
//   NoModificationAllowedError, and the file stays, its handle still working.
//   The same holds when the handle belongs to another Worker; another file of
//   the directory is removed normally.
// - removeEntry(directory, { recursive: true }) with such a file inside
//   rejects the same way and removes nothing, the other files included.
// - Once the handle is closed, both resolve.
// - A second createSyncAccessHandle on a file whose first one is open rejects
//   with NoModificationAllowedError.
// - Listing the directory resolves while a file in it is held open, here or in
//   another Worker, and lists that file. A file is listed as soon as
//   getFileHandle({ create: true }) has resolved, before anything is written
//   to it; a creation requested while a listing runs is not in that listing.
// A handle opened through `storage` by a test, and not by the worker, is what
// a handle held by another context looks like to the worker: it cannot close
// it.
//
// Not measured, and chosen here: a non-empty directory without `recursive` is
// InvalidModificationError, a missing entry NotFoundError, and an `onRemove`
// hook that throws stands in for any other failure of the device.
//
// A closed handle refuses reads and writes, as a real one does.

export interface FakeOpfsHooks {
  onRead?: (name: string, at: number) => void;
  onWrite?: (name: string, at: number, bytes: Uint8Array) => void;
  /** Called before an entry is removed; throwing is the file system's failure. */
  onRemove?: (name: string, options: { recursive: boolean }) => void;
  /** Called when a removal is refused because the file is held open. */
  onHeldRemove?: (name: string) => void;
  /** Awaited when a listing of the directory starts, before it reads it. */
  onList?: () => void | Promise<void>;
  /** Called when a sync access handle is closed, after it is. */
  onClose?: (name: string) => void;
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
        hooks.onClose?.(name);
      },
    };
  };
  // The directory exists from the start (tests seed `files` directly), stops
  // existing when it is removed, and exists again once it is asked for with
  // `create`.
  let present = true;
  const fileHandle = (name: string) => ({
    kind: "file",
    name,
    createSyncAccessHandle: async () => access(name),
    getFile: async () =>
      new File(
        [(files.get(name) ?? new Uint8Array()) as Uint8Array<ArrayBuffer>],
        name,
      ),
  });
  // One listing sees the directory as it was when the listing started.
  const listing = async function* (): AsyncGenerator<
    [string, ReturnType<typeof fileHandle>]
  > {
    await hooks.onList?.();
    for (const name of [...files.keys()].sort()) yield [name, fileHandle(name)];
  };
  const directory = {
    entries: () => listing(),
    keys: async function* (): AsyncGenerator<string> {
      for await (const [name] of listing()) yield name;
    },
    values: async function* (): AsyncGenerator<ReturnType<typeof fileHandle>> {
      for await (const [, handle] of listing()) yield handle;
    },
    removeEntry: async (
      name: string,
      { recursive = false }: { recursive?: boolean } = {},
    ) => {
      if (!files.has(name))
        throw new DOMException("no such entry", "NotFoundError");
      if (inUse(name)) {
        hooks.onHeldRemove?.(name);
        throw locked();
      }
      hooks.onRemove?.(name, { recursive });
      files.delete(name);
    },
    getFileHandle: async (name: string, options: { create?: boolean } = {}) => {
      if (!options.create && !files.has(name))
        throw new DOMException("no such file", "NotFoundError");
      stats.fileOpens.push({ name, create: options.create === true });
      // Listed from now on, empty until something is written.
      if (!files.has(name)) files.set(name, new Uint8Array());
      return fileHandle(name);
    },
  };
  return {
    storage: {
      getDirectory: async () => {
        stats.directoryOpens += 1;
        return {
          getDirectoryHandle: async (
            _name: string,
            options: { create?: boolean } = {},
          ) => {
            if (!present && !options.create)
              throw new DOMException("no such directory", "NotFoundError");
            present = true;
            return directory;
          },
          // The reassembly directory itself, removed by a purge.
          removeEntry: async (
            name: string,
            { recursive = false }: { recursive?: boolean } = {},
          ) => {
            if (!present)
              throw new DOMException("no such entry", "NotFoundError");
            if (files.size > 0 && !recursive)
              throw new DOMException(
                "directory is not empty",
                "InvalidModificationError",
              );
            if ([...files.keys()].some(inUse)) throw locked();
            hooks.onRemove?.(name, { recursive });
            files.clear();
            present = false;
          },
        };
      },
      ...extra,
    },
    stats,
  };
};
