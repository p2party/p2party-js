export interface ByteInputConstraints {
  readonly exactLength?: number;
  readonly maximumLength?: number;
}

const typedArrayPrototype = Object.getPrototypeOf(
  Uint8Array.prototype,
) as object;
const typedArrayLengthGetter = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  "length",
)?.get as ((this: Uint8Array) => number) | undefined;
const typedArraySet = Uint8Array.prototype.set;

const rangeError = (
  label: string,
  constraints: ByteInputConstraints,
): RangeError => {
  if (constraints.exactLength !== undefined)
    return new RangeError(
      `${label} must be exactly ${String(constraints.exactLength)} bytes`,
    );
  return new RangeError(`${label} exceeds the supported length`);
};

const requireConstraint = (
  label: string,
  name: string,
  value: number | undefined,
): void => {
  if (value !== undefined && (!Number.isSafeInteger(value) || value < 0))
    throw new RangeError(
      `${label} ${name} must be a non-negative safe integer`,
    );
};

const intrinsicLength = (value: Uint8Array, label: string): number => {
  if (typedArrayLengthGetter === undefined)
    throw new Error(`${label}: Uint8Array length intrinsic is unavailable`);

  const length = Reflect.apply(typedArrayLengthGetter, value, []) as number;
  if (!Number.isSafeInteger(length) || length < 0)
    throw new RangeError(`${label} has an invalid length`);
  return length;
};

const validateOwnedLength = (
  snapshot: Uint8Array,
  label: string,
  constraints: ByteInputConstraints,
): void => {
  const length = intrinsicLength(snapshot, label);
  if (
    (constraints.exactLength !== undefined &&
      length !== constraints.exactLength) ||
    (constraints.maximumLength !== undefined &&
      length > constraints.maximumLength)
  )
    throw rangeError(label, constraints);
};

/**
 * Take an ordinary, owned snapshot of borrowed bytes before a WASM boundary.
 *
 * Typed-array intrinsics are used deliberately: a Proxy can pass `instanceof`
 * while lying about its length, and a real view can shadow `length`, iteration,
 * or species properties. None of those surfaces influence this copy.
 */
export const snapshotByteInput = (
  value: unknown,
  label: string,
  constraints: ByteInputConstraints = {},
): Uint8Array => {
  // Check the untrappable internal-slot predicate first, so even a Proxy with
  // a hostile getPrototypeOf trap is rejected with our stable TypeError.
  if (!ArrayBuffer.isView(value) || !(value instanceof Uint8Array))
    throw new TypeError(`${label} must be a Uint8Array`);

  requireConstraint(label, "exactLength", constraints.exactLength);
  requireConstraint(label, "maximumLength", constraints.maximumLength);
  if (
    constraints.exactLength !== undefined &&
    constraints.maximumLength !== undefined &&
    constraints.exactLength > constraints.maximumLength
  )
    throw new RangeError(`${label} exactLength cannot exceed maximumLength`);

  const length = intrinsicLength(value, label);
  const preflightMaximum = constraints.exactLength ?? constraints.maximumLength;
  if (preflightMaximum !== undefined && length > preflightMaximum)
    throw rangeError(label, constraints);

  const snapshot = new Uint8Array(length);
  try {
    // This takes the typed-array source path and ignores shadowed JS surfaces.
    Reflect.apply(typedArraySet, snapshot, [value]);
  } catch {
    snapshot.fill(0);
    throw new RangeError(`${label} changed while it was being copied`);
  }

  try {
    // Security decisions use only the owned snapshot, never borrowed metadata.
    validateOwnedLength(snapshot, label, constraints);
    return snapshot;
  } catch (cause) {
    snapshot.fill(0);
    throw cause;
  }
};
