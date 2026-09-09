/**
 * Closed error for malformed or fabricated inputs at the trusted admission
 * kernel boundary. Policy denials are ordinary result values and never use
 * this error.
 */
export class AdmissionInputError extends Error {
  override readonly name = "AdmissionInputError";
  readonly code = "invalid-admission-kernel-input" as const;

  constructor(message: string) {
    super(`admission: ${message}`);
  }
}

export const invalidAdmissionInput = (message: string): never => {
  throw new AdmissionInputError(message);
};
