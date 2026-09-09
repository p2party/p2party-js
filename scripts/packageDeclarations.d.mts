export function preparePackageDeclarations(options: {
  packageRoot: string;
  sourceRoot: string;
}): { retained: string[]; removed: number; removedBytes: number };
export function validatePackageDeclarations(options: {
  packageRoot: string;
  projectRoot: string;
  consumerRoot: string;
}): void;
