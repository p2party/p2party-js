import { describe, expect, test } from "bun:test";

import {
  validateClaimEvaluationShapeV1,
  validateClaimRegistryV1,
  validateExecutableRendezvousKernelManifestV1,
  validateFormalProofResultV1,
  validateNormativeRegistriesV1,
  validateV04ReleaseConformanceShapeV1,
} from "../../src/blindRendezvous/normativeKernel";

import type {
  ClaimDefinitionV1,
  ClaimEvaluationV1,
  ClaimRegistryV1,
  ExecutableRendezvousKernelManifestV1,
  FormalObligationRegistryV1,
  FormalProofResultV1,
} from "../../src/blindRendezvous/normativeKernel";

const bytes32 = (value: number): Uint8Array => new Uint8Array(32).fill(value);

const entrypointIdsByModule = {
  1: [1],
  2: [2],
  3: [3],
  4: [4],
  5: [5],
  6: [6, 7],
  7: [8],
  8: [9],
} as const;

const manifest: ExecutableRendezvousKernelManifestV1 = {
  version: 1,
  canonicalBinarySchemaHash: bytes32(1),
  modules: ([1, 2, 3, 4, 5, 6, 7, 8] as const).map((moduleId) => ({
    moduleId,
    entrypoints: entrypointIdsByModule[moduleId].map((entrypointId) => ({
      entrypointId,
      inputSchemaHash: bytes32(entrypointId * 3),
      outputSchemaHash: bytes32(entrypointId * 3 + 1),
      normativeSourceHash: bytes32(entrypointId * 3 + 2),
    })),
    executableArtifactHash: bytes32(moduleId * 4 + 1),
    normativeSourceTreeHash: bytes32(moduleId * 4 + 2),
    canonicalVectorSetHash: bytes32(moduleId * 4 + 3),
  })),
};

const definition: ClaimDefinitionV1 = {
  claimId: 1,
  scopeKind: "release",
  scopeSchemaHash: bytes32(40),
  predicateEntrypointId: 9,
  assumptionIds: [1],
  requiredEvidenceKindIds: [1],
  prerequisiteClaimIds: [],
  requiredFormalObligationIds: [1],
  wordingIdByState: {
    notImplemented: 100,
    notEvaluated: 101,
    unknown: 102,
    expired: 103,
    failed: 104,
    satisfied: 105,
  },
  forbiddenWordingIds: [200],
};

const claimRegistry: ClaimRegistryV1 = {
  version: 1,
  assumptions: [
    {
      assumptionId: 1,
      kind: "cryptographic",
      canonicalStatement: "The selected primitive remains secure.",
      verification: { kind: "declared-foundational" },
    },
  ],
  evidenceKinds: [
    {
      evidenceKindId: 1,
      canonicalSchemaHash: bytes32(41),
      verifierEntrypointId: 9,
    },
  ],
  claims: [definition],
  wordingCatalogHash: bytes32(42),
};

const formalRegistry: FormalObligationRegistryV1 = {
  version: 1,
  obligations: [
    {
      obligationId: 1,
      kind: "computational-game",
      modelSourceHash: bytes32(50),
      propertySourceHash: bytes32(51),
      abstractionMapHash: bytes32(53),
      toolchainLockHash: bytes32(54),
      proofScopeSchemaHash: bytes32(55),
      scopeCoverageEntrypointId: 9,
      assumptionIds: [1],
    },
  ],
};

const satisfiedEvaluation: ClaimEvaluationV1 = {
  version: 1,
  input: {
    releaseRegistryHash: bytes32(60),
    claimRegistryHash: bytes32(61),
    claimId: 1,
    scopeDigest: bytes32(62),
    evaluatedAtMs: 10_000n,
    evaluationClockUncertaintyMs: 100n,
    implementationPresent: true,
    evaluationDatasetDigest: bytes32(63),
  },
  state: "satisfied",
  reasonIds: [],
  selectedWordingId: 105,
  validThroughMs: 20_000n,
};

const currentClaimRoots = {
  releaseRegistryHash: satisfiedEvaluation.input.releaseRegistryHash,
  claimRegistryHash: satisfiedEvaluation.input.claimRegistryHash,
};

describe("blind-rendezvous normative kernel registry", () => {
  test("accepts one complete closed kernel and cross-resolved registries", () => {
    expect(() =>
      validateNormativeRegistriesV1(manifest, claimRegistry, formalRegistry),
    ).not.toThrow();
  });

  test("rejects missing, reordered, and malformed kernel modules", () => {
    expect(() =>
      validateExecutableRendezvousKernelManifestV1({
        ...manifest,
        modules: manifest.modules.slice(0, 7),
      }),
    ).toThrow("every kernel module exactly once");

    expect(() =>
      validateExecutableRendezvousKernelManifestV1({
        ...manifest,
        modules: [
          manifest.modules[1],
          manifest.modules[0],
          ...manifest.modules.slice(2),
        ],
      }),
    ).toThrow("sorted by moduleId");

    expect(() =>
      validateExecutableRendezvousKernelManifestV1({
        ...manifest,
        canonicalBinarySchemaHash: new Uint8Array(31),
      }),
    ).toThrow("exactly 32 bytes");

    expect(() =>
      validateExecutableRendezvousKernelManifestV1({
        ...manifest,
        modules: manifest.modules.map((module) =>
          module.moduleId === 1
            ? { ...module, executableArtifactHash: new Uint8Array(31) }
            : module,
        ),
      }),
    ).toThrow("exactly 32 bytes");

    expect(() =>
      validateExecutableRendezvousKernelManifestV1({
        ...manifest,
        modules: manifest.modules.map((module) =>
          module.moduleId === 6
            ? { ...module, entrypoints: module.entrypoints.slice(0, 1) }
            : module,
        ),
      }),
    ).toThrow("closed module interface");
  });

  test("rejects unresolved references and cyclic claim prerequisites", () => {
    expect(() =>
      validateClaimRegistryV1({
        ...claimRegistry,
        claims: [{ ...definition, assumptionIds: [2] }],
      }),
    ).toThrow("references unknown id 2");

    const second: ClaimDefinitionV1 = {
      ...definition,
      claimId: 2,
      prerequisiteClaimIds: [1],
    };
    expect(() =>
      validateClaimRegistryV1({
        ...claimRegistry,
        claims: [{ ...definition, prerequisiteClaimIds: [2] }, second],
      }),
    ).toThrow("must be acyclic");
  });

  test("keeps positive wording distinct from non-positive states", () => {
    expect(() =>
      validateClaimRegistryV1({
        ...claimRegistry,
        claims: [
          {
            ...definition,
            wordingIdByState: {
              ...definition.wordingIdByState,
              unknown: definition.wordingIdByState.satisfied,
            },
          },
        ],
      }),
    ).toThrow("reuses its satisfied wording");
  });

  test("keeps foundational and evidence-verified assumptions disjoint", () => {
    expect(() =>
      validateClaimRegistryV1({
        ...claimRegistry,
        assumptions: [
          {
            ...claimRegistry.assumptions[0],
            verification: {
              kind: "declared-foundational",
              verifierEntrypointId: 9,
            },
          },
        ],
      } as unknown as ClaimRegistryV1),
    ).toThrow("missing or unexpected fields");

    expect(() =>
      validateClaimRegistryV1({
        ...claimRegistry,
        assumptions: [
          {
            ...claimRegistry.assumptions[0],
            verification: {
              kind: "evidence-verified",
              verifierEntrypointId: 9,
            },
          },
        ],
      }),
    ).not.toThrow();
  });

  test("uses claim definitions as the sole claim-to-obligation reference", () => {
    expect(() =>
      validateNormativeRegistriesV1(
        manifest,
        {
          ...claimRegistry,
          claims: [{ ...definition, requiredFormalObligationIds: [2] }],
        },
        formalRegistry,
      ),
    ).toThrow("references unknown id 2");
  });

  test("validates proof-scope schema and entrypoint bindings", () => {
    expect(() =>
      validateNormativeRegistriesV1(manifest, claimRegistry, {
        ...formalRegistry,
        obligations: [
          {
            ...formalRegistry.obligations[0],
            proofScopeSchemaHash: new Uint8Array(31),
          },
        ],
      }),
    ).toThrow("exactly 32 bytes");

    expect(() =>
      validateNormativeRegistriesV1(manifest, claimRegistry, {
        ...formalRegistry,
        obligations: [
          {
            ...formalRegistry.obligations[0],
            scopeCoverageEntrypointId: 10,
          },
        ],
      } as unknown as FormalObligationRegistryV1),
    ).toThrow("registered kernel entrypoint");
  });

  test("requires all six v0.4 formal-obligation IDs", () => {
    const v04FormalRegistry: FormalObligationRegistryV1 = {
      ...formalRegistry,
      obligations: [1, 2, 3, 4, 5, 6].map((obligationId) => ({
        ...formalRegistry.obligations[0],
        obligationId,
      })),
    };
    expect(() =>
      validateV04ReleaseConformanceShapeV1(
        manifest,
        claimRegistry,
        v04FormalRegistry,
      ),
    ).not.toThrow();
    expect(() =>
      validateV04ReleaseConformanceShapeV1(manifest, claimRegistry, {
        ...v04FormalRegistry,
        obligations: v04FormalRegistry.obligations.filter(
          (obligation) => obligation.obligationId !== 4,
        ),
      }),
    ).toThrow("missing formal obligation 4");
  });

  test("rejects accessor-backed artifact fields", () => {
    const withAccessor = { ...manifest };
    Object.defineProperty(withAccessor, "version", {
      get: () => 1,
      enumerable: true,
    });
    expect(() =>
      validateExecutableRendezvousKernelManifestV1(
        withAccessor as ExecutableRendezvousKernelManifestV1,
      ),
    ).toThrow("enumerable data property");
  });
});

describe("claim-evaluation artifact shape", () => {
  test("checks shape only; synthetic hashes do not authorize claim wording", () => {
    // The byte-filled roots and dataset digest below are fixtures, not
    // canonically derived or verified evidence.
    expect(() =>
      validateClaimEvaluationShapeV1(
        satisfiedEvaluation,
        definition,
        currentClaimRoots,
      ),
    ).not.toThrow();

    expect(() =>
      validateClaimEvaluationShapeV1(
        {
          ...satisfiedEvaluation,
          state: "expired",
          reasonIds: [1],
          selectedWordingId: 103,
          validThroughMs: null,
        },
        definition,
        currentClaimRoots,
      ),
    ).not.toThrow();
  });

  test("rejects mutations of either current registry root", () => {
    expect(() =>
      validateClaimEvaluationShapeV1(
        {
          ...satisfiedEvaluation,
          input: {
            ...satisfiedEvaluation.input,
            releaseRegistryHash: bytes32(71),
          },
        },
        definition,
        currentClaimRoots,
      ),
    ).toThrow("current release registry");

    expect(() =>
      validateClaimEvaluationShapeV1(
        {
          ...satisfiedEvaluation,
          input: {
            ...satisfiedEvaluation.input,
            claimRegistryHash: bytes32(72),
          },
        },
        definition,
        currentClaimRoots,
      ),
    ).toThrow("current claim registry");
  });

  test("rejects internally inconsistent result shapes", () => {
    expect(() =>
      validateClaimEvaluationShapeV1(
        {
          ...satisfiedEvaluation,
          input: {
            ...satisfiedEvaluation.input,
            implementationPresent: false,
          },
        },
        definition,
        currentClaimRoots,
      ),
    ).toThrow("implementation presence");

    expect(() =>
      validateClaimEvaluationShapeV1(
        {
          ...satisfiedEvaluation,
          selectedWordingId: 101,
        },
        definition,
        currentClaimRoots,
      ),
    ).toThrow("wrong wording");

    expect(() =>
      validateClaimEvaluationShapeV1(
        { ...satisfiedEvaluation, validThroughMs: null },
        definition,
        currentClaimRoots,
      ),
    ).toThrow("future valid-through timestamp");

    expect(() =>
      validateClaimEvaluationShapeV1(
        {
          ...satisfiedEvaluation,
          validThroughMs: satisfiedEvaluation.input.evaluatedAtMs,
        },
        definition,
        currentClaimRoots,
      ),
    ).toThrow("future valid-through timestamp");
  });

  test("requires exact fields and canonical state reasons", () => {
    expect(() =>
      validateClaimEvaluationShapeV1(
        {
          ...satisfiedEvaluation,
          syntheticDependencyDigest: bytes32(73),
        } as unknown as ClaimEvaluationV1,
        definition,
        currentClaimRoots,
      ),
    ).toThrow("missing or unexpected fields");

    expect(() =>
      validateClaimEvaluationShapeV1(
        {
          ...satisfiedEvaluation,
          state: "expired",
          selectedWordingId: 103,
        },
        definition,
        currentClaimRoots,
      ),
    ).toThrow("must contain a reason");

    expect(() =>
      validateClaimEvaluationShapeV1(
        {
          ...satisfiedEvaluation,
          state: "expired",
          selectedWordingId: 103,
          reasonIds: [2, 1],
          validThroughMs: null,
        },
        definition,
        currentClaimRoots,
      ),
    ).toThrow("strictly sorted");
  });
});

describe("formal proof-result binding", () => {
  const obligation = formalRegistry.obligations[0];
  const proofResult: FormalProofResultV1 = {
    version: 1,
    releaseRegistryHash: bytes32(80),
    formalObligationRegistryHash: bytes32(81),
    obligationId: 1,
    modelSourceHash: obligation.modelSourceHash,
    propertySourceHash: obligation.propertySourceHash,
    assumptionSetHash: bytes32(52),
    abstractionMapHash: obligation.abstractionMapHash,
    toolchainLockHash: obligation.toolchainLockHash,
    proofScopeDigest: bytes32(82),
    implementationArtifactSetDigest: bytes32(83),
    canonicalTraceSetDigest: bytes32(84),
    schedulerWorkloadDigest: bytes32(85),
    result: "proved-within-scope",
    proofArtifactDigest: bytes32(86),
    counterexampleTraceDigest: null,
  };
  const formalProofContext = {
    releaseRegistryHash: proofResult.releaseRegistryHash,
    formalObligationRegistryHash: proofResult.formalObligationRegistryHash,
    expectedAssumptionSetHash: proofResult.assumptionSetHash,
  };

  test("binds the exact obligation sources, toolchain, and result shape", () => {
    expect(() =>
      validateFormalProofResultV1(proofResult, obligation, formalProofContext),
    ).not.toThrow();

    expect(() =>
      validateFormalProofResultV1(
        { ...proofResult, propertySourceHash: bytes32(87) },
        obligation,
        formalProofContext,
      ),
    ).toThrow("does not bind");

    expect(() =>
      validateFormalProofResultV1(
        { ...proofResult, result: "counterexample" },
        obligation,
        formalProofContext,
      ),
    ).toThrow("counterexample state and trace");

    expect(() =>
      validateFormalProofResultV1(
        {
          ...proofResult,
          canonicalTraceSetDigest: new Uint8Array(31),
        },
        obligation,
        formalProofContext,
      ),
    ).toThrow("exactly 32 bytes");

    expect(() =>
      validateFormalProofResultV1(
        { ...proofResult, assumptionSetHash: bytes32(90) },
        obligation,
        formalProofContext,
      ),
    ).toThrow("derived assumption set");
  });

  test("rejects mutations of either current proof registry root", () => {
    expect(() =>
      validateFormalProofResultV1(
        { ...proofResult, releaseRegistryHash: bytes32(88) },
        obligation,
        formalProofContext,
      ),
    ).toThrow("current release registry");

    expect(() =>
      validateFormalProofResultV1(
        { ...proofResult, formalObligationRegistryHash: bytes32(89) },
        obligation,
        formalProofContext,
      ),
    ).toThrow("current formal-obligation registry");
  });
});
