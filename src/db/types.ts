// types.ts
export interface Chunk {
  merkleRoot: string;
  chunkIndex: number;
  data: Blob;
  mimeType: string;
}

export interface SendQueue {
  position: number;
  label: string;
  toPeerId: string;
  encryptedData: Blob;
}

// Each method and its arguments/return type
export type WorkerMessages =
  | {
      id: number;
      method: "getDBChunk";
      args: [merkleRootHex: string, chunkIndex: number];
    }
  | {
      id: number;
      method: "existsDBChunk";
      args: [merkleRootHex: string, chunkIndex: number];
    }
  | {
      id: number;
      method: "getDBSendQueue";
      args: [label: string, toPeerId: string];
    }
  | { id: number; method: "getDBAllChunks"; args: [merkleRootHex: string] }
  | { id: number; method: "getDBAllChunksCount"; args: [merkleRootHex: string] }
  | { id: number; method: "setDBChunk"; args: [chunk: Chunk] }
  | { id: number; method: "setDBSendQueue"; args: [item: SendQueue] }
  | {
      id: number;
      method: "deleteDBChunk";
      args: [merkleRootHex: string, chunkIndex?: number];
    }
  | {
      id: number;
      method: "deleteDBSendQueue";
      args: [label: string, toPeerId: string, position?: number];
    }
  | {
      id: number;
      method: "deleteDB";
      args: [];
    };

// Return types for each method
export interface WorkerMethodReturnTypes {
  getDBChunk: Blob | undefined;
  existsDBChunk: boolean;
  getDBSendQueue: SendQueue[];
  getDBAllChunks: Chunk[];
  getDBAllChunksCount: number;
  setDBChunk: void;
  setDBSendQueue: void;
  deleteDBChunk: void;
  deleteDBSendQueue: void;
  deleteDB: void;
}
