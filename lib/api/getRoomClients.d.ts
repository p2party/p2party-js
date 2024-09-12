export interface Client {
  id: string;
  createdAt: Date;
  updatedAt: Date;
}
export declare const getRoomClients: (
  signalingServer?: string,
) => Promise<Client[]>;
//# sourceMappingURL=getRoomClients.d.ts.map
