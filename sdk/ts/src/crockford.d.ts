export declare const CROCKFORD_ALPHABET: string;
export declare const ROOM_ID_BYTES: 5;
export declare const ROOM_ID_LENGTH: 8;

export declare function encodeRoomId(bytes: Uint8Array): string;
export declare function normalizeRoomId(input: string): string;
export declare function decodeRoomId(input: string): Uint8Array;
export declare function isValidRoomId(input: string, options?: { strict?: boolean }): boolean;
export declare function formatRoomId(roomId: string): string;
export declare function generateRoomId(): string;
