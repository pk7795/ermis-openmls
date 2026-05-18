// ========================================
// Application Message Types
// ========================================

export interface Attachment {
    type: 'image' | 'video' | 'file' | 'audio';
    url: string;
    name: string;
    size?: number;
    mimeType?: string;
}

export type MessageType = 'regular' | 'reply' | 'system';
export type MessageStatus = 'sending' | 'sent' | 'received' | 'failed';

export interface ApplicationMessage {
    id: string;
    text: string;
    attachments: Attachment[];
    mentioned_users: string[];
    mentioned_all: boolean;
    parent_id: string | null;
    quoted_message_id: string | null;
    type: MessageType;
    created_at: number;
}

export interface DisplayMessage extends ApplicationMessage {
    sender: string;
    status: MessageStatus;
}

// ========================================
// MLS Types (from WASM)
// ========================================

export interface MlsMember {
    user_id: string;
    index: number;
}

export interface ProcessedMessage {
    is_application_message: boolean;
    is_proposal: boolean;
    is_commit: boolean;
    content: Uint8Array;
    sender_user_id?: string;
    /** Additional Authenticated Data - metadata bound to ciphertext */
    aad: Uint8Array;
}

export interface ProposalResult {
    proposal_ref: Uint8Array;
    bytes: Uint8Array;
}

export interface CommitBundle {
    commit: Uint8Array;
    welcome?: Uint8Array;
    has_welcome: () => boolean;
}

// ========================================
// User State Types
// ========================================

export interface UserState {
    provider: any;  // Provider from WASM
    identity: any;  // Identity from WASM
    group: any | null;  // Group from WASM
}

// ========================================
// Component Props
// ========================================

export interface ChatPanelProps {
    name: string;
    userId: string;
    messages: DisplayMessage[];
    members: MlsMember[];
    epoch: number;
    onSendMessage: (senderId: string, text: string, options?: SendMessageOptions) => void;
    onAddMember?: (userId: string) => void;
    onRemoveMember?: (userId: string) => void;
    onMarkGhost?: (userId: string) => void;
    onExternalJoinPre?: (userId: string) => void;
    onExternalJoinPost?: (userId: string) => void;
    onKeyRotate?: (userId: string) => void;
}

export interface LogEntry {
    message: string;
    type: 'info' | 'success' | 'error' | 'warning' | 'proposal' | 'commit';
    time: string;
}

export interface LogPanelProps {
    logs: LogEntry[];
}

export interface SendMessageOptions {
    attachments?: Attachment[];
    mentioned_users?: string[];
    mentioned_all?: boolean;
    parent_id?: string | null;
    quoted_message_id?: string | null;
}

// ========================================
// E2EE API Types (Metadata Separation)
// ========================================

/**
 * Content that gets encrypted into MLS ciphertext
 * Only sensitive data goes here - server cannot read this
 */
export interface EncryptedContent {
    text: string;
    /** Decryption keys for attachments (if using E2EE file encryption) */
    attachment_keys?: Record<string, string>;
}

/**
 * MLS message type enum matching Bellboy's MLSMessageType
 */
export type MLSMessageType = 'application' | 'commit' | 'proposal' | 'welcome';

/**
 * Additional Authenticated Data (AAD) structure
 * This metadata is bound cryptographically to the ciphertext
 * Server can read but cannot modify without clients detecting
 */
export interface MessageAAD {
    message_id: string;
    sender_id: string;
    channel_id: string;
    created_at: number;  // Unix timestamp
}

/**
 * Serialize AAD for MLS encryption
 */
export const serializeAAD = (aad: MessageAAD): Uint8Array => {
    return new TextEncoder().encode(JSON.stringify(aad));
};

/**
 * Deserialize AAD from decrypted message
 */
export const deserializeAAD = (bytes: Uint8Array): MessageAAD => {
    const json = new TextDecoder().decode(bytes);
    return JSON.parse(json);
};

/**
 * E2EE message payload for API request
 * Combines encrypted content with plaintext metadata
 * Note: AAD is embedded inside mls_ciphertext by MLS protocol, not sent separately
 */
export interface E2EEMessagePayload {
    id: string;
    /** MLS ciphertext (encrypted content + AAD in MLS wire format) */
    mls_ciphertext: number[];  // Uint8Array serialized as array
    /** MLS epoch number */
    mls_epoch: number;
    /** MLS message type */
    mls_message_type: MLSMessageType;
    // ---- Plaintext metadata (server can read) ----
    mentioned_users?: string[];
    mentioned_all?: boolean;
    parent_id?: string | null;
    quoted_message_id?: string | null;
    attachments?: Attachment[];
}

/**
 * Full API request body for E2EE message endpoint
 * POST /channels/{type}/{id}/e2ee/message
 */
export interface E2EEMessageRequest {
    message: E2EEMessagePayload;
}

// ========================================
// Helper Functions
// ========================================

export const createApplicationMessage = ({
    text,
    attachments = [],
    mentioned_users = [],
    mentioned_all = false,
    parent_id = null,
    quoted_message_id = null,
    type = 'regular'
}: {
    text: string;
    attachments?: Attachment[];
    mentioned_users?: string[];
    mentioned_all?: boolean;
    parent_id?: string | null;
    quoted_message_id?: string | null;
    type?: MessageType;
}): ApplicationMessage => ({
    id: crypto.randomUUID(),
    text,
    attachments,
    mentioned_users,
    mentioned_all,
    parent_id,
    quoted_message_id,
    type,
    created_at: Date.now(),
});

export const serializeMessage = (msg: ApplicationMessage): Uint8Array => {
    return new TextEncoder().encode(JSON.stringify(msg));
};

export const deserializeMessage = (bytes: Uint8Array | number[]): ApplicationMessage => {
    const json = new TextDecoder().decode(new Uint8Array(bytes));
    return JSON.parse(json);
};

// ========================================
// E2EE Helper Functions (Metadata Separation)
// ========================================

/**
 * Serialize only the sensitive content for encryption
 * This is what goes into the MLS ciphertext
 */
export const serializeEncryptedContent = (content: EncryptedContent): Uint8Array => {
    return new TextEncoder().encode(JSON.stringify(content));
};

/**
 * Deserialize encrypted content after decryption
 */
export const deserializeEncryptedContent = (bytes: Uint8Array | number[]): EncryptedContent => {
    const json = new TextDecoder().decode(new Uint8Array(bytes));
    return JSON.parse(json);
};

/**
 * Create E2EE message request with separated metadata
 * AAD is already inside the ciphertext, not sent separately
 * @param id - Message UUID
 * @param ciphertext - MLS encrypted content (includes AAD)
 * @param epoch - MLS epoch
 * @param options - Plaintext metadata (server can read)
 */
export const createE2EERequest = (
    id: string,
    ciphertext: Uint8Array,
    epoch: number,
    options: SendMessageOptions = {}
): E2EEMessageRequest => ({
    message: {
        id,
        mls_ciphertext: Array.from(ciphertext),
        mls_epoch: epoch,
        mls_message_type: 'application',
        mentioned_users: options.mentioned_users,
        mentioned_all: options.mentioned_all,
        parent_id: options.parent_id,
        quoted_message_id: options.quoted_message_id,
        attachments: options.attachments,
    }
});
