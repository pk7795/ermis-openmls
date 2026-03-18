import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Shield, Users, Key, UserPlus, UserMinus, RefreshCw, UsersRound } from 'lucide-react';
import ChatPanel from './components/ChatPanel';
import LogPanel from './components/LogPanel';
import {
    UserState,
    DisplayMessage,
    LogEntry,
    SendMessageOptions,
    EncryptedContent,
    MessageAAD,
    createApplicationMessage,
    serializeMessage,
    deserializeMessage,
    serializeEncryptedContent,
    deserializeEncryptedContent,
    serializeAAD,
    deserializeAAD,
    createE2EERequest,
} from './types';

import init, {
    Provider,
    Identity,
    Group,
    KeyPackage,
} from './wasm/openmls_wasm.js';

const CHANNEL_CID = "team:demo_channel_001";

type LogType = 'info' | 'success' | 'error' | 'warning' | 'proposal' | 'commit';

function App(): React.ReactElement {
    const [wasmReady, setWasmReady] = useState<boolean>(false);
    const [logs, setLogs] = useState<LogEntry[]>([]);

    // Dynamic user management
    const [users, setUsers] = useState<Map<string, UserState>>(new Map());
    const usersRef = useRef<Map<string, UserState>>(users);
    // Helper: update users state AND ref synchronously (avoids stale ref from useEffect)
    const setUsersAndRef = useCallback((updater: (prev: Map<string, UserState>) => Map<string, UserState>) => {
        setUsers(prev => {
            const next = updater(prev);
            usersRef.current = next;
            return next;
        });
    }, []);
    const [userMessages, setUserMessages] = useState<Map<string, DisplayMessage[]>>(new Map());
    const [newMemberName, setNewMemberName] = useState<string>('');

    // Group state
    const [groupCreated, setGroupCreated] = useState<boolean>(false);
    const [adminUserId, setAdminUserId] = useState<string | null>(null);
    const [pendingProposals, setPendingProposals] = useState<number>(0);

    const addLog = useCallback((message: string, type: LogType = 'info') => {
        const time = new Date().toLocaleTimeString();
        setLogs(prev => [...prev, { message, type, time }]);
    }, []);

    // Initialize WASM
    useEffect(() => {
        const initWasm = async () => {
            try {
                await init();
                addLog('WASM module initialized successfully (Production APIs)', 'success');
                setWasmReady(true);
            } catch (error) {
                addLog(`Failed to initialize WASM: ${(error as Error).message}`, 'error');
            }
        };
        initWasm();
    }, [addLog]);

    // Helper: get user state
    const getUser = useCallback((userId: string): UserState | undefined => {
        return users.get(userId);
    }, [users]);

    // Helper: update a single user in the map
    const updateUser = useCallback((userId: string, updater: (prev: UserState) => UserState) => {
        setUsersAndRef(prev => {
            const newMap = new Map(prev);
            const existing = newMap.get(userId);
            if (existing) {
                newMap.set(userId, updater(existing));
            }
            return newMap;
        });
    }, [setUsersAndRef]);

    // Helper: add messages for a user
    const addMessageForUser = useCallback((userId: string, msg: DisplayMessage) => {
        setUserMessages(prev => {
            const newMap = new Map(prev);
            const existing = newMap.get(userId) || [];
            newMap.set(userId, [...existing, msg]);
            return newMap;
        });
    }, []);

    // Add a new user (create identity)
    const addNewUser = useCallback((name: string) => {
        const userId = name.toLowerCase().trim();
        if (!userId) return;
        if (users.has(userId)) {
            addLog(`User "${userId}" already exists!`, 'warning');
            return;
        }

        try {
            const provider = new Provider();
            const identity = new Identity(provider, userId);
            addLog(`✓ ${name} identity created (user_id: ${identity.user_id})`, 'success');

            setUsersAndRef(prev => {
                const newMap = new Map(prev);
                newMap.set(userId, { provider, identity, group: null });
                return newMap;
            });
            setUserMessages(prev => {
                const newMap = new Map(prev);
                newMap.set(userId, []);
                return newMap;
            });

            // First user becomes admin
            if (users.size === 0 && !adminUserId) {
                setAdminUserId(userId);
                addLog(`${name} is the admin (first user)`, 'info');
            }
        } catch (error) {
            addLog(`Error creating identity for ${name}: ${(error as Error).message}`, 'error');
        }
    }, [users, adminUserId, addLog, setUsersAndRef]);

    // Create group with CID (admin only)
    const createGroupWithCid = useCallback(() => {
        if (!adminUserId) return;
        const admin = users.get(adminUserId);
        if (!admin) return;

        try {
            addLog(`Creating group with CID: ${CHANNEL_CID}`, 'info');

            const group = Group.create_with_cid(admin.provider, admin.identity, CHANNEL_CID);
            addLog(`✓ Group created! cid: ${group.cid()}, epoch: ${group.epoch()}`, 'success');

            updateUser(adminUserId, prev => ({ ...prev, group }));
            setGroupCreated(true);
        } catch (error) {
            addLog(`Error creating group: ${(error as Error).message}`, 'error');
        }
    }, [adminUserId, users, updateUser, addLog]);

    // Add a single member to the group
    const addMemberToGroup = useCallback((userId: string) => {
        if (!adminUserId) return;
        // Use ref to always get latest state
        const currentUsers = usersRef.current;
        const admin = currentUsers.get(adminUserId);
        const member = currentUsers.get(userId);
        if (!admin?.group || !member) return;
        if (member.group) {
            addLog(`${userId} is already in the group!`, 'warning');
            return;
        }

        try {
            addLog(`=== Add Member: ${userId} ===`, 'info');

            // Step 1: Create key package
            const kp = member.identity.key_package(member.provider);
            addLog(`Created key package for ${userId}`, 'info');

            // Step 2: Propose add
            const proposal = admin.group.propose_add_member(admin.provider, admin.identity, kp);
            addLog(`📝 Proposal: Add ${userId} (ref: ${proposal.proposal_ref.slice(0, 8).join(',')})`, 'proposal');

            // Step 2.5: Broadcast proposal to existing group members BEFORE commit
            currentUsers.forEach((u, uid) => {
                if (uid !== adminUserId && uid !== userId && u.group) {
                    try {
                        u.group.process_message(u.provider, proposal.bytes);
                        addLog(`${uid} received add proposal`, 'info');
                    } catch (e) {
                        addLog(`${uid} error processing proposal: ${(e as Error).message}`, 'error');
                    }
                }
            });

            // Step 3: Commit
            addLog('Committing proposal...', 'commit');
            const commitBundle = admin.group.commit_pending_proposals(admin.provider, admin.identity);
            addLog(`✓ Commit created! has_welcome: ${commitBundle.has_welcome()}`, 'commit');

            // Step 4: Broadcast commit to existing group members BEFORE merge
            const commitBytes = commitBundle.commit;
            currentUsers.forEach((u, uid) => {
                if (uid !== adminUserId && uid !== userId && u.group) {
                    try {
                        u.group.process_message(u.provider, commitBytes);
                        addLog(`${uid} processed add-member commit (epoch: ${u.group.epoch()})`, 'info');
                        updateUser(uid, prev => ({ ...prev, group: prev.group }));
                    } catch (e) {
                        addLog(`${uid} error processing commit: ${(e as Error).message}`, 'error');
                    }
                }
            });

            // Step 5: Merge pending commit for admin
            admin.group.merge_pending_commit(admin.provider);
            addLog(`✓ Commit merged! New epoch: ${admin.group.epoch()}`, 'success');

            // Step 6: New member joins with Welcome
            const ratchetTree = admin.group.export_ratchet_tree();
            const welcome = commitBundle.welcome;

            const memberGroup = Group.join_with_welcome(member.provider, welcome, ratchetTree);
            addLog(`✓ ${userId} joined! epoch: ${memberGroup.epoch()}, cid: ${memberGroup.cid()}`, 'success');

            updateUser(userId, prev => ({ ...prev, group: memberGroup }));
            updateUser(adminUserId, prev => ({ ...prev, group: prev.group }));

            // Log members
            const members = admin.group.members();
            addLog(`Group members: ${members.map((m: { user_id: string }) => m.user_id).join(', ')}`, 'info');

        } catch (error) {
            addLog(`Error adding member ${userId}: ${(error as Error).message}`, 'error');
        }
    }, [adminUserId, updateUser, addLog]);

    // Batch add ALL pending members with Try-Filter-ReBatch fallback
    const addMultipleMembersToGroup = useCallback(() => {
        if (!adminUserId) return;
        const currentUsers = usersRef.current;
        const admin = currentUsers.get(adminUserId);
        if (!admin?.group) return;

        // Collect all users NOT yet in the group (excluding admin)
        const pendingUsers: { userId: string; state: UserState }[] = [];
        currentUsers.forEach((state, uid) => {
            if (uid !== adminUserId && !state.group) {
                pendingUsers.push({ userId: uid, state });
            }
        });

        if (pendingUsers.length === 0) {
            addLog('No pending members to add!', 'warning');
            return;
        }

        // Helper: execute the actual add_members + join flow
        const executeAddMembers = (
            kps: any[],
            usersToAdd: { userId: string; state: UserState }[]
        ) => {
            addLog(`Calling add_members() with ${kps.length} KeyPackages...`, 'commit');
            const commitBundle = admin.group.add_members(
                admin.provider,
                admin.identity,
                kps
            );
            addLog(`✓ Single commit! has_welcome: ${commitBundle.has_welcome()}, ${commitBundle.commit.length} bytes`, 'commit');

            // Broadcast commit to existing group members BEFORE merge
            const commitBytes = commitBundle.commit;
            currentUsers.forEach((u, uid) => {
                if (uid !== adminUserId && u.group) {
                    try {
                        u.group.process_message(u.provider, commitBytes);
                        addLog(`${uid} processed commit (epoch: ${u.group.epoch()})`, 'info');
                        updateUser(uid, prev => ({ ...prev, group: prev.group }));
                    } catch (e) {
                        addLog(`${uid} error processing commit: ${(e as Error).message}`, 'error');
                    }
                }
            });

            // Merge pending commit for admin
            admin.group.merge_pending_commit(admin.provider);
            addLog(`✓ Commit merged! New epoch: ${admin.group.epoch()}`, 'success');

            // Export ratchet tree + welcome for new members
            const ratchetTree = admin.group.export_ratchet_tree();
            const welcome = commitBundle.welcome;

            // All new members join with the SAME welcome + ratchet tree
            const joinedUsers: string[] = [];
            for (const { userId, state } of usersToAdd) {
                try {
                    const memberGroup = Group.join_with_welcome(state.provider, welcome, ratchetTree);
                    addLog(`✓ ${userId} joined! epoch: ${memberGroup.epoch()}, cid: ${memberGroup.cid()}`, 'success');
                    updateUser(userId, prev => ({ ...prev, group: memberGroup }));
                    joinedUsers.push(userId);
                } catch (e) {
                    addLog(`${userId} error joining: ${(e as Error).message}`, 'error');
                }
            }

            updateUser(adminUserId, prev => ({ ...prev, group: prev.group }));
            return joinedUsers;
        };

        try {
            addLog(`=== Batch Add Members: ${pendingUsers.map(u => u.userId).join(', ')} ===`, 'info');

            // Step 1: Create key packages for ALL pending users
            const allKeyPackages: any[] = [];
            const kpToUserMap: Map<number, string> = new Map(); // index → userId
            for (let i = 0; i < pendingUsers.length; i++) {
                const { userId, state } = pendingUsers[i];
                const kp = state.identity.key_package(state.provider);
                allKeyPackages.push(kp);
                kpToUserMap.set(i, userId);
                addLog(`Created key package for ${userId}`, 'info');
            }

            // Step 2: Try batch add (Happy Path)
            try {
                const joinedUsers = executeAddMembers(allKeyPackages, pendingUsers);
                const members = admin.group.members();
                addLog(`Group members (${members.length}): ${members.map((m: { user_id: string }) => m.user_id).join(', ')}`, 'info');
                addLog(`✅ Batch add complete — ${joinedUsers.length} users added in 1 commit, 1 welcome`, 'success');

            } catch (batchError) {
                // ========================================
                // FALLBACK: Try-Filter-ReBatch (Hướng A — strict per-user)
                // ========================================
                addLog(`⚠️ Batch add failed: ${(batchError as Error).message}`, 'warning');
                addLog(`🔍 Isolating bad KeyPackages...`, 'info');

                // Test each KP individually by serializing → deserializing (triggers validate())
                const failedUserIds = new Set<string>();
                for (let i = 0; i < allKeyPackages.length; i++) {
                    const userId = kpToUserMap.get(i)!;
                    try {
                        // Roundtrip validation: serialize → from_bytes (which calls validate())
                        const kpBytes = allKeyPackages[i].to_bytes();
                        // KeyPackage.from_bytes throws if invalid
                        const _validated = KeyPackage.from_bytes(kpBytes);
                        addLog(`  ✓ ${userId} KP valid`, 'info');
                    } catch (e) {
                        addLog(`  ✗ ${userId} KP INVALID: ${(e as Error).message}`, 'error');
                        failedUserIds.add(userId);
                    }
                }

                if (failedUserIds.size === pendingUsers.length) {
                    addLog(`❌ All KeyPackages invalid. Cannot add anyone.`, 'error');
                    return;
                }

                // Filter: remove ALL KPs of failing users (Hướng A — strict)
                const cleanKps: any[] = [];
                const cleanUsers: { userId: string; state: UserState }[] = [];
                for (let i = 0; i < allKeyPackages.length; i++) {
                    const userId = kpToUserMap.get(i)!;
                    if (!failedUserIds.has(userId)) {
                        cleanKps.push(allKeyPackages[i]);
                        cleanUsers.push(pendingUsers[i]);
                    }
                }

                addLog(`♻ Re-batching with ${cleanUsers.length} valid users (excluded: ${Array.from(failedUserIds).join(', ')})`, 'warning');

                // Re-batch with clean KPs
                const joinedUsers = executeAddMembers(cleanKps, cleanUsers);
                const members = admin.group.members();
                addLog(`Group members (${members.length}): ${members.map((m: { user_id: string }) => m.user_id).join(', ')}`, 'info');
                addLog(`⚠️ Partial add — ${joinedUsers.length}/${pendingUsers.length} users added. Failed: ${Array.from(failedUserIds).join(', ')}`, 'warning');
            }

        } catch (error) {
            addLog(`Error in add members flow: ${(error as Error).message}`, 'error');
        }
    }, [adminUserId, updateUser, addLog]);

    // Remove member by user_id (Direct Commit — proposals inline)
    const removeMember = useCallback((userIdToRemove: string) => {
        if (!adminUserId) return;
        const currentUsers = usersRef.current;
        const admin = currentUsers.get(adminUserId);
        if (!admin?.group) return;

        try {
            addLog(`=== Remove Member: ${userIdToRemove} ===`, 'info');

            // Step 1: Direct Commit — remove_user() creates commit with inline remove proposals
            const commitBundle = admin.group.remove_user(
                admin.provider,
                admin.identity,
                userIdToRemove
            );
            admin.group.merge_pending_commit(admin.provider);
            addLog(`✓ Member removed! New epoch: ${admin.group.epoch()}`, 'success');

            // Step 2: Broadcast commit to remaining members
            currentUsers.forEach((u, uid) => {
                if (uid !== adminUserId && uid !== userIdToRemove && u.group) {
                    try {
                        u.group.process_message(u.provider, commitBundle.commit);
                        addLog(`${uid} processed remove commit (new epoch: ${u.group.epoch()})`, 'info');
                    } catch (e) {
                        addLog(`${uid} error processing commit: ${(e as Error).message}`, 'error');
                    }
                }
            });

            // Clear removed user's group
            updateUser(userIdToRemove, prev => ({ ...prev, group: null }));
            // Force re-render for admin
            updateUser(adminUserId, prev => ({ ...prev, group: prev.group }));

            const members = admin.group.members();
            addLog(`Remaining members: ${members.map((m: { user_id: string }) => m.user_id).join(', ')}`, 'info');

        } catch (error) {
            addLog(`Error removing member: ${(error as Error).message}`, 'error');
        }
    }, [adminUserId, updateUser, addLog]);

    // Self update (key rotation)
    const performKeyRotation = useCallback((userKey: string) => {
        const currentUsers = usersRef.current;
        const user = currentUsers.get(userKey);
        if (!user?.group) return;

        try {
            addLog(`=== Key Rotation: ${userKey} ===`, 'info');

            const commitBundle = user.group.self_update(user.provider, user.identity);
            addLog(`✓ Self-update commit created`, 'commit');

            user.group.merge_pending_commit(user.provider);
            addLog(`✓ Keys rotated! New epoch: ${user.group.epoch()}`, 'success');

            updateUser(userKey, prev => ({ ...prev, group: prev.group }));

            // Broadcast commit to other members
            const commit = commitBundle.commit;
            currentUsers.forEach((u, uid) => {
                if (uid !== userKey && u.group) {
                    try {
                        u.group.process_message(u.provider, commit);
                        updateUser(uid, prev => ({ ...prev, group: prev.group }));
                    } catch (e) {
                        addLog(`${uid} error: ${(e as Error).message}`, 'error');
                    }
                }
            });

            addLog(`All members synced to epoch ${user.group.epoch()}`, 'success');

        } catch (error) {
            addLog(`Error in key rotation: ${(error as Error).message}`, 'error');
        }
    }, [updateUser, addLog]);

    // Send encrypted message with METADATA SEPARATION
    const handleSendMessage = useCallback((senderId: string, text: string, options: SendMessageOptions = {}) => {
        const currentUsers = usersRef.current;
        const sender = currentUsers.get(senderId);
        if (!sender?.group) return;

        try {
            const messageId = crypto.randomUUID();
            const timestamp = Date.now();

            // Build AAD
            const aad: MessageAAD = {
                message_id: messageId,
                sender_id: senderId,
                channel_id: CHANNEL_CID,
                created_at: timestamp,
            };

            // Encrypt ONLY the sensitive content (text) with AAD
            const encryptedContent: EncryptedContent = { text };
            const serializedContent = serializeEncryptedContent(encryptedContent);
            const ciphertext = sender.group.create_message_with_aad(
                sender.provider,
                sender.identity,
                serializedContent,
                serializeAAD(aad)
            );

            // Log AAD and separation
            addLog(`${senderId} [AAD] message_id=${messageId.slice(0, 8)}... sender=${senderId} channel=${CHANNEL_CID.slice(0, 15)}...`, 'info');
            addLog(`${senderId} [E2EE] Encrypted with AAD (${ciphertext.length} bytes)`, 'info');

            // Display message for sender
            const displayMsg: DisplayMessage = {
                id: messageId,
                text,
                attachments: options.attachments || [],
                mentioned_users: options.mentioned_users || [],
                mentioned_all: options.mentioned_all || false,
                parent_id: options.parent_id || null,
                quoted_message_id: options.quoted_message_id || null,
                type: options.parent_id ? 'reply' : 'regular',
                created_at: Date.now(),
                sender: senderId,
                status: 'sent'
            };

            addMessageForUser(senderId, displayMsg);

            // Decrypt for other members
            currentUsers.forEach((receiver, receiverId) => {
                if (receiverId !== senderId && receiver.group) {
                    try {
                        const processed = receiver.group.process_message(receiver.provider, ciphertext);
                        if (processed.is_application_message) {
                            const decryptedContent = deserializeEncryptedContent(processed.content);
                            const receivedAAD = deserializeAAD(new Uint8Array(processed.aad));
                            addLog(`${receiverId} [AAD verified] sender=${receivedAAD.sender_id} msg=${receivedAAD.message_id.slice(0, 8)}...`, 'success');

                            addMessageForUser(receiverId, {
                                id: messageId,
                                text: decryptedContent.text,
                                attachments: options.attachments || [],
                                mentioned_users: options.mentioned_users || [],
                                mentioned_all: options.mentioned_all || false,
                                parent_id: options.parent_id || null,
                                quoted_message_id: options.quoted_message_id || null,
                                type: options.parent_id ? 'reply' : 'regular',
                                created_at: receivedAAD.created_at,
                                sender: receivedAAD.sender_id,
                                status: 'received' as const
                            });
                            addLog(`${receiverId} decrypted: "${decryptedContent.text.slice(0, 30)}..."`, 'success');
                        }
                    } catch (e) {
                        addLog(`${receiverId} error decrypting: ${(e as Error).message}`, 'error');
                    }
                }
            });

        } catch (error) {
            addLog(`Error sending message: ${(error as Error).message}`, 'error');
        }
    }, [addLog, addMessageForUser]);

    // Export derived key
    const exportKey = useCallback(() => {
        if (!adminUserId) return;
        const admin = usersRef.current.get(adminUserId);
        if (!admin?.group) return;

        try {
            const key = admin.group.export_key(admin.provider, "media_key", new Uint8Array([0x01, 0x02]), 32);
            addLog(`Exported key (32 bytes): ${Array.from(key.slice(0, 8) as Uint8Array).map((b: number) => b.toString(16).padStart(2, '0')).join('')}...`, 'success');
        } catch (error) {
            addLog(`Error exporting key: ${(error as Error).message}`, 'error');
        }
    }, [adminUserId, addLog]);

    // Handle add member form submit
    const handleAddMember = (e: React.FormEvent) => {
        e.preventDefault();
        if (!newMemberName.trim()) return;
        addNewUser(newMemberName.trim());
        setNewMemberName('');
    };

    // Get ordered user IDs (admin first)
    const userIds = Array.from(users.keys()).sort((a, b) => {
        if (a === adminUserId) return -1;
        if (b === adminUserId) return 1;
        return 0;
    });

    // Users not yet in group
    const usersNotInGroup = userIds.filter(uid => {
        const u = users.get(uid);
        return u && !u.group && uid !== adminUserId;
    });

    return (
        <div className="container">
            <div style={{ textAlign: 'center', color: 'white', marginBottom: '30px' }}>
                <h1 style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '12px' }}>
                    <Shield size={40} />
                    OpenMLS Chat
                </h1>
                <p style={{ opacity: 0.9, marginTop: '8px' }}>
                    Dynamic Member Management with Separated Proposal/Commit, CID Mapping
                </p>
            </div>

            {/* Control Panel */}
            <div className="panel mb-4">
                <h3 style={{ marginBottom: '16px' }}>🎮 Controls</h3>
                <div className="flex flex-wrap gap-2">
                    <button
                        className="btn btn-success"
                        onClick={createGroupWithCid}
                        disabled={!adminUserId || groupCreated || !users.get(adminUserId!)}
                    >
                        <Shield size={18} /> Create Group (CID)
                    </button>

                    {/* Add pending members to group */}
                    {groupCreated && usersNotInGroup.map(uid => (
                        <button
                            key={uid}
                            className="btn btn-primary"
                            onClick={() => addMemberToGroup(uid)}
                        >
                            <UserPlus size={18} /> Add {uid} to Group
                        </button>
                    ))}

                    {/* Batch add all pending members */}
                    {groupCreated && usersNotInGroup.length >= 2 && (
                        <button
                            className="btn btn-success"
                            onClick={addMultipleMembersToGroup}
                        >
                            <UsersRound size={18} /> Add All Pending ({usersNotInGroup.length})
                        </button>
                    )}

                    {/* Remove members (non-admin, in group) */}
                    {groupCreated && userIds.filter(uid => uid !== adminUserId && users.get(uid)?.group).map(uid => (
                        <button
                            key={`remove-${uid}`}
                            className="btn btn-warning"
                            onClick={() => removeMember(uid)}
                        >
                            <UserMinus size={18} /> Remove {uid}
                        </button>
                    ))}

                    {adminUserId && users.get(adminUserId)?.group && (
                        <button
                            className="btn btn-primary"
                            onClick={() => performKeyRotation(adminUserId)}
                        >
                            <RefreshCw size={18} /> Admin Key Rotation
                        </button>
                    )}

                    {adminUserId && users.get(adminUserId)?.group && (
                        <button
                            className="btn btn-success"
                            onClick={exportKey}
                        >
                            <Key size={18} /> Export Key
                        </button>
                    )}
                </div>

                {/* User chips */}
                {userIds.length > 0 && (
                    <div className="user-chips">
                        {userIds.map(uid => (
                            <span key={uid} className={`user-chip ${uid === adminUserId ? 'admin' : ''}`}>
                                {uid === adminUserId ? '👑 ' : ''}{uid}
                                {users.get(uid)?.group ? ' ✓' : ''}
                            </span>
                        ))}
                    </div>
                )}

                {/* Add new member form */}
                <form className="add-member-form" onSubmit={handleAddMember}>
                    <input
                        value={newMemberName}
                        onChange={(e) => setNewMemberName(e.target.value)}
                        placeholder="Enter user name..."
                        disabled={!wasmReady}
                    />
                    <button
                        type="submit"
                        className="btn btn-primary"
                        disabled={!wasmReady || !newMemberName.trim()}
                    >
                        <UserPlus size={18} /> Add User
                    </button>
                </form>

                {pendingProposals > 0 && (
                    <div className="badge badge-warning" style={{ marginTop: '12px' }}>
                        Pending Proposals: {pendingProposals}
                    </div>
                )}
            </div>

            {/* Chat Panels - Dynamic */}
            <div className="grid-3">
                {userIds.map(uid => {
                    const user = users.get(uid);
                    return (
                        <ChatPanel
                            key={uid}
                            name={uid === adminUserId ? `${uid} (Admin)` : uid}
                            userId={uid}
                            messages={userMessages.get(uid) || []}
                            members={user?.group?.members() || []}
                            epoch={user?.group?.epoch() || 0}
                            onSendMessage={handleSendMessage}
                        />
                    );
                })}
            </div>

            {/* Log Panel */}
            <LogPanel logs={logs} />
        </div>
    );
}

export default App;
