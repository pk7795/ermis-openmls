import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  Archive,
  CheckCircle2,
  History,
  KeyRound,
  Laptop,
  Lock,
  RotateCcw,
  Send,
  ShieldCheck,
  Smartphone,
  Unlock,
  UserRound,
  UserPlus,
} from 'lucide-react'

import init, {
  Provider,
  Identity,
  Group,
  decrypt_with_epoch_archive,
  peek_sender_data_from_archive,
} from './wasm/openmls_wasm.js'

const CHANNEL_CID = 'team:epoch_archive_restore_v4'
const RECOVERY_NAMESPACE = `mls:archive:${CHANNEL_CID}`
const VAULT_KDF_ITERATIONS = 150_000

type LogType = 'info' | 'success' | 'error' | 'warning' | 'commit'
type DeviceId = 'alice1' | 'alice2' | 'bob'
type UserId = 'alice' | 'bob'
type MessageSource = 'sent' | 'live' | 'archive'
type ArchiveScope = 'account_owned' | 'group_sponsored'

type LogEntry = {
  time: string
  type: LogType
  message: string
}

type Actor = {
  id: DeviceId
  userId: UserId
  label: string
  provider: any
  identity: any
  group: any
  archives: Record<number, Uint8Array>
  joinedEpoch: number
}

type Actors = {
  alice1: Actor
  alice2?: Actor
  bob: Actor
}

type StoredMessage = {
  id: string
  senderDevice: DeviceId
  senderUser: UserId
  senderLabel: string
  text: string
  ciphertext: Uint8Array
  epoch: number
  generation: number
}

type ChatLine = {
  id: string
  senderLabel: string
  text: string
  epoch: number
  generation: number
  source: MessageSource
}

type ChatState = Record<DeviceId, ChatLine[]>

type VaultMetadata = {
  ownerUser: UserId
  ownerDevice: DeviceId
  channelId: string
  epoch: number
  createdAt: number
}

type VaultRecord = {
  version: 1
  kdf: 'PBKDF2-SHA256'
  iterations: number
  salt: Uint8Array
  nonce: Uint8Array
  ciphertext: Uint8Array
  metadata: VaultMetadata
}

type VaultState = {
  pinCreated: boolean
  pinMasked: string
  records: Record<number, VaultRecord>
  alice2UnlockedEpochs: number[]
}

type SnapshotMember = {
  leafIndex: number
  userId: string
  signatureKey: string
}

type LatestGroupInfoRecord = {
  channelId: string
  epoch: number
  updatedByDevice: DeviceId
  updatedAt: number
}

type MemberSnapshotRecord = {
  snapshotHash: string
  channelId: string
  firstSeenEpoch: number
  lastSeenEpoch: number
  members: SnapshotMember[]
  byteLength: number
}

type ArchiveBlobRecord = {
  archiveBlobId: string
  channelId: string
  epoch: number
  scope: ArchiveScope
  exporterUserId: UserId
  exporterDeviceId: DeviceId
  memberSnapshotHash: string
  archiveLength: number
  createdAt: number
}

type ArchiveKeyWrapRecord = {
  keyWrapId: string
  archiveBlobId: string
  recipientUserId: UserId
  recoveryKeyId: string
  epoch: number
  createdAt: number
}

type RecoveryStoreState = {
  latestGroupInfo?: LatestGroupInfoRecord
  latestSnapshotHash?: string
  memberSnapshots: Record<string, MemberSnapshotRecord>
  archiveBlobs: Record<string, ArchiveBlobRecord>
  archiveKeyWraps: Record<string, ArchiveKeyWrapRecord>
}

type ArchiveOptions = {
  scope?: ArchiveScope
  publishGroupInfo?: boolean
}

const encoder = new TextEncoder()
const decoder = new TextDecoder()

function encodeJson(value: unknown): Uint8Array {
  return encoder.encode(JSON.stringify(value))
}

function decodeJson<T>(bytes: Uint8Array | number[] | undefined): T {
  if (!bytes) throw new Error('Missing bytes')
  return JSON.parse(decoder.decode(new Uint8Array(bytes))) as T
}

function toNumber(value: number | bigint): number {
  return typeof value === 'bigint' ? Number(value) : value
}

function emptyRecoveryStore(): RecoveryStoreState {
  return {
    memberSnapshots: {},
    archiveBlobs: {},
    archiveKeyWraps: {},
  }
}

function bytesToHex(bytes: ArrayLike<number>): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

function shortHash(hash: string): string {
  return hash.slice(0, 12)
}

function archiveBlobIdFor(scope: ArchiveScope, deviceId: DeviceId, epoch: number): string {
  return `${scope}:${deviceId}:epoch-${epoch}`
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return bytesToHex(new Uint8Array(digest))
}

function canonicalizeOptimizedSnapshot(group: any): { snapshotBytes: Uint8Array; members: SnapshotMember[] } {
  const members = group
    .members()
    .map((member: any) => ({
      leafIndex: toNumber(member.index),
      userId: String(member.user_id),
      signatureKey: bytesToHex(member.signature_key),
    }))
    .sort((left: SnapshotMember, right: SnapshotMember) => left.leafIndex - right.leafIndex)

  return {
    members,
    snapshotBytes: encodeJson({
      snapshotVersion: 2,
      hashMode: 'optimized-member-signatures',
      groupId: bytesToHex(group.group_id()),
      protocolVersion: 'MLS10',
      ciphersuite: 'openmls-wasm-demo-default',
      signatureScheme: 'ed25519-demo-identities',
      members,
    }),
  }
}

function explainSnapshotChange(previous: MemberSnapshotRecord | undefined, nextMembers: SnapshotMember[]): string {
  if (!previous) return 'first optimized snapshot for this channel'

  const previousByLeaf = new Map(previous.members.map((member) => [member.leafIndex, member]))
  const nextByLeaf = new Map(nextMembers.map((member) => [member.leafIndex, member]))

  for (const member of nextMembers) {
    const before = previousByLeaf.get(member.leafIndex)
    if (!before) return `leaf ${member.leafIndex} added for ${member.userId}`
    if (before.userId !== member.userId) return `leaf ${member.leafIndex} user changed ${before.userId}->${member.userId}`
    if (before.signatureKey !== member.signatureKey) return `leaf ${member.leafIndex} signature_key changed`
  }

  for (const member of previous.members) {
    if (!nextByLeaf.has(member.leafIndex)) return `leaf ${member.leafIndex} removed`
  }

  return 'optimized verification material changed'
}

function nowTime(): string {
  return new Date().toLocaleTimeString()
}

function maskPin(pin: string): string {
  return '•'.repeat(pin.length)
}

function sourceLabel(source: MessageSource): string {
  if (source === 'archive') return 'restored'
  if (source === 'live') return 'live'
  return 'sent'
}

async function derivePinKey(pin: string, salt: Uint8Array, iterations: number): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey('raw', encoder.encode(pin), 'PBKDF2', false, ['deriveKey'])
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: 'SHA-256',
    },
    baseKey,
    {
      name: 'AES-GCM',
      length: 256,
    },
    false,
    ['encrypt', 'decrypt'],
  )
}

async function encryptArchiveWithPin(
  pin: string,
  archive: Uint8Array,
  metadata: VaultMetadata,
): Promise<VaultRecord> {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const key = await derivePinKey(pin, salt, VAULT_KDF_ITERATIONS)
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
      additionalData: encodeJson(metadata),
    },
    key,
    archive,
  ))

  return {
    version: 1,
    kdf: 'PBKDF2-SHA256',
    iterations: VAULT_KDF_ITERATIONS,
    salt,
    nonce,
    ciphertext,
    metadata,
  }
}

async function decryptArchiveWithPin(pin: string, record: VaultRecord): Promise<Uint8Array> {
  const key = await derivePinKey(pin, record.salt, record.iterations)
  return new Uint8Array(await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: record.nonce,
      additionalData: encodeJson(record.metadata),
    },
    key,
    record.ciphertext,
  ))
}

function emptyChats(): ChatState {
  return {
    alice1: [],
    alice2: [],
    bob: [],
  }
}

function sentLine(message: StoredMessage): ChatLine {
  return {
    id: message.id,
    senderLabel: message.senderLabel,
    text: message.text,
    epoch: message.epoch,
    generation: message.generation,
    source: 'sent',
  }
}

function App(): React.ReactElement {
  const [wasmReady, setWasmReady] = useState(false)
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [actors, setActors] = useState<Actors | null>(null)
  const [messages, setMessages] = useState<StoredMessage[]>([])
  const [chats, setChats] = useState<ChatState>(() => emptyChats())
  const [drafts, setDrafts] = useState<Record<DeviceId, string>>({
    alice1: 'Hello from Alice device 1 before the second device joins.',
    alice2: 'Alice device 2 is online after restore.',
    bob: 'Bob reply from the original device.',
  })
  const [pinDraft, setPinDraft] = useState('')
  const [busy, setBusy] = useState(false)
  const [vault, setVault] = useState<VaultState>({
    pinCreated: false,
    pinMasked: '',
    records: {},
    alice2UnlockedEpochs: [],
  })
  const [recoveryStore, setRecoveryStore] = useState<RecoveryStoreState>(() => emptyRecoveryStore())
  const recoveryStoreRef = useRef<RecoveryStoreState>(emptyRecoveryStore())
  const logRef = useRef<HTMLDivElement>(null)
  const initializedRef = useRef(false)

  const addLog = useCallback((message: string, type: LogType = 'info') => {
    setLogs((prev) => [...prev, { time: nowTime(), type, message }])
  }, [])

  const replaceRecoveryStore = useCallback((next: RecoveryStoreState) => {
    recoveryStoreRef.current = next
    setRecoveryStore(next)
  }, [])

  const updateRecoveryStore = useCallback((updater: (prev: RecoveryStoreState) => RecoveryStoreState): RecoveryStoreState => {
    const next = updater(recoveryStoreRef.current)
    recoveryStoreRef.current = next
    setRecoveryStore(next)
    return next
  }, [])

  const archiveActorEpoch = useCallback(async (
    actor: Actor,
    reason: string,
    options: ArchiveOptions = {},
  ): Promise<Uint8Array> => {
    const epoch = toNumber(actor.group.epoch())
    const scope = options.scope ?? 'account_owned'
    const publishGroupInfo = options.publishGroupInfo ?? true
    const archive = actor.group.archive_current_epoch()
    actor.archives[epoch] = archive

    const { snapshotBytes, members } = canonicalizeOptimizedSnapshot(actor.group)
    const snapshotHash = await sha256Hex(snapshotBytes)
    const storeBefore = recoveryStoreRef.current
    const existingSnapshot = storeBefore.memberSnapshots[snapshotHash]
    const previousSnapshot = storeBefore.latestSnapshotHash
      ? storeBefore.memberSnapshots[storeBefore.latestSnapshotHash]
      : undefined
    const archiveBlobId = archiveBlobIdFor(scope, actor.id, epoch)
    const snapshotReason = existingSnapshot
      ? 'same optimized leaf_index + user_id + signature_key; epoch/encryption_key ignored'
      : explainSnapshotChange(previousSnapshot, members)

    updateRecoveryStore((prev) => {
      const now = Date.now()
      const memberSnapshots = { ...prev.memberSnapshots }
      memberSnapshots[snapshotHash] = existingSnapshot
        ? {
            ...existingSnapshot,
            lastSeenEpoch: Math.max(existingSnapshot.lastSeenEpoch, epoch),
          }
        : {
            snapshotHash,
            channelId: CHANNEL_CID,
            firstSeenEpoch: epoch,
            lastSeenEpoch: epoch,
            members,
            byteLength: snapshotBytes.length,
          }

      return {
        ...prev,
        latestGroupInfo: publishGroupInfo
          ? {
              channelId: CHANNEL_CID,
              epoch,
              updatedByDevice: actor.id,
              updatedAt: now,
            }
          : prev.latestGroupInfo,
        latestSnapshotHash: snapshotHash,
        memberSnapshots,
        archiveBlobs: {
          ...prev.archiveBlobs,
          [archiveBlobId]: {
            archiveBlobId,
            channelId: CHANNEL_CID,
            epoch,
            scope,
            exporterUserId: actor.userId,
            exporterDeviceId: actor.id,
            memberSnapshotHash: snapshotHash,
            archiveLength: archive.length,
            createdAt: now,
          },
        },
      }
    })

    if (publishGroupInfo) {
      addLog(`Latest GroupInfo overwritten for ${CHANNEL_CID} at epoch ${epoch} by ${actor.label}`, 'commit')
    }
    addLog(
      `MemberSnapshot ${existingSnapshot ? 'reused' : 'stored'} hash=${shortHash(snapshotHash)} at epoch ${epoch}: ${snapshotReason}`,
      existingSnapshot ? 'info' : 'success',
    )
    addLog(
      `ArchiveBlob stored in ${RECOVERY_NAMESPACE}: blob=${archiveBlobId}, snapshot=${shortHash(snapshotHash)}, bytes=${archive.length} (${reason})`,
      'success',
    )
    return archive
  }, [addLog, updateRecoveryStore])

  const addArchiveKeyWrap = useCallback((epoch: number, archiveBlobId: string, recipientUserId: UserId) => {
    const recoveryKeyId = 'pin-demo-recovery-key'
    const keyWrapId = `wrap:${recipientUserId}:${epoch}:${recoveryKeyId}:${archiveBlobId}`
    updateRecoveryStore((prev) => ({
      ...prev,
      archiveKeyWraps: {
        ...prev.archiveKeyWraps,
        [keyWrapId]: {
          keyWrapId,
          archiveBlobId,
          recipientUserId,
          recoveryKeyId,
          epoch,
          createdAt: Date.now(),
        },
      },
    }))
    addLog(`ArchiveKeyWrap stored for ${recipientUserId}: epoch=${epoch}, blob=${archiveBlobId}, recovery_key=${recoveryKeyId}`, 'success')
  }, [addLog, updateRecoveryStore])

  const setupInitialGroup = useCallback(async (): Promise<Actors> => {
    replaceRecoveryStore(emptyRecoveryStore())
    const aliceProvider = new Provider()
    const bobProvider = new Provider()
    const aliceIdentity = new Identity(aliceProvider, 'alice')
    const bobIdentity = new Identity(bobProvider, 'bob')

    const aliceGroup = Group.create_with_cid(aliceProvider, aliceIdentity, CHANNEL_CID)
    addLog(`Alice device 1 created group ${CHANNEL_CID} at epoch ${toNumber(aliceGroup.epoch())}`, 'success')

    const bobKeyPackage = bobIdentity.key_package(bobProvider)
    const addBob = aliceGroup.add_members(aliceProvider, aliceIdentity, [bobKeyPackage])
    addLog('Alice device 1 committed Add for Bob', 'commit')
    aliceGroup.merge_pending_commit(aliceProvider)

    const bobRatchetTree = aliceGroup.export_ratchet_tree()
    const bobGroup = Group.join_with_welcome(bobProvider, addBob.welcome, bobRatchetTree)
    addLog(`Bob joined from Welcome at epoch ${toNumber(bobGroup.epoch())}`, 'success')

    const nextActors: Actors = {
      alice1: {
        id: 'alice1',
        userId: 'alice',
        label: 'Alice device 1',
        provider: aliceProvider,
        identity: aliceIdentity,
        group: aliceGroup,
        archives: {},
        joinedEpoch: toNumber(aliceGroup.epoch()),
      },
      bob: {
        id: 'bob',
        userId: 'bob',
        label: 'Bob device',
        provider: bobProvider,
        identity: bobIdentity,
        group: bobGroup,
        archives: {},
        joinedEpoch: toNumber(bobGroup.epoch()),
      },
    }

    await archiveActorEpoch(nextActors.alice1, 'fresh epoch 1 archive waiting for PIN vault sealing', { publishGroupInfo: true })
    await archiveActorEpoch(nextActors.bob, 'Bob local recovery seed', { publishGroupInfo: false })
    return nextActors
  }, [addLog, archiveActorEpoch, replaceRecoveryStore])

  useEffect(() => {
    if (initializedRef.current) return
    initializedRef.current = true
    init()
      .then(async () => {
        setWasmReady(true)
        const initialActors = await setupInitialGroup()
        setActors(initialActors)
        addLog('WASM initialized; v4 interactive chat is ready', 'success')
      })
      .catch((error: Error) => addLog(`WASM init failed: ${error.message}`, 'error'))
  }, [addLog, setupInitialGroup])

  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight })
  }, [logs])

  const reset = useCallback(async () => {
    if (!wasmReady || busy) return
    setBusy(true)
    try {
      setLogs([])
      const initialActors = await setupInitialGroup()
      setActors(initialActors)
      setMessages([])
      setChats(emptyChats())
      setDrafts({
        alice1: 'Hello from Alice device 1 before the second device joins.',
        alice2: 'Alice device 2 is online after restore.',
        bob: 'Bob reply from the original device.',
      })
      setPinDraft('')
      setVault({
        pinCreated: false,
        pinMasked: '',
        records: {},
        alice2UnlockedEpochs: [],
      })
      addLog('Demo state reset; Alice device 1 and Bob are back at epoch 1', 'info')
    } catch (error) {
      addLog(`Demo reset failed: ${(error as Error).message}`, 'error')
    } finally {
      setBusy(false)
    }
  }, [addLog, busy, setupInitialGroup, wasmReady])

  const actorForDevice = useCallback((deviceId: DeviceId): Actor | undefined => {
    if (!actors) return undefined
    return actors[deviceId]
  }, [actors])

  const createMessage = useCallback((sender: Actor, text: string): StoredMessage => {
    const epoch = toNumber(sender.group.epoch())
    const archiveForPeek = sender.archives[epoch]
    if (!archiveForPeek) {
      throw new Error(`${sender.label} has no archive for epoch ${epoch}`)
    }
    const id = crypto.randomUUID()
    const aad = {
      message_id: id,
      sender_device: sender.id,
      sender_user: sender.userId,
      channel_id: CHANNEL_CID,
      created_at: Date.now(),
    }
    const ciphertext = sender.group.create_message_with_aad(
      sender.provider,
      sender.identity,
      encodeJson({ text }),
      encodeJson(aad),
    )
    const senderData = peek_sender_data_from_archive(sender.provider, archiveForPeek, ciphertext)
    const message = {
      id,
      senderDevice: sender.id,
      senderUser: sender.userId,
      senderLabel: sender.label,
      text,
      ciphertext,
      epoch: toNumber(senderData.epoch),
      generation: senderData.generation,
    }
    addLog(
      `${sender.label} sent ${id.slice(0, 8)} at epoch ${message.epoch}, generation ${message.generation}`,
      'info',
    )
    return message
  }, [addLog])

  const processLive = useCallback((receiver: Actor, message: StoredMessage): ChatLine => {
    const processed = receiver.group.process_message(receiver.provider, message.ciphertext)
    if (!processed.is_application_message()) {
      throw new Error(`${receiver.label} expected application message`)
    }
    const content = decodeJson<{ text: string }>(processed.content)
    const aad = decodeJson<{ message_id: string; sender_device: DeviceId }>(processed.aad)
    addLog(
      `${receiver.label} live-decrypted ${aad.message_id.slice(0, 8)} from ${aad.sender_device} at local epoch ${toNumber(receiver.group.epoch())}`,
      'success',
    )
    return {
      id: message.id,
      senderLabel: message.senderLabel,
      text: content.text,
      epoch: message.epoch,
      generation: message.generation,
      source: 'live',
    }
  }, [addLog])

  const deliverMessage = useCallback((senderId: DeviceId, message: StoredMessage) => {
    if (!actors) return
    const nextLines: Partial<ChatState> = {
      [senderId]: [sentLine(message)],
    }
    const recipients: DeviceId[] = ['alice1', 'alice2', 'bob'].filter((id) => id !== senderId) as DeviceId[]
    for (const recipientId of recipients) {
      const recipient = actors[recipientId]
      if (!recipient) continue
      nextLines[recipientId] = [processLive(recipient, message)]
    }
    setChats((prev) => ({
      alice1: [...prev.alice1, ...(nextLines.alice1 ?? [])],
      alice2: [...prev.alice2, ...(nextLines.alice2 ?? [])],
      bob: [...prev.bob, ...(nextLines.bob ?? [])],
    }))
    setMessages((prev) => [...prev, message])
    setActors({ ...actors })
  }, [actors, processLive])

  const sendFrom = useCallback((deviceId: DeviceId) => {
    if (!actors) return
    const sender = actorForDevice(deviceId)
    if (!sender) {
      addLog(`${deviceId} is not joined yet`, 'warning')
      return
    }
    const text = drafts[deviceId].trim()
    if (!text) return
    try {
      const message = createMessage(sender, text)
      deliverMessage(deviceId, message)
      setDrafts((prev) => ({ ...prev, [deviceId]: '' }))
    } catch (error) {
      addLog(`Send failed from ${sender.label}: ${(error as Error).message}`, 'error')
    }
  }, [actorForDevice, actors, addLog, createMessage, deliverMessage, drafts])

  const createPin = useCallback(async () => {
    if (!actors || busy) return
    const pin = pinDraft.trim()
    if (!/^\d{4,12}$/.test(pin)) {
      addLog('PIN must be 4-12 digits for this demo', 'warning')
      return
    }
    const aliceArchives = Object.entries(actors.alice1.archives)
      .map(([epoch, archive]) => ({ epoch: Number(epoch), archive }))
      .filter(({ archive }) => Boolean(archive))
      .sort((left, right) => left.epoch - right.epoch)
    if (aliceArchives.length === 0) {
      addLog('Alice device 1 has no archives to seal', 'error')
      return
    }
    setBusy(true)
    try {
      addLog(`Alice device 1 creates PIN ${maskPin(pin)} and derives a vault key`, 'info')
      addLog(
        `KDF: PBKDF2-SHA256, ${VAULT_KDF_ITERATIONS.toLocaleString()} iterations; backfilling ${aliceArchives.length} Alice archive record(s) into the PIN vault`,
        'info',
      )
      const records: Record<number, VaultRecord> = {}
      for (const { epoch, archive } of aliceArchives) {
        const record = await encryptArchiveWithPin(pin, archive, {
          ownerUser: 'alice',
          ownerDevice: 'alice1',
          channelId: CHANNEL_CID,
          epoch,
          createdAt: Date.now(),
        })
        records[epoch] = record
        addArchiveKeyWrap(epoch, archiveBlobIdFor('account_owned', 'alice1', epoch), 'alice')
        addLog(
          `Alice device 1 sealed epoch ${epoch} archive into PIN vault: plaintext=${archive.length} bytes, ciphertext=${record.ciphertext.length} bytes`,
          'success',
        )
      }
      setVault({
        pinCreated: true,
        pinMasked: maskPin(pin),
        records,
        alice2UnlockedEpochs: [],
      })
      setPinDraft('')
    } catch (error) {
      addLog(`PIN vault sealing failed: ${(error as Error).message}`, 'error')
    } finally {
      setBusy(false)
    }
  }, [actors, addArchiveKeyWrap, addLog, busy, pinDraft])

  const advanceToEpoch = useCallback(async (currentActors: Actors, targetEpoch: number) => {
    while (toNumber(currentActors.alice1.group.epoch()) < targetEpoch) {
      const update = currentActors.alice1.group.self_update(
        currentActors.alice1.provider,
        currentActors.alice1.identity,
      )
      currentActors.alice1.group.merge_pending_commit(currentActors.alice1.provider)
      currentActors.bob.group.process_message(currentActors.bob.provider, update.commit)
      const epoch = toNumber(currentActors.alice1.group.epoch())
      addLog(
        `Self-update commit applied: Alice device 1=${epoch}, Bob=${toNumber(currentActors.bob.group.epoch())}`,
        'commit',
      )
      await archiveActorEpoch(currentActors.alice1, `fresh archive after self-update to epoch ${epoch}`, { publishGroupInfo: true })
      await archiveActorEpoch(currentActors.bob, `fresh archive after self-update to epoch ${epoch}`, { publishGroupInfo: false })
    }
  }, [addLog, archiveActorEpoch])

  const joinAlice2 = useCallback(async () => {
    if (!actors || actors.alice2 || busy) return
    setBusy(true)
    try {
      await advanceToEpoch(actors, 9)
      const alice2Provider = new Provider()
      const alice2Identity = new Identity(alice2Provider, 'alice')
      const alice2KeyPackage = alice2Identity.key_package(alice2Provider)
      const addAlice2 = actors.alice1.group.add_members(
        actors.alice1.provider,
        actors.alice1.identity,
        [alice2KeyPackage],
      )
      addLog('Alice device 1 committed Add for Alice device 2 while group was at epoch 9', 'commit')
      actors.alice1.group.merge_pending_commit(actors.alice1.provider)
      actors.bob.group.process_message(actors.bob.provider, addAlice2.commit)

      const alice2RatchetTree = actors.alice1.group.export_ratchet_tree()
      const alice2Group = Group.join_with_welcome(alice2Provider, addAlice2.welcome, alice2RatchetTree)
      const alice2: Actor = {
        id: 'alice2',
        userId: 'alice',
        label: 'Alice device 2',
        provider: alice2Provider,
        identity: alice2Identity,
        group: alice2Group,
        archives: {},
        joinedEpoch: toNumber(alice2Group.epoch()),
      }
      actors.alice2 = alice2
      addLog(
        `Alice device 2 joined from Welcome at epoch ${alice2.joinedEpoch}; pre-join messages require the PIN vault`,
        'success',
      )
      await archiveActorEpoch(actors.alice1, 'fresh epoch after adding Alice device 2', { publishGroupInfo: true })
      await archiveActorEpoch(actors.bob, 'fresh epoch after Alice device 2 joined', { publishGroupInfo: false })
      await archiveActorEpoch(alice2, 'new device starts archiving from its join epoch', { publishGroupInfo: false })
      setActors({ ...actors })
    } catch (error) {
      addLog(`Alice device 2 join failed: ${(error as Error).message}`, 'error')
    } finally {
      setBusy(false)
    }
  }, [actors, addLog, archiveActorEpoch, advanceToEpoch, busy])

  const rotateKey = useCallback(async () => {
    if (!actors || busy) return
    const pin = vault.pinCreated ? window.prompt('Enter Alice PIN to seal the new epoch archive') : null
    if (vault.pinCreated && pin === null) {
      addLog('Key rotate cancelled before PIN entry', 'warning')
      return
    }
    setBusy(true)
    try {
      const verificationRecord = Object.values(vault.records)[0]
      if (vault.pinCreated && pin && verificationRecord) {
        await decryptArchiveWithPin(pin, verificationRecord)
        addLog(`PIN ${maskPin(pin)} verified before key rotation`, 'success')
      }

      const update = actors.alice1.group.self_update(
        actors.alice1.provider,
        actors.alice1.identity,
      )
      actors.alice1.group.merge_pending_commit(actors.alice1.provider)
      actors.bob.group.process_message(actors.bob.provider, update.commit)
      if (actors.alice2) {
        actors.alice2.group.process_message(actors.alice2.provider, update.commit)
      }
      const nextEpoch = toNumber(actors.alice1.group.epoch())
      addLog(
        `Key rotation committed: Alice D1=${nextEpoch}, Alice D2=${actors.alice2 ? toNumber(actors.alice2.group.epoch()) : '-'}, Bob=${toNumber(actors.bob.group.epoch())}`,
        'commit',
      )

      const aliceArchive = await archiveActorEpoch(actors.alice1, 'fresh archive after manual key rotation', { publishGroupInfo: true })
      await archiveActorEpoch(actors.bob, 'fresh archive after manual key rotation', { publishGroupInfo: false })
      if (actors.alice2) {
        await archiveActorEpoch(actors.alice2, 'fresh archive after manual key rotation', { publishGroupInfo: false })
      }

      if (vault.pinCreated && pin) {
        const record = await encryptArchiveWithPin(pin, aliceArchive, {
          ownerUser: 'alice',
          ownerDevice: 'alice1',
          channelId: CHANNEL_CID,
          epoch: nextEpoch,
          createdAt: Date.now(),
        })
        setVault((prev) => ({
          ...prev,
          records: {
            ...prev.records,
            [nextEpoch]: record,
          },
        }))
        addArchiveKeyWrap(nextEpoch, archiveBlobIdFor('account_owned', 'alice1', nextEpoch), 'alice')
        addLog(
          `Alice device 1 sealed epoch ${nextEpoch} archive into PIN vault after key rotation (${record.ciphertext.length} bytes)`,
          'success',
        )
      }

      setActors({ ...actors })
    } catch (error) {
      addLog(`Key rotation failed: ${(error as Error).message}`, 'error')
    } finally {
      setBusy(false)
    }
  }, [actors, addArchiveKeyWrap, addLog, archiveActorEpoch, busy, vault])

  const restoreAlice2 = useCallback(async () => {
    if (!actors?.alice2 || busy) return
    const preJoinMessages = messages.filter((message) => message.epoch < actors.alice2!.joinedEpoch)
    const restoreEpochs = Array.from(new Set(preJoinMessages.map((message) => message.epoch))).sort((left, right) => left - right)
    if (restoreEpochs.length === 0) {
      addLog('Alice device 2 has no pre-join ciphertexts to restore', 'warning')
      return
    }
    const availableEpochs = restoreEpochs.filter((epoch) => vault.records[epoch])
    if (availableEpochs.length === 0) {
      addLog(`Alice PIN vault has no encrypted archive for pre-join epochs ${restoreEpochs.join(', ')}`, 'warning')
      return
    }
    const pin = window.prompt('Enter Alice PIN to unlock old messages')
    if (pin === null) {
      addLog('Alice device 2 restore cancelled before PIN entry', 'warning')
      return
    }
    setBusy(true)
    try {
      try {
        actors.alice2.group.process_message(actors.alice2.provider, preJoinMessages[0]?.ciphertext ?? new Uint8Array())
      } catch (error) {
        addLog(
          `Expected live-state miss before restore: Alice device 2 cannot read epoch ${preJoinMessages[0]?.epoch ?? '-'} directly (${(error as Error).message})`,
          'warning',
        )
      }

      addLog(`Alice device 2 derives vault key from entered PIN ${maskPin(pin)} for epochs ${availableEpochs.join(', ')}`, 'info')
      const archivesByEpoch = new Map<number, Uint8Array>()
      for (const epoch of availableEpochs) {
        const archive = await decryptArchiveWithPin(pin, vault.records[epoch])
        archivesByEpoch.set(epoch, archive)
        addLog(`Alice device 2 unlocked epoch ${epoch} archive from PIN vault (${archive.length} bytes)`, 'success')
      }

      const restoredLines: ChatLine[] = []
      for (const message of preJoinMessages) {
        const archive = archivesByEpoch.get(message.epoch)
        if (!archive) {
          addLog(`Alice device 2 skipped ${message.id.slice(0, 8)}: no PIN archive for epoch ${message.epoch}`, 'warning')
          continue
        }
        const recovered = decrypt_with_epoch_archive(actors.alice2.provider, archive, message.ciphertext, true, 0)
        const content = decodeJson<{ text: string }>(recovered.content)
        const aad = decodeJson<{ message_id: string; sender_device: DeviceId }>(recovered.aad)
        addLog(
          `Alice device 2 restored ${aad.message_id.slice(0, 8)} via PIN vault: epoch=${toNumber(recovered.epoch)}, sender=${aad.sender_device}, gen=${recovered.generation}`,
          'success',
        )
        restoredLines.push({
          id: message.id,
          senderLabel: message.senderLabel,
          text: content.text,
          epoch: toNumber(recovered.epoch),
          generation: recovered.generation,
          source: 'archive' as const,
        })
      }

      setChats((prev) => ({
        ...prev,
        alice2: [
          ...restoredLines,
          ...prev.alice2.filter((line) => !restoredLines.some((restored) => restored.id === line.id)),
        ].sort((left, right) => left.epoch - right.epoch || left.generation - right.generation),
      }))
      setVault((prev) => {
        const unlockedEpochs = Array.from(new Set([...prev.alice2UnlockedEpochs, ...availableEpochs])).sort((left, right) => left - right)
        return {
          ...prev,
          alice2UnlockedEpochs: unlockedEpochs,
        }
      })
    } catch (error) {
      addLog(`Alice device 2 restore failed. PIN may be wrong: ${(error as Error).message}`, 'error')
    } finally {
      setBusy(false)
    }
  }, [actors, addLog, busy, messages, vault.records])

  const status = useMemo(() => {
    if (!wasmReady) return 'Loading WASM'
    if (!actors) return 'Initializing'
    return `Alice D1 ${toNumber(actors.alice1.group.epoch())} / Alice D2 ${actors.alice2 ? toNumber(actors.alice2.group.epoch()) : '-'} / Bob ${toNumber(actors.bob.group.epoch())}`
  }, [actors, wasmReady])

  const vaultRecordCount = Object.keys(vault.records).length
  const recoveryStats = useMemo(() => ({
    snapshots: Object.keys(recoveryStore.memberSnapshots).length,
    archiveBlobs: Object.keys(recoveryStore.archiveBlobs).length,
    keyWraps: Object.keys(recoveryStore.archiveKeyWraps).length,
    latestGroupInfoEpoch: recoveryStore.latestGroupInfo?.epoch,
    latestSnapshotHash: recoveryStore.latestSnapshotHash,
  }), [recoveryStore])

  const chatCards = useMemo(() => {
    const alice2Joined = Boolean(actors?.alice2)
    return [
      {
        id: 'alice1' as const,
        title: 'Alice device 1',
        userLabel: 'Alice member, PIN owner',
        icon: <Laptop size={18} />,
        actor: actors?.alice1,
        enabled: Boolean(actors?.alice1),
        vaultSummary: vault.pinCreated ? `PIN vault created (${vaultRecordCount} record)` : 'PIN vault not created',
      },
      {
        id: 'alice2' as const,
        title: 'Alice device 2',
        userLabel: alice2Joined ? 'Alice member, joined late' : 'Not joined',
        icon: <Smartphone size={18} />,
        actor: actors?.alice2,
        enabled: alice2Joined,
        vaultSummary: vault.alice2UnlockedEpochs.length > 0
          ? `unlocked epoch ${vault.alice2UnlockedEpochs.join(', ')}`
          : 'old history locked',
      },
      {
        id: 'bob' as const,
        title: 'Bob device',
        userLabel: 'Bob member',
        icon: <UserRound size={18} />,
        actor: actors?.bob,
        enabled: Boolean(actors?.bob),
        vaultSummary: 'no Alice PIN vault access',
      },
    ]
  }, [actors, vault, vaultRecordCount])

  return (
    <main className="app">
      <header className="topbar">
        <div>
          <div className="title">
            <ShieldCheck size={30} color="#0f766e" />
            <h1>OpenMLS Chat V4: Interactive PIN Restore</h1>
          </div>
          <p className="subtitle">
            Alice device 1 creates a PIN manually; Alice device 2 joins later and unlocks old history with that PIN.
          </p>
        </div>
        <div className="toolbar">
          <button className="btn neutral" onClick={reset} disabled={busy || !wasmReady}>
            <RotateCcw size={17} /> Reset
          </button>
        </div>
      </header>

      <section className="state-strip">
        <div className="status-card">
          <div className="label">Runtime epochs</div>
          <div className="value mono">{status}</div>
        </div>
        <div className="status-card">
          <div className="label">Channel</div>
          <div className="value mono">{CHANNEL_CID}</div>
        </div>
        <div className="status-card">
          <div className="label">Ciphertexts</div>
          <div className="value">{messages.length}</div>
        </div>
        <div className="status-card pin-card">
          <div className="label">Alice PIN vault</div>
          <div className="value">{vault.pinCreated ? vault.pinMasked : 'No PIN'}</div>
          <div className="mini-meta">
            {vaultRecordCount} encrypted record{vaultRecordCount === 1 ? '' : 's'}
            {vault.alice2UnlockedEpochs.length > 0 && ` / Alice D2 unlocked epoch ${vault.alice2UnlockedEpochs.join(', ')}`}
          </div>
        </div>
        <div className="status-card storage-card">
          <div className="label">Recovery K-V POC</div>
          <div className="value mono">{RECOVERY_NAMESPACE}</div>
          <div className="mini-meta">
            GroupInfo epoch {recoveryStats.latestGroupInfoEpoch ?? '-'} / snapshots {recoveryStats.snapshots} / blobs {recoveryStats.archiveBlobs} / wraps {recoveryStats.keyWraps}
          </div>
          <div className="mini-meta">latest optimized snapshot {recoveryStats.latestSnapshotHash ? shortHash(recoveryStats.latestSnapshotHash) : '-'}</div>
        </div>
      </section>

      <section className="actions-panel">
        <div className="action-block">
          <div>
            <div className="label">Alice 1 PIN</div>
            <div className="mini-meta">Create this before Alice 2 restores history.</div>
          </div>
          <input
            value={pinDraft}
            onChange={(event) => setPinDraft(event.target.value)}
            placeholder="Enter 4-12 digit PIN"
            inputMode="numeric"
            type="password"
            disabled={busy || vault.pinCreated}
          />
          <button className="btn" onClick={createPin} disabled={busy || vault.pinCreated || !actors}>
            <Lock size={16} /> Create PIN
          </button>
        </div>

        <div className="action-block">
          <div>
            <div className="label">Alice 2 lifecycle</div>
            <div className="mini-meta">Join first, then restore pre-join messages with PIN.</div>
          </div>
          <button className="btn secondary" onClick={joinAlice2} disabled={busy || !actors || Boolean(actors.alice2)}>
            <UserPlus size={16} /> Join Alice 2
          </button>
          <button
            className="btn"
            onClick={restoreAlice2}
            disabled={busy || !actors?.alice2 || !vault.pinCreated || messages.filter((message) => message.epoch < (actors.alice2?.joinedEpoch ?? 0)).length === 0}
          >
            <Unlock size={16} /> Restore old messages
          </button>
        </div>

        <div className="action-block rotate-block">
          <div>
            <div className="label">Epoch / key rotation</div>
            <div className="mini-meta">Alice 1 self-update commit advances the MLS epoch.</div>
          </div>
          <button className="btn warning" onClick={rotateKey} disabled={busy || !actors}>
            <KeyRound size={16} /> Key rotate
          </button>
        </div>
      </section>

      <section className="chat-layout">
        <div className="chat-grid">
          {chatCards.map((chat) => (
            <article className={`chat-box ${chat.enabled ? '' : 'disabled'}`} key={chat.id}>
              <div className="chat-head">
                <div className="device-icon">{chat.icon}</div>
                <div>
                  <h2>{chat.title}</h2>
                  <p>{chat.userLabel}</p>
                </div>
              </div>

              <div className="device-meta">
                <span><History size={13} /> joined epoch {chat.actor?.joinedEpoch ?? '-'}</span>
                <span><KeyRound size={13} /> current epoch {chat.actor ? toNumber(chat.actor.group.epoch()) : '-'}</span>
                <span><Archive size={13} /> archives: {chat.actor ? Object.keys(chat.actor.archives).map((epoch) => `epoch ${epoch}`).join(', ') : '-'}</span>
                <span><ShieldCheck size={13} /> {chat.vaultSummary}</span>
              </div>

              <div className="messages">
                {chats[chat.id].length === 0 && (
                  <div className="empty-chat">
                    {chat.id === 'alice2' && !chat.enabled
                      ? 'Click Join Alice 2 to add this device.'
                      : 'No messages in this device view yet.'}
                  </div>
                )}
                {chats[chat.id].map((line) => (
                  <div
                    className={`bubble ${line.senderLabel.startsWith(chat.title) ? 'own' : ''} ${line.source}`}
                    key={`${chat.id}-${line.id}-${line.source}`}
                  >
                    <div className="bubble-top">
                      <strong>{line.senderLabel}</strong>
                      <span className={`pill ${line.source}`}>
                        {line.source === 'archive' && <Archive size={12} />}
                        {line.source !== 'archive' && <CheckCircle2 size={12} />}
                        {sourceLabel(line.source)}
                      </span>
                    </div>
                    <p>{line.text}</p>
                    <div className="bubble-meta">epoch {line.epoch} / gen {line.generation}</div>
                  </div>
                ))}
              </div>

              <div className="composer">
                <input
                  value={drafts[chat.id]}
                  onChange={(event) => setDrafts((prev) => ({ ...prev, [chat.id]: event.target.value }))}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter') sendFrom(chat.id)
                  }}
                  placeholder={chat.enabled ? `Message as ${chat.title}` : 'Device not joined'}
                  disabled={!chat.enabled || busy}
                />
                <button className="icon-btn" onClick={() => sendFrom(chat.id)} disabled={!chat.enabled || busy}>
                  <Send size={17} />
                </button>
              </div>
            </article>
          ))}
        </div>

        <section className="panel log-panel">
          <h2>Protocol Log</h2>
          <div className="log" ref={logRef}>
            {logs.length === 0 && <div className="log-line">Waiting for actions...</div>}
            {logs.map((entry, index) => (
              <div className={`log-line ${entry.type}`} key={`${entry.time}-${index}`}>
                <span className="mono">[{entry.time}] </span>
                {entry.message}
              </div>
            ))}
          </div>
        </section>
      </section>
    </main>
  )
}

export default App
