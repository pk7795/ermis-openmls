import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  Archive,
  CheckCircle2,
  History,
  KeyRound,
  Laptop,
  Play,
  RotateCcw,
  ShieldCheck,
  Smartphone,
  UserRound,
} from 'lucide-react'

import init, {
  Provider,
  Identity,
  Group,
  decrypt_with_epoch_archive,
  peek_sender_data_from_archive,
} from './wasm/openmls_wasm.js'

const CHANNEL_CID = 'team:epoch_archive_restore_demo'
const ALICE_VAULT_PIN = '246810'
const VAULT_KDF_ITERATIONS = 150_000

type LogType = 'info' | 'success' | 'error' | 'warning' | 'commit'
type DeviceId = 'alice1' | 'alice2' | 'bob'
type UserId = 'alice' | 'bob'
type MessageSource = 'sent' | 'live' | 'archive'

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

type DeviceChat = {
  id: DeviceId
  title: string
  userLabel: string
  epoch: number | null
  joinedEpoch: number | null
  archiveSummary: string
  vaultSummary: string
  lines: ChatLine[]
}

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

function nowTime(): string {
  return new Date().toLocaleTimeString()
}

function sourceLabel(source: MessageSource): string {
  if (source === 'archive') return 'restored'
  if (source === 'live') return 'live'
  return 'sent'
}

function maskPin(pin: string): string {
  return '•'.repeat(pin.length)
}

async function derivePinKey(pin: string, salt: Uint8Array, iterations: number): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(pin),
    'PBKDF2',
    false,
    ['deriveKey'],
  )
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

function App(): React.ReactElement {
  const [wasmReady, setWasmReady] = useState(false)
  const [running, setRunning] = useState(false)
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [actors, setActors] = useState<Actors | null>(null)
  const [messages, setMessages] = useState<StoredMessage[]>([])
  const [chats, setChats] = useState<DeviceChat[]>([])
  const [vault, setVault] = useState<VaultState>({
    pinCreated: false,
    pinMasked: '',
    records: {},
    alice2UnlockedEpochs: [],
  })
  const logRef = useRef<HTMLDivElement>(null)

  const addLog = useCallback((message: string, type: LogType = 'info') => {
    setLogs((prev) => [...prev, { time: nowTime(), type, message }])
  }, [])

  useEffect(() => {
    init()
      .then(() => {
        setWasmReady(true)
        addLog('WASM initialized: OpenMLS epoch archive bindings are ready', 'success')
      })
      .catch((error: Error) => addLog(`WASM init failed: ${error.message}`, 'error'))
  }, [addLog])

  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight })
  }, [logs])

  const reset = useCallback(() => {
    setActors(null)
    setMessages([])
    setChats([])
    setVault({
      pinCreated: false,
      pinMasked: '',
      records: {},
      alice2UnlockedEpochs: [],
    })
    setLogs([])
    addLog('Demo state reset', 'info')
  }, [addLog])

  const archiveActorEpoch = useCallback((actor: Actor, reason: string): Uint8Array => {
    const epoch = toNumber(actor.group.epoch())
    const archive = actor.group.archive_current_epoch()
    actor.archives[epoch] = archive
    addLog(`${actor.label} archived fresh epoch ${epoch} (${archive.length} bytes): ${reason}`, 'success')
    return archive
  }, [addLog])

  const setupInitialGroup = useCallback((): Actors => {
    const aliceProvider = new Provider()
    const bobProvider = new Provider()
    const aliceIdentity = new Identity(aliceProvider, 'alice')
    const bobIdentity = new Identity(bobProvider, 'bob')

    const aliceGroup = Group.create_with_cid(aliceProvider, aliceIdentity, CHANNEL_CID)
    addLog(`Alice device 1 created MLS group ${CHANNEL_CID} at epoch ${toNumber(aliceGroup.epoch())}`, 'success')

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

    archiveActorEpoch(nextActors.alice1, 'vault seed for Alice account history')
    archiveActorEpoch(nextActors.bob, 'Bob local history recovery seed')

    return nextActors
  }, [addLog, archiveActorEpoch])

  const createMessage = useCallback((sender: Actor, archiveForPeek: Uint8Array, text: string): StoredMessage => {
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
      `${sender.label} sent app message ${id.slice(0, 8)} at epoch ${message.epoch}, generation ${message.generation}`,
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

  const sentLine = useCallback((message: StoredMessage): ChatLine => ({
    id: message.id,
    senderLabel: message.senderLabel,
    text: message.text,
    epoch: message.epoch,
    generation: message.generation,
    source: 'sent',
  }), [])

  const recoverWithArchive = useCallback((actor: Actor, archive: Uint8Array, message: StoredMessage): ChatLine => {
    const recovered = decrypt_with_epoch_archive(actor.provider, archive, message.ciphertext, true, 0)
    const content = decodeJson<{ text: string }>(recovered.content)
    const aad = decodeJson<{ message_id: string; sender_device: DeviceId }>(recovered.aad)
    addLog(
      `${actor.label} restored ${aad.message_id.slice(0, 8)} via Alice vault archive: sender=${aad.sender_device}, epoch=${recovered.epoch}, gen=${recovered.generation}, archive_owner_message=${recovered.own_message}`,
      'success',
    )
    return {
      id: message.id,
      senderLabel: message.senderLabel,
      text: content.text,
      epoch: toNumber(recovered.epoch),
      generation: recovered.generation,
      source: 'archive',
    }
  }, [addLog])

  const advanceToEpoch = useCallback((currentActors: Actors, targetEpoch: number) => {
    while (toNumber(currentActors.alice1.group.epoch()) < targetEpoch) {
      const update = currentActors.alice1.group.self_update(
        currentActors.alice1.provider,
        currentActors.alice1.identity,
      )
      currentActors.alice1.group.merge_pending_commit(currentActors.alice1.provider)
      currentActors.bob.group.process_message(currentActors.bob.provider, update.commit)
      addLog(
        `Self-update commit applied: Alice device 1=${toNumber(currentActors.alice1.group.epoch())}, Bob=${toNumber(currentActors.bob.group.epoch())}`,
        'commit',
      )
    }
  }, [addLog])

  const joinAliceSecondDevice = useCallback((currentActors: Actors): Actor => {
    const alice2Provider = new Provider()
    const alice2Identity = new Identity(alice2Provider, 'alice')
    const alice2KeyPackage = alice2Identity.key_package(alice2Provider)

    const addAlice2 = currentActors.alice1.group.add_members(
      currentActors.alice1.provider,
      currentActors.alice1.identity,
      [alice2KeyPackage],
    )
    addLog('Alice device 1 committed Add for Alice device 2 while group was at epoch 9', 'commit')

    currentActors.alice1.group.merge_pending_commit(currentActors.alice1.provider)
    currentActors.bob.group.process_message(currentActors.bob.provider, addAlice2.commit)

    const alice2RatchetTree = currentActors.alice1.group.export_ratchet_tree()
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
    currentActors.alice2 = alice2

    addLog(
      `Alice device 2 joined from Welcome at epoch ${alice2.joinedEpoch}; it has no live MLS state for epoch 1 messages`,
      'success',
    )
    archiveActorEpoch(currentActors.alice1, 'fresh epoch after adding Alice device 2')
    archiveActorEpoch(currentActors.bob, 'fresh epoch after Alice device 2 joined')
    archiveActorEpoch(alice2, 'new device starts archiving from its join epoch')
    return alice2
  }, [addLog, archiveActorEpoch])

  const buildChats = useCallback((
    currentActors: Actors,
    alice1Lines: ChatLine[],
    bobLines: ChatLine[],
    alice2Lines: ChatLine[],
    aliceVault: Record<number, VaultRecord>,
    alice2UnlockedEpochs: number[],
  ): DeviceChat[] => [
    {
      id: 'alice1',
      title: 'Alice device 1',
      userLabel: 'Alice member',
      epoch: toNumber(currentActors.alice1.group.epoch()),
      joinedEpoch: currentActors.alice1.joinedEpoch,
      archiveSummary: Object.keys(currentActors.alice1.archives).map((epoch) => `epoch ${epoch}`).join(', '),
      vaultSummary: `PIN vault records: ${Object.keys(aliceVault).map((epoch) => `epoch ${epoch}`).join(', ')}`,
      lines: alice1Lines,
    },
    {
      id: 'alice2',
      title: 'Alice device 2',
      userLabel: 'Alice member, joined late',
      epoch: currentActors.alice2 ? toNumber(currentActors.alice2.group.epoch()) : null,
      joinedEpoch: currentActors.alice2?.joinedEpoch ?? null,
      archiveSummary: currentActors.alice2
        ? Object.keys(currentActors.alice2.archives).map((epoch) => `epoch ${epoch}`).join(', ')
        : 'not joined',
      vaultSummary: alice2UnlockedEpochs.length > 0
        ? `unlocked with PIN: epoch ${alice2UnlockedEpochs.join(', epoch ')}`
        : 'PIN vault locked',
      lines: alice2Lines,
    },
    {
      id: 'bob',
      title: 'Bob device',
      userLabel: 'Bob member',
      epoch: toNumber(currentActors.bob.group.epoch()),
      joinedEpoch: currentActors.bob.joinedEpoch,
      archiveSummary: Object.keys(currentActors.bob.archives).map((epoch) => `epoch ${epoch}`).join(', '),
      vaultSummary: 'no Alice PIN vault access',
      lines: bobLines,
    },
  ], [])

  const runFullPoc = useCallback(async () => {
    if (!wasmReady || running) return
    setRunning(true)
    setMessages([])
    setChats([])
    setVault({
      pinCreated: false,
      pinMasked: '',
      records: {},
      alice2UnlockedEpochs: [],
    })

    try {
      const currentActors = setupInitialGroup()
      const createdMessages: StoredMessage[] = []
      const alice1Lines: ChatLine[] = []
      const bobLines: ChatLine[] = []
      const alice2Lines: ChatLine[] = []
      const aliceVault: Record<number, VaultRecord> = {}
      const alice2UnlockedEpochs: number[] = []
      const epoch1AliceVaultArchive = currentActors.alice1.archives[1]

      addLog('Phase 1: Alice device 1 creates a PIN and seals the fresh epoch 1 archive', 'info')
      addLog(
        `Alice device 1 created account recovery PIN ${maskPin(ALICE_VAULT_PIN)} (${ALICE_VAULT_PIN.length} digits)`,
        'success',
      )
      addLog(
        `PIN KDF configured: PBKDF2-SHA256, ${VAULT_KDF_ITERATIONS.toLocaleString()} iterations, AES-GCM-256 archive wrapping`,
        'info',
      )
      aliceVault[1] = await encryptArchiveWithPin(
        ALICE_VAULT_PIN,
        epoch1AliceVaultArchive,
        {
          ownerUser: 'alice',
          ownerDevice: 'alice1',
          channelId: CHANNEL_CID,
          epoch: 1,
          createdAt: Date.now(),
        },
      )
      setVault({
        pinCreated: true,
        pinMasked: maskPin(ALICE_VAULT_PIN),
        records: { ...aliceVault },
        alice2UnlockedEpochs: [],
      })
      addLog(
        `Alice device 1 encrypted epoch 1 archive into PIN vault: plaintext=${epoch1AliceVaultArchive.length} bytes, ciphertext=${aliceVault[1].ciphertext.length} bytes`,
        'success',
      )

      addLog('Phase 2: create old chat history in epoch 1 before Alice device 2 exists', 'info')

      const oldAliceMessage = createMessage(
        currentActors.alice1,
        epoch1AliceVaultArchive,
        'Epoch 1: Alice device 1 sends the first encrypted message.',
      )
      createdMessages.push(oldAliceMessage)
      alice1Lines.push(sentLine(oldAliceMessage))
      bobLines.push(processLive(currentActors.bob, oldAliceMessage))

      const oldBobMessage = createMessage(
        currentActors.bob,
        currentActors.bob.archives[1],
        'Epoch 1: Bob replies before Alice device 2 is installed.',
      )
      createdMessages.push(oldBobMessage)
      bobLines.push(sentLine(oldBobMessage))
      alice1Lines.push(processLive(currentActors.alice1, oldBobMessage))

      const oldAliceMessageTwo = createMessage(
        currentActors.alice1,
        epoch1AliceVaultArchive,
        'Epoch 1: this message will later be restored on Alice device 2 from archive.',
      )
      createdMessages.push(oldAliceMessageTwo)
      alice1Lines.push(sentLine(oldAliceMessageTwo))
      bobLines.push(processLive(currentActors.bob, oldAliceMessageTwo))

      addLog('Phase 3: advance live group state from epoch 1 to epoch 9', 'info')
      advanceToEpoch(currentActors, 9)

      addLog('Phase 4: add Alice device 2; Welcome creates its live group at epoch 10', 'info')
      const alice2 = joinAliceSecondDevice(currentActors)

      try {
        alice2.group.process_message(alice2.provider, oldAliceMessage.ciphertext)
        addLog('Unexpected: Alice device 2 live-decrypted an epoch 1 message', 'error')
      } catch (error) {
        addLog(
          `Expected: Alice device 2 live state cannot read epoch 1 ciphertext: ${(error as Error).message}`,
          'warning',
        )
      }

      addLog('Phase 5: Alice device 2 uses Alice PIN to unlock the encrypted epoch 1 vault archive', 'info')
      addLog(
        `Alice device 2 entered PIN ${maskPin(ALICE_VAULT_PIN)} and derives the same vault key locally`,
        'info',
      )
      const unlockedEpoch1Archive = await decryptArchiveWithPin(ALICE_VAULT_PIN, aliceVault[1])
      alice2UnlockedEpochs.push(1)
      setVault({
        pinCreated: true,
        pinMasked: maskPin(ALICE_VAULT_PIN),
        records: { ...aliceVault },
        alice2UnlockedEpochs: [...alice2UnlockedEpochs],
      })
      addLog(
        `Alice device 2 decrypted PIN vault record for epoch 1: archive=${unlockedEpoch1Archive.length} bytes`,
        'success',
      )

      addLog('Phase 6: Alice device 2 restores old chat history using the PIN-unlocked archive', 'info')
      for (const message of createdMessages) {
        alice2Lines.push(recoverWithArchive(alice2, unlockedEpoch1Archive, message))
      }

      addLog('Phase 7: send new messages after Alice device 2 joined; all devices decrypt live at epoch 10', 'info')

      aliceVault[10] = await encryptArchiveWithPin(
        ALICE_VAULT_PIN,
        currentActors.alice1.archives[10],
        {
          ownerUser: 'alice',
          ownerDevice: 'alice1',
          channelId: CHANNEL_CID,
          epoch: 10,
          createdAt: Date.now(),
        },
      )
      addLog(
        `Alice device 1 also sealed the fresh epoch 10 archive into the PIN vault (${aliceVault[10].ciphertext.length} bytes)`,
        'success',
      )

      const alice2Message = createMessage(
        alice2,
        alice2.archives[10],
        'Epoch 10: Alice device 2 is online and can send new encrypted messages.',
      )
      createdMessages.push(alice2Message)
      alice2Lines.push(sentLine(alice2Message))
      alice1Lines.push(processLive(currentActors.alice1, alice2Message))
      bobLines.push(processLive(currentActors.bob, alice2Message))

      const bobEpoch10Message = createMessage(
        currentActors.bob,
        currentActors.bob.archives[10],
        'Epoch 10: Bob sees Alice device 2 as a normal group member now.',
      )
      createdMessages.push(bobEpoch10Message)
      bobLines.push(sentLine(bobEpoch10Message))
      alice1Lines.push(processLive(currentActors.alice1, bobEpoch10Message))
      alice2Lines.push(processLive(alice2, bobEpoch10Message))

      setActors({ ...currentActors })
      setMessages(createdMessages)
      setVault({
        pinCreated: true,
        pinMasked: maskPin(ALICE_VAULT_PIN),
        records: { ...aliceVault },
        alice2UnlockedEpochs: [...alice2UnlockedEpochs],
      })
      setChats(buildChats(currentActors, alice1Lines, bobLines, alice2Lines, aliceVault, alice2UnlockedEpochs))
      addLog('Demo complete: Alice device 2 joined at epoch 10, unlocked Alice PIN vault, and restored epoch 1 history', 'success')
    } catch (error) {
      addLog(`POC failed: ${(error as Error).message}`, 'error')
    } finally {
      setRunning(false)
    }
  }, [
    addLog,
    advanceToEpoch,
    buildChats,
    createMessage,
    joinAliceSecondDevice,
    processLive,
    recoverWithArchive,
    running,
    sentLine,
    setupInitialGroup,
    wasmReady,
  ])

  const status = useMemo(() => {
    if (!wasmReady) return 'Loading WASM'
    if (!actors) return 'Ready'
    return `Alice D1 ${toNumber(actors.alice1.group.epoch())} / Alice D2 ${actors.alice2 ? toNumber(actors.alice2.group.epoch()) : '-'} / Bob ${toNumber(actors.bob.group.epoch())}`
  }, [actors, wasmReady])

  const vaultRecordCount = Object.keys(vault.records).length

  return (
    <main className="app">
      <header className="topbar">
        <div>
          <div className="title">
            <ShieldCheck size={30} color="#0f766e" />
            <h1>OpenMLS Chat V3: Late Device Restore</h1>
          </div>
          <p className="subtitle">
            Alice seals epoch archives with a PIN, then a second device uses that PIN to restore old chat history.
          </p>
        </div>
        <div className="toolbar">
          <button className="btn" onClick={runFullPoc} disabled={!wasmReady || running}>
            <Play size={17} /> {running ? 'Running' : 'Run visual demo'}
          </button>
          <button className="btn neutral" onClick={reset} disabled={running}>
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
          <div className="value">{vault.pinCreated ? vault.pinMasked : '-'}</div>
          <div className="mini-meta">
            {vaultRecordCount} encrypted record{vaultRecordCount === 1 ? '' : 's'}
            {vault.alice2UnlockedEpochs.length > 0 && ` / Alice D2 unlocked epoch ${vault.alice2UnlockedEpochs.join(', ')}`}
          </div>
        </div>
      </section>

      <section className="chat-layout">
        <div className="chat-grid">
          {chats.length === 0 && (
            <>
              {(['alice1', 'alice2', 'bob'] as DeviceId[]).map((id) => (
                <article className="chat-box empty" key={id}>
                  <div className="chat-head">
                    <div className="device-icon">{id === 'alice2' ? <Smartphone size={18} /> : <Laptop size={18} />}</div>
                    <div>
                      <h2>{id === 'alice1' ? 'Alice device 1' : id === 'alice2' ? 'Alice device 2' : 'Bob device'}</h2>
                      <p>{id === 'alice2' ? 'Will join at epoch 10' : 'Ready for demo run'}</p>
                    </div>
                  </div>
                  <div className="empty-chat">Run the demo to populate this device chat box.</div>
                </article>
              ))}
            </>
          )}

          {chats.map((chat) => (
            <article className="chat-box" key={chat.id}>
              <div className="chat-head">
                <div className="device-icon">
                  {chat.id === 'alice2' ? <Smartphone size={18} /> : chat.id === 'bob' ? <UserRound size={18} /> : <Laptop size={18} />}
                </div>
                <div>
                  <h2>{chat.title}</h2>
                  <p>{chat.userLabel}</p>
                </div>
              </div>

              <div className="device-meta">
                <span><History size={13} /> joined epoch {chat.joinedEpoch ?? '-'}</span>
                <span><KeyRound size={13} /> current epoch {chat.epoch ?? '-'}</span>
                <span><Archive size={13} /> archives: {chat.archiveSummary || '-'}</span>
                <span><ShieldCheck size={13} /> {chat.vaultSummary}</span>
              </div>

              <div className="messages">
                {chat.lines.map((line) => (
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
