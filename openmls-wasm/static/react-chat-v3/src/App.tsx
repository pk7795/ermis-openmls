import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  Archive,
  CheckCircle2,
  History,
  KeyRound,
  MessageSquareText,
  Play,
  RotateCcw,
  ShieldCheck,
} from 'lucide-react'

import init, {
  Provider,
  Identity,
  Group,
  decrypt_with_epoch_archive,
  peek_sender_data_from_archive,
} from './wasm/openmls_wasm.js'

const CHANNEL_CID = 'team:epoch_archive_poc'

type LogType = 'info' | 'success' | 'error' | 'warning' | 'commit'

type LogEntry = {
  time: string
  type: LogType
  message: string
}

type Actor = {
  id: 'alice' | 'bob'
  provider: any
  identity: any
  group: any
  archive: Uint8Array
}

type Actors = {
  alice: Actor
  bob: Actor
}

type StoredMessage = {
  id: string
  label: string
  senderId: string
  ciphertext: Uint8Array
  epoch: number
  generation: number
  liveText?: string
  recoveredByBob?: string
  recoveredOwn?: string
  recoveredAfterWindow?: string
  normalAfterWindowError?: string
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

function shortHex(bytes: Uint8Array, length = 10): string {
  return Array.from(bytes.slice(0, length))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
}

function App(): React.ReactElement {
  const [wasmReady, setWasmReady] = useState(false)
  const [running, setRunning] = useState(false)
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [actors, setActors] = useState<Actors | null>(null)
  const [messages, setMessages] = useState<StoredMessage[]>([])
  const logRef = useRef<HTMLDivElement>(null)

  const addLog = useCallback((message: string, type: LogType = 'info') => {
    setLogs((prev) => [...prev, { time: nowTime(), type, message }])
  }, [])

  useEffect(() => {
    init()
      .then(() => {
        setWasmReady(true)
        addLog('WASM module initialized with epoch archive bindings', 'success')
      })
      .catch((error: Error) => addLog(`WASM init failed: ${error.message}`, 'error'))
  }, [addLog])

  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight })
  }, [logs])

  const reset = useCallback(() => {
    setActors(null)
    setMessages([])
    setLogs([])
    addLog('Demo state reset', 'info')
  }, [addLog])

  const setupActors = useCallback((): Actors => {
    const aliceProvider = new Provider()
    const bobProvider = new Provider()
    const aliceIdentity = new Identity(aliceProvider, 'alice')
    const bobIdentity = new Identity(bobProvider, 'bob')

    const aliceGroup = Group.create_with_cid(aliceProvider, aliceIdentity, CHANNEL_CID)
    addLog(`Alice created group ${CHANNEL_CID} at epoch ${toNumber(aliceGroup.epoch())}`, 'success')

    const bobKeyPackage = bobIdentity.key_package(bobProvider)
    const addBundle = aliceGroup.add_members(aliceProvider, aliceIdentity, [bobKeyPackage])
    aliceGroup.merge_pending_commit(aliceProvider)
    const ratchetTree = aliceGroup.export_ratchet_tree()
    const bobGroup = Group.join_with_welcome(bobProvider, addBundle.welcome, ratchetTree)
    addLog(`Bob joined group at epoch ${toNumber(bobGroup.epoch())}`, 'success')

    const aliceArchive = aliceGroup.archive_current_epoch()
    const bobArchive = bobGroup.archive_current_epoch()
    addLog(`Archived fresh epoch ${toNumber(bobGroup.epoch())} for Alice (${aliceArchive.length} bytes)`, 'success')
    addLog(`Archived fresh epoch ${toNumber(bobGroup.epoch())} for Bob (${bobArchive.length} bytes)`, 'success')

    const nextActors = {
      alice: {
        id: 'alice',
        provider: aliceProvider,
        identity: aliceIdentity,
        group: aliceGroup,
        archive: aliceArchive,
      },
      bob: {
        id: 'bob',
        provider: bobProvider,
        identity: bobIdentity,
        group: bobGroup,
        archive: bobArchive,
      },
    } satisfies Actors

    setActors(nextActors)
    return nextActors
  }, [addLog])

  const createArchivedMessage = useCallback(
    (sender: Actor, receiverArchiveOwner: Actor, label: string, text: string): StoredMessage => {
      const id = crypto.randomUUID()
      const aad = {
        message_id: id,
        sender_id: sender.id,
        channel_id: CHANNEL_CID,
        created_at: Date.now(),
      }
      const ciphertext = sender.group.create_message_with_aad(
        sender.provider,
        sender.identity,
        encodeJson({ text }),
        encodeJson(aad),
      )
      const senderData = peek_sender_data_from_archive(
        receiverArchiveOwner.provider,
        receiverArchiveOwner.archive,
        ciphertext,
      )

      return {
        id,
        label,
        senderId: sender.id,
        ciphertext,
        epoch: toNumber(senderData.epoch),
        generation: senderData.generation,
      }
    },
    [],
  )

  const recoverText = useCallback(
    (provider: any, archive: Uint8Array, ciphertext: Uint8Array, allowOwnMessages: boolean): string => {
      const recovered = decrypt_with_epoch_archive(provider, archive, ciphertext, allowOwnMessages, 0)
      const encryptedContent = decodeJson<{ text: string }>(recovered.content)
      const aad = decodeJson<{ message_id: string; sender_id: string }>(recovered.aad)
      addLog(
        `Archive recovery ok: sender=${aad.sender_id}, gen=${recovered.generation}, own=${recovered.own_message}`,
        'success',
      )
      return encryptedContent.text
    },
    [addLog],
  )

  const processLiveForBob = useCallback((bob: Actor, message: StoredMessage): string => {
    const processed = bob.group.process_message(bob.provider, message.ciphertext)
    if (!processed.is_application_message()) {
      throw new Error('Expected application message')
    }
    const encryptedContent = decodeJson<{ text: string }>(processed.content)
    const aad = decodeJson<{ message_id: string; sender_id: string }>(processed.aad)
    addLog(`Bob live decrypt ok: sender=${aad.sender_id}, msg=${aad.message_id.slice(0, 8)}`, 'success')
    return encryptedContent.text
  }, [addLog])

  const advanceAliceEpochs = useCallback((currentActors: Actors, count: number) => {
    for (let i = 0; i < count; i += 1) {
      const update = currentActors.alice.group.self_update(
        currentActors.alice.provider,
        currentActors.alice.identity,
      )
      currentActors.alice.group.merge_pending_commit(currentActors.alice.provider)
      currentActors.bob.group.process_message(currentActors.bob.provider, update.commit)
      addLog(
        `Epoch advanced by Alice update: Alice=${toNumber(currentActors.alice.group.epoch())}, Bob=${toNumber(currentActors.bob.group.epoch())}`,
        'commit',
      )
    }
  }, [addLog])

  const runFullPoc = useCallback(async () => {
    if (!wasmReady || running) return
    setRunning(true)
    setMessages([])

    try {
      const currentActors = setupActors()
      const createdMessages: StoredMessage[] = []

      const coldMessage = createArchivedMessage(
        currentActors.alice,
        currentActors.bob,
        'Epoch 1 cold message',
        'This message is never decrypted by Bob live until epoch 7.',
      )
      addLog(
        `Stored ciphertext ${coldMessage.id.slice(0, 8)} at epoch ${coldMessage.epoch}, generation ${coldMessage.generation}`,
        'info',
      )

      coldMessage.recoveredByBob = recoverText(
        currentActors.bob.provider,
        currentActors.bob.archive,
        coldMessage.ciphertext,
        true,
      )
      coldMessage.recoveredOwn = recoverText(
        currentActors.alice.provider,
        currentActors.alice.archive,
        coldMessage.ciphertext,
        true,
      )
      createdMessages.push(coldMessage)

      const liveMessage = createArchivedMessage(
        currentActors.alice,
        currentActors.bob,
        'Live message',
        'Bob decrypts this through normal MLS state first.',
      )
      liveMessage.liveText = processLiveForBob(currentActors.bob, liveMessage)
      liveMessage.recoveredByBob = recoverText(
        currentActors.bob.provider,
        currentActors.bob.archive,
        liveMessage.ciphertext,
        true,
      )
      createdMessages.push(liveMessage)

      const batch = [
        createArchivedMessage(currentActors.alice, currentActors.bob, 'Batch message A', 'Batch item A'),
        createArchivedMessage(currentActors.alice, currentActors.bob, 'Batch message B', 'Batch item B'),
        createArchivedMessage(currentActors.alice, currentActors.bob, 'Batch message C', 'Batch item C'),
      ]
      const recoveredOutOfOrder = [...batch].reverse().map((message) => ({
        ...message,
        recoveredByBob: recoverText(currentActors.bob.provider, currentActors.bob.archive, message.ciphertext, true),
      }))
      createdMessages.push(...recoveredOutOfOrder)
      addLog('Recovered batch messages out of order by using a fresh archive clone per call', 'success')

      advanceAliceEpochs(currentActors, 6)

      try {
        currentActors.bob.group.process_message(currentActors.bob.provider, coldMessage.ciphertext)
        coldMessage.normalAfterWindowError = 'unexpected success'
        addLog('Unexpected live decrypt success for old epoch message', 'error')
      } catch (error) {
        coldMessage.normalAfterWindowError = (error as Error).message
        addLog(
          `Expected live-state rejection after epoch window: ${(error as Error).message}`,
          'success',
        )
      }

      coldMessage.recoveredAfterWindow = recoverText(
        currentActors.bob.provider,
        currentActors.bob.archive,
        coldMessage.ciphertext,
        true,
      )
      addLog('Archive recovery still decrypts the epoch 1 message after live state moved past the window', 'success')

      setActors({ ...currentActors })
      setMessages([...createdMessages])
    } catch (error) {
      addLog(`POC failed: ${(error as Error).message}`, 'error')
    } finally {
      setRunning(false)
    }
  }, [
    addLog,
    advanceAliceEpochs,
    createArchivedMessage,
    processLiveForBob,
    recoverText,
    running,
    setupActors,
    wasmReady,
  ])

  const status = useMemo(() => {
    if (!wasmReady) return 'Loading WASM'
    if (!actors) return 'Ready'
    return `Epoch ${toNumber(actors.bob.group.epoch())}`
  }, [actors, wasmReady])

  return (
    <main className="app">
      <header className="topbar">
        <div>
          <div className="title">
            <ShieldCheck size={30} color="#0f766e" />
            <h1>OpenMLS Chat V3: Epoch Archive POC</h1>
          </div>
          <p className="subtitle">
            Archives fresh MLS epoch secrets, then decrypts historical ciphertext without old live group state.
          </p>
        </div>
        <div className="toolbar">
          <button className="btn" onClick={runFullPoc} disabled={!wasmReady || running}>
            <Play size={17} /> {running ? 'Running' : 'Run full POC'}
          </button>
          <button className="btn neutral" onClick={reset} disabled={running}>
            <RotateCcw size={17} /> Reset
          </button>
        </div>
      </header>

      <section className="layout">
        <div className="grid">
          <section className="panel">
            <h2>State</h2>
            <div className="grid two">
              <div className="status-card">
                <div className="label">Runtime</div>
                <div className="value">{status}</div>
              </div>
              <div className="status-card">
                <div className="label">Channel</div>
                <div className="value mono">{CHANNEL_CID}</div>
              </div>
              <div className="status-card">
                <div className="label">Alice Archive</div>
                <div className="value">{actors ? `${actors.alice.archive.length} bytes` : '-'}</div>
              </div>
              <div className="status-card">
                <div className="label">Bob Archive</div>
                <div className="value">{actors ? `${actors.bob.archive.length} bytes` : '-'}</div>
              </div>
            </div>
          </section>

          <section className="panel">
            <h2>Recovered Messages</h2>
            <div className="message-list">
              {messages.length === 0 && (
                <div className="status-card">
                  <span className="badge warn">No run yet</span>
                  <p className="subtitle">Run the POC to create ciphertext, archive epoch state, and recover history.</p>
                </div>
              )}

              {messages.map((message) => (
                <article className="message" key={message.id}>
                  <div className="message-header">
                    <span>{message.label}</span>
                    <span className="mono">
                      epoch {message.epoch} / gen {message.generation} / {message.ciphertext.length} bytes
                    </span>
                  </div>
                  <p className="message-text">{message.recoveredByBob || message.liveText || 'Encrypted only'}</p>
                  <div className="recovery-grid">
                    <div className="recovery">
                      <strong><Archive size={14} /> Bob archive</strong>
                      {message.recoveredByBob || '-'}
                    </div>
                    <div className="recovery">
                      <strong><KeyRound size={14} /> Alice own archive</strong>
                      {message.recoveredOwn || '-'}
                    </div>
                    <div className="recovery">
                      <strong><MessageSquareText size={14} /> Live Bob decrypt</strong>
                      {message.liveText || '-'}
                    </div>
                    <div className="recovery">
                      <strong><History size={14} /> After epoch window</strong>
                      {message.recoveredAfterWindow || message.normalAfterWindowError || '-'}
                    </div>
                  </div>
                  <div className="message-header" style={{ marginTop: 8 }}>
                    <span className="badge good"><CheckCircle2 size={13} /> ciphertext #{message.id.slice(0, 8)}</span>
                    <span className="mono">{shortHex(message.ciphertext)}</span>
                  </div>
                </article>
              ))}
            </div>
          </section>
        </div>

        <section className="panel">
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
