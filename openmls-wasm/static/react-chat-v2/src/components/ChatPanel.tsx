import React, { useState, useEffect, useRef, FormEvent } from 'react';
import { Send } from 'lucide-react';
import { ChatPanelProps, DisplayMessage, MlsMember, SendMessageOptions } from '../types';

const ChatPanel: React.FC<ChatPanelProps> = ({
    name,
    userId,
    onSendMessage,
    messages = [],
    members = [],
    epoch,
    onAddMember,
    onRemoveMember,
    onExternalJoinPre,
    onExternalJoinPost,
    onKeyRotate
}) => {
    const [input, setInput] = useState<string>('');
    const messagesEndRef = useRef<HTMLDivElement>(null);

    const scrollToBottom = (): void => {
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    };

    useEffect(() => {
        scrollToBottom();
    }, [messages]);

    const handleSubmit = (e: FormEvent<HTMLFormElement>): void => {
        e.preventDefault();
        if (!input.trim()) return;
        onSendMessage(userId, input);
        setInput('');
    };

    return (
        <div className="panel" style={{ height: '550px', display: 'flex', flexDirection: 'column' }}>
            <div style={{ borderBottom: '1px solid #e2e8f0', paddingBottom: '12px', marginBottom: '12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#10b981' }} />
                        <h3>{name}</h3>
                        <span className="badge badge-info">Epoch: {epoch}</span>
                    </div>
                    <div style={{ display: 'flex', gap: '8px' }}>
                        {onAddMember && (
                            <button
                                className="btn btn-primary"
                                style={{ padding: '4px 8px', fontSize: '12px' }}
                                onClick={() => onAddMember(userId)}
                            >
                                Add to Group
                            </button>
                        )}
                        {onRemoveMember && (
                            <button
                                className="btn btn-warning"
                                style={{ padding: '4px 8px', fontSize: '12px' }}
                                onClick={() => onRemoveMember(userId)}
                            >
                                Remove
                            </button>
                        )}
                        {onExternalJoinPre && (
                            <button
                                className="btn btn-success"
                                style={{ padding: '4px 8px', fontSize: '12px' }}
                                onClick={() => onExternalJoinPre(userId)}
                            >
                                External Join (Pre)
                            </button>
                        )}
                        {onExternalJoinPost && (
                            <button
                                className="btn btn-success"
                                style={{ padding: '4px 8px', fontSize: '12px' }}
                                onClick={() => onExternalJoinPost(userId)}
                            >
                                External Join (Post)
                            </button>
                        )}
                        {onKeyRotate && (
                            <button
                                className="btn btn-primary"
                                style={{ padding: '4px 8px', fontSize: '12px' }}
                                onClick={() => onKeyRotate(userId)}
                            >
                                Key Rotate
                            </button>
                        )}
                    </div>
                </div>
                <div style={{ fontSize: '12px', color: '#666' }}>
                    Members: {members.map((m: MlsMember) => m.user_id).join(', ')}
                </div>
            </div>

            <div style={{ flex: 1, overflowY: 'auto', padding: '10px', background: '#f8fafc', borderRadius: '8px', marginBottom: '12px' }}>
                {messages.map((msg: DisplayMessage, idx: number) => {
                    const isMe = msg.sender === userId;
                    const time = msg.created_at
                        ? new Date(msg.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
                        : '';
                    return (
                        <div key={msg.id || idx} style={{
                            display: 'flex',
                            justifyContent: isMe ? 'flex-end' : 'flex-start',
                            marginBottom: '8px'
                        }}>
                            <div style={{
                                maxWidth: '80%',
                                padding: '8px 12px',
                                borderRadius: '12px',
                                background: isMe ? '#667eea' : 'white',
                                color: isMe ? 'white' : '#333',
                                border: isMe ? 'none' : '1px solid #e2e8f0',
                                boxShadow: '0 1px 2px rgba(0,0,0,0.05)'
                            }}>
                                {!isMe && <div style={{ fontSize: '11px', opacity: 0.7, marginBottom: '2px' }}>{msg.sender}</div>}
                                {msg.type === 'reply' && (
                                    <div style={{
                                        fontSize: '10px',
                                        opacity: 0.6,
                                        fontStyle: 'italic',
                                        marginBottom: '4px',
                                        borderLeft: '2px solid currentColor',
                                        paddingLeft: '6px'
                                    }}>
                                        Reply to message
                                    </div>
                                )}
                                <div>{msg.text}</div>
                                {/* Metadata footer */}
                                <div style={{
                                    display: 'flex',
                                    justifyContent: 'flex-end',
                                    alignItems: 'center',
                                    gap: '6px',
                                    marginTop: '4px',
                                    fontSize: '10px',
                                    opacity: 0.6
                                }}>
                                    {msg.id && <span title={`ID: ${msg.id}`}>#{msg.id.slice(0, 4)}</span>}
                                    {time && <span>{time}</span>}
                                    {msg.status === 'sent' && <span>✓</span>}
                                </div>
                            </div>
                        </div>
                    );
                })}
                <div ref={messagesEndRef} />
            </div>

            <form onSubmit={handleSubmit} style={{ display: 'flex', gap: '8px' }}>
                <input
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    placeholder="Type a message..."
                />
                <button type="submit" className="btn btn-primary" style={{ padding: '8px 12px' }}>
                    <Send size={18} />
                </button>
            </form>
        </div>
    );
};

export default ChatPanel;
