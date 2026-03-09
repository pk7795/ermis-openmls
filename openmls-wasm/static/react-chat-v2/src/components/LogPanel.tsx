import React, { useEffect, useRef } from 'react';
import { Terminal } from 'lucide-react';
import { LogPanelProps, LogEntry } from '../types';

type LogType = LogEntry['type'];

const LogPanel: React.FC<LogPanelProps> = ({ logs }) => {
    const scrollRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [logs]);

    const getLogColor = (type: LogType): string => {
        switch (type) {
            case 'success': return '#10b981';
            case 'error': return '#ef4444';
            case 'warning': return '#f59e0b';
            case 'proposal': return '#8b5cf6';
            case 'commit': return '#ec4899';
            default: return '#3b82f6';
        }
    };

    const getTextColor = (type: LogType): string => {
        switch (type) {
            case 'success': return '#86efac';
            case 'error': return '#fca5a5';
            case 'warning': return '#fcd34d';
            case 'proposal': return '#c4b5fd';
            case 'commit': return '#f9a8d4';
            default: return '#e2e8f0';
        }
    };

    return (
        <div className="panel" style={{ background: '#1e293b', color: '#e2e8f0', fontFamily: 'monospace' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px', borderBottom: '1px solid #334155', paddingBottom: '12px' }}>
                <Terminal size={20} color="#667eea" />
                <h3>Protocol Log (TypeScript)</h3>
            </div>

            <div ref={scrollRef} style={{ maxHeight: '400px', overflowY: 'auto' }}>
                {logs.map((log: LogEntry, idx: number) => (
                    <div key={idx} style={{
                        marginBottom: '6px',
                        paddingLeft: '10px',
                        borderLeft: `3px solid ${getLogColor(log.type)}`,
                        color: getTextColor(log.type),
                        fontSize: '13px'
                    }}>
                        <span style={{ opacity: 0.5, marginRight: '8px' }}>[{log.time}]</span>
                        {log.message}
                    </div>
                ))}
                {logs.length === 0 && <div style={{ opacity: 0.5, fontStyle: 'italic' }}>Waiting for actions...</div>}
            </div>
        </div>
    );
};

export default LogPanel;
