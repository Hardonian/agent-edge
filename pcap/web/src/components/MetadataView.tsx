import React from 'react';
import { Manifest, CaptureMetadata } from '../types';

interface MetadataViewProps {
  manifest?: Manifest;
  metadata?: CaptureMetadata;
}

export const MetadataView: React.FC<MetadataViewProps> = ({ manifest, metadata }) => {
  if (!manifest) {
    return (
      <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-dim)' }}>
        No manifest metadata available.
      </div>
    );
  }

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      height: 'calc(100vh - 54px)',
      backgroundColor: 'var(--bg-app)',
      padding: 24,
      overflowY: 'auto',
      maxWidth: 900,
    }}>
      <div style={{ marginBottom: 20 }}>
        <h2 style={{ fontSize: 18, fontWeight: 800, color: '#f8fafc' }}>
          Capture Metadata & Integrity Manifest
        </h2>
        <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 2 }}>
          Cryptographic hashes and runtime properties bundled into this .apcap container.
        </p>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        {/* Manifest Properties */}
        <div style={{
          backgroundColor: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 8,
          padding: 16,
          display: 'flex',
          flexDirection: 'column',
          gap: 10,
          fontFamily: 'var(--font-mono)',
          fontSize: 13,
        }}>
          {metadata?.title && (
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 6 }}>
              <span style={{ color: 'var(--text-dim)' }}>Title</span>
              <span style={{ color: '#f8fafc', fontWeight: 600 }}>{metadata.title}</span>
            </div>
          )}
          <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 6 }}>
            <span style={{ color: 'var(--text-dim)' }}>Capture ID</span>
            <span style={{ color: '#38bdf8', fontWeight: 600 }}>{manifest.capture_id}</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 6 }}>
            <span style={{ color: 'var(--text-dim)' }}>Format Version</span>
            <span style={{ color: 'var(--text-main)' }}>{manifest.format} v{manifest.format_version}</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 6 }}>
            <span style={{ color: 'var(--text-dim)' }}>AgentPCAP Engine</span>
            <span style={{ color: 'var(--text-main)' }}>{manifest.agentpcap_version}</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 6 }}>
            <span style={{ color: 'var(--text-dim)' }}>Capture Mode</span>
            <span className="badge" style={{ backgroundColor: 'rgba(56, 189, 248, 0.1)', color: '#38bdf8' }}>
              {manifest.capture_mode.toUpperCase()}
            </span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 6 }}>
            <span style={{ color: 'var(--text-dim)' }}>Redaction Policy</span>
            <span className="badge" style={{ backgroundColor: 'rgba(34, 197, 94, 0.1)', color: '#4ade80' }}>
              {manifest.redaction_mode.toUpperCase()}
            </span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 6 }}>
            <span style={{ color: 'var(--text-dim)' }}>Created At</span>
            <span style={{ color: 'var(--text-main)' }}>{new Date(manifest.created_at).toLocaleString()}</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 6 }}>
            <span style={{ color: 'var(--text-dim)' }}>Protocols Observed</span>
            <div style={{ display: 'flex', gap: 6 }}>
              {manifest.protocols_seen?.map(p => (
                <span key={p} className={`badge badge-${p.toLowerCase()}`}>
                  {p}
                </span>
              ))}
            </div>
          </div>
        </div>

        {/* SHA-256 Bundle Hashes */}
        <div style={{
          backgroundColor: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 8,
          padding: 16,
        }}>
          <h3 style={{ fontSize: 13, fontWeight: 700, color: '#f8fafc', marginBottom: 12 }}>
            Cryptographic Integrity Hashes (SHA-256)
          </h3>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontFamily: 'var(--font-mono)', fontSize: 12 }}>
            {manifest.hashes && Object.entries(manifest.hashes).map(([file, hash]) => (
              <div key={file} style={{
                backgroundColor: 'var(--bg-app)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 6,
                padding: '8px 12px',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}>
                <span style={{ color: '#38bdf8', fontWeight: 600 }}>{file}</span>
                <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>{hash}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Host Metadata */}
        <div style={{
          backgroundColor: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 8,
          padding: 16,
          display: 'flex',
          justifyContent: 'space-between',
          fontFamily: 'var(--font-mono)',
          fontSize: 12,
        }}>
          <div>
            <span style={{ color: 'var(--text-dim)' }}>Host OS: </span>
            <span style={{ color: 'var(--text-main)' }}>{manifest.host_metadata.os} / {manifest.host_metadata.arch}</span>
          </div>
          {manifest.host_metadata.go_version && (
            <div>
              <span style={{ color: 'var(--text-dim)' }}>Go Runtime: </span>
              <span style={{ color: 'var(--text-main)' }}>{manifest.host_metadata.go_version}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
