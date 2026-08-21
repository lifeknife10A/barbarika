import { AuditLogEntry } from '../types';

const STORAGE_KEY = 'barbarika_unmask_audit_log';

export class AuditLogger {
  private static listeners: ((logs: AuditLogEntry[]) => void)[] = [];

  static getLogs(): AuditLogEntry[] {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        return JSON.parse(stored);
      }
    } catch (e) {
      console.error('Failed to load audit logs', e);
    }
    return [
      {
        id: 'audit-init-01',
        timestamp: new Date(Date.now() - 3600000).toISOString(),
        user_name: 'Nandini Chitlangia',
        user_role: 'CISO / Lead Reviewer',
        target_field: 'src_ip',
        entity_id: 'EVT-9382-SSH-FAIL',
        masked_value: '203.0.***.***',
        unmasked_value: '203.0.113.87',
        reason: 'Investigating high-frequency credential stuffing source',
        ip_address: '10.0.0.45',
      }
    ];
  }

  static logUnmask(entry: Omit<AuditLogEntry, 'id' | 'timestamp'>): AuditLogEntry {
    const logs = this.getLogs();
    const newEntry: AuditLogEntry = {
      id: `audit-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toISOString(),
      ...entry,
    };
    const updated = [newEntry, ...logs];
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    } catch (e) {
      console.error('Failed to save audit log', e);
    }
    this.listeners.forEach(cb => cb(updated));
    return newEntry;
  }

  static subscribe(listener: (logs: AuditLogEntry[]) => void): () => void {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter(l => l !== listener);
    };
  }
}
