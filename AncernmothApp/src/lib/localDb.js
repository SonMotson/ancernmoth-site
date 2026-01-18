// Dexie (IndexedDB) example — install `dexie`
import Dexie from 'dexie';

export const db = new Dexie('AncernmothLocalDB');
db.version(1).stores({
  notes: '++id, title, body, updatedAt'
});

// Example usage:
// await db.notes.add({ title: 'Note', body: 'Body', updatedAt: Date.now() });