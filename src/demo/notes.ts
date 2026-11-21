export interface Note {
  readonly id: number;
  readonly text: string;
}

export interface NotesStoreOptions {
  readonly maxNotes?: number;
}

export const DEFAULT_MAX_NOTES = 1000;
export const MAX_SEARCH_RESULTS = 20;
export const NO_MATCH_TEXT = "No notes match.";

export const SEED_NOTES: readonly Note[] = Object.freeze([
  Object.freeze({ id: 1, text: "Water the plants on Sunday" }),
  Object.freeze({ id: 2, text: "Renew the passport in March" }),
  Object.freeze({ id: 3, text: "Router admin page is on the second shelf" })
]);

export class NotesStore {
  private readonly seedNotes: readonly Note[];
  private readonly addedNotes: Note[] = [];
  private readonly maxNotes: number;
  private nextId: number;

  constructor(options: NotesStoreOptions = {}) {
    this.seedNotes = SEED_NOTES;
    const requestedMax = options.maxNotes ?? DEFAULT_MAX_NOTES;
    this.maxNotes = Math.max(this.seedNotes.length, requestedMax);
    this.nextId = this.seedNotes.length + 1;
  }

  search(query: string): Note[] {
    const needle = query.toLowerCase();
    const matches: Note[] = [];

    for (const note of this.seedNotes) {
      if (note.text.toLowerCase().includes(needle)) {
        matches.push(note);
        if (matches.length >= MAX_SEARCH_RESULTS) {
          return matches;
        }
      }
    }

    for (const note of this.addedNotes) {
      if (note.text.toLowerCase().includes(needle)) {
        matches.push(note);
        if (matches.length >= MAX_SEARCH_RESULTS) {
          return matches;
        }
      }
    }

    return matches;
  }

  formatSearchResults(query: string): string {
    const matches = this.search(query);
    if (matches.length === 0) {
      return NO_MATCH_TEXT;
    }
    return matches.map((note) => `${note.id}: ${note.text}`).join("\n");
  }

  append(text: string): Note {
    const note: Note = { id: this.nextId, text };
    this.nextId += 1;

    const maxAdded = this.maxNotes - this.seedNotes.length;
    if (maxAdded > 0) {
      if (this.addedNotes.length >= maxAdded) {
        this.addedNotes.shift();
      }
      this.addedNotes.push(note);
    }

    return note;
  }

  size(): number {
    return this.seedNotes.length + this.addedNotes.length;
  }

  listAll(): Note[] {
    return [...this.seedNotes, ...this.addedNotes];
  }
}
