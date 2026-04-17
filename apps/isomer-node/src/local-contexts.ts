/**
 * Local JSON-LD context pinning for deterministic Isomer verification.
 *
 * The sidecar intentionally avoids remote context fetches at verification time.
 * Instead it loads the small set of contexts used by Isomer artifacts from the
 * local Python resource tree under `src/vc_isomer/resources/contexts`.
 */
import { readFile } from "node:fs/promises";
import { join } from "node:path";

// This map is intentionally small and pinned. If Isomer artifacts introduce a
// new context, maintainers should add it here explicitly rather than permitting
// network fetches during verification.
const CONTEXT_FILES: Record<string, string> = {
  "https://www.w3.org/2018/credentials/v1": "vc-v1.jsonld",
  "https://w3id.org/security/data-integrity/v2": "security-data-integrity-v2.jsonld",
  "https://www.gleif.org/contexts/isomer-v1.jsonld": "isomer-v1.jsonld"
};

/**
 * Load pinned JSON-LD contexts from the local Isomer resource tree.
 */
export class LocalContextLoader {
  readonly #root: string;
  readonly #cache = new Map<string, unknown>();

  /**
   * Create a loader rooted at the Isomer workspace path.
   */
  constructor(resourceRoot: string) {
    this.#root = resourceRoot;
  }

  /**
   * Load one registered context document from disk and cache it by URL.
   */
  async load(url: string): Promise<{ contextUrl?: string; documentUrl: string; document: unknown }> {
    const filename = CONTEXT_FILES[url];
    if (!filename) {
      throw new Error(`no local JSON-LD context registered for ${url}`);
    }
    if (!this.#cache.has(url)) {
      const path = join(this.#root, "src", "vc_isomer", "resources", "contexts", filename);
      this.#cache.set(url, JSON.parse(await readFile(path, "utf8")));
    }
    return {
      documentUrl: url,
      document: this.#cache.get(url)
    };
  }

  /**
   * JSON-LD documentLoader adapter bound to this instance.
   */
  loader = async (url: string): Promise<{ contextUrl?: string; documentUrl: string; document: unknown }> => {
    return await this.load(url);
  };
}
