import { readFile } from "node:fs/promises";
import { join } from "node:path";

const CONTEXT_FILES: Record<string, string> = {
  "https://www.w3.org/2018/credentials/v1": "vc-v1.jsonld",
  "https://w3id.org/security/data-integrity/v2": "security-data-integrity-v2.jsonld",
  "https://www.gleif.org/contexts/isomer-v1.jsonld": "isomer-v1.jsonld"
};

export class LocalContextLoader {
  readonly #root: string;
  readonly #cache = new Map<string, unknown>();

  constructor(resourceRoot: string) {
    this.#root = resourceRoot;
  }

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

  loader = async (url: string): Promise<{ contextUrl?: string; documentUrl: string; document: unknown }> => {
    return await this.load(url);
  };
}
