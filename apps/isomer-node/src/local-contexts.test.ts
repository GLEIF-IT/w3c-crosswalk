/**
 * Contract tests for the pinned local JSON-LD context loader.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { LocalContextLoader } from "./local-contexts.js";

test("loader rejects unknown context urls", async () => {
  const loader = new LocalContextLoader("/tmp/resources");

  await assert.rejects(
    loader.load("https://example.com/unknown.jsonld"),
    /no local JSON-LD context registered/
  );
});
