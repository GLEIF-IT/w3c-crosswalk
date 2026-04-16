import test from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { LocalContextLoader } from "./local-contexts.js";

test("local context loader rejects unknown remote contexts", async () => {
  const loader = new LocalContextLoader(resolve("../.."));
  await assert.rejects(
    loader.load("https://example.com/unknown.jsonld"),
    /no local JSON-LD context registered/
  );
});
