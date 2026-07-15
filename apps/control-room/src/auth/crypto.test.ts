import { describe, expect, it } from "vitest";
import type { ControlRoomChallenge } from "../api/types";
import { deriveChallengeProof } from "./crypto";

describe("deriveChallengeProof", () => {
  it("matches the PBKDF2-HMAC-SHA256 contract vector", async () => {
    const challenge: ControlRoomChallenge = {
      schema_version: "1.0.0",
      challenge_id: "challenge-00000001",
      nonce: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI",
      salt: "AQEBAQEBAQEBAQEBAQEBAQ",
      kdf: "PBKDF2-HMAC-SHA256",
      iterations: 310000,
      expires_at: "2099-01-01T00:00:00Z",
    };

    await expect(
      deriveChallengeProof("SYNTHETIC_TEST_ONLY_VALUE", challenge),
    ).resolves.toBe("4o7qpLZo8bisuovqXET2ixbBaAkBVLCKOpjGqMj9F7A");
  });
});
