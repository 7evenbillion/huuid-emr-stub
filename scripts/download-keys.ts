/**
 * NOT IMPLEMENTED -- flagged, not faked.
 *
 * HUUID-EMR-STUB-v0.1.2.docx Section 4, install step 5 expects this to
 * download ./keys/resolver-public-key.pem and ./keys/facility-private-key.pem
 * from the HUUID Protocol Working Group. The live resolver (huuid-resolver,
 * Month 2/3) has no key-distribution endpoint anywhere in its route table
 * (see HANDOFF.md) -- there is nothing for this script to call yet.
 *
 * Until that endpoint exists, place a PKCS8-PEM Ed25519 private key for your
 * facility at HUUID_FACILITY_PRIVATE_KEY_PATH manually.
 */
console.log('download-keys: NOT IMPLEMENTED.');
console.log('The live resolver has no key-distribution endpoint yet (see README.md).');
console.log('Place your facility private key manually at the path set by');
console.log('HUUID_FACILITY_PRIVATE_KEY_PATH in your .env (PKCS8 PEM, Ed25519).');
process.exit(1);
