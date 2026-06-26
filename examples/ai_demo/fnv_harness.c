// Minimal KLEE harness for fnv_hash. A 256-byte symbolic payload with a
// symbolic length is fed to fnv_hash, then we assert the post-condition
// that key_len <= BMC_MAX_KEY_LENGTH. KLEE forks at every byte (terminator
// vs. continue), which is the path-explosion case this experiment targets.

#include <stdint.h>
#include <klee/klee.h>

#define BMC_MAX_KEY_LENGTH 250u
#define PAYLOAD_SIZE 256u

unsigned int fnv_hash(const char *payload, unsigned int len, uint32_t *out_hash);

int main(void) {
  char payload[PAYLOAD_SIZE];
  unsigned int len;
  uint32_t out_hash;

  klee_make_symbolic(payload, sizeof payload, "payload");
  klee_make_symbolic(&len, sizeof len, "len");
  klee_assume(len <= PAYLOAD_SIZE);

  unsigned int key_len = fnv_hash(payload, len, &out_hash);

  // The loop iterates while off < BMC_MAX_KEY_LENGTH + 1, so key_len can
  // reach BMC_MAX_KEY_LENGTH + 1 in the worst case. This is the precise
  // post-condition both KLEE and Clam should be able to discharge.
  klee_assert(key_len <= BMC_MAX_KEY_LENGTH + 1u);
  return 0;
}
