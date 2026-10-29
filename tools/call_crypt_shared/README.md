# call_crypt_shared

Test the [Crypt Shared](https://www.mongodb.com/try/download/enterprise-advanced/releases) library.

The library is referred to as "Crypt Shared" on the  and is often referred to as `crypt_shared` in code. The library file name is `mongo_crypt_v1.(dylib|so|dll)`.

This tool is not a supported product and has no stability guarantees.

## Usage

```bash
# Print library version:
./tools/call_crypt_shared.sh --version --lib $HOME/bin/mongodl/crypt_shared/8.3.2/lib/mongo_crypt_v1.dylib
# mongo_crypt_v1-dev-8.3.2

# Mark up a command (reads from stdin):
cat ./tools/call_crypt_shared/tests/find.yml | ./tools/call_crypt_shared.sh --lib $HOME/bin/mongodl/crypt_shared/8.3.2/lib/mongo_crypt_v1.dylib
# (JSON output)

# Mark up a command from a file:
./tools/call_crypt_shared.sh --cmd ./tools/call_crypt_shared/tests/find.yml --lib $HOME/bin/mongodl/crypt_shared/8.3.2/lib/mongo_crypt_v1.dylib
# (JSON output)

# Use CRYPT_SHARED_LIB_PATH env var instead of --lib:
CRYPT_SHARED_LIB_PATH=$HOME/bin/mongodl/crypt_shared/8.3.2/lib/mongo_crypt_v1.dylib ./tools/call_crypt_shared.sh --version
# mongo_crypt_v1-dev-8.3.2
```
